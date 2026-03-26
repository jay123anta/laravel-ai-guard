<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AiDetector;
use JayAnta\AiGuard\Services\HoneypotService;
use JayAnta\AiGuard\Services\MlDetector;
use JayAnta\AiGuard\Services\PromptInjectionDetector;
use JayAnta\AiGuard\Services\RequestFingerprinter;
use JayAnta\AiGuard\Services\ResponseScanner;
use JayAnta\AiGuard\Services\RobotsTxtEnforcer;

class AiGuardMiddleware
{
    private AiDetector $aiDetector;
    private PromptInjectionDetector $promptDetector;
    private HoneypotService $honeypot;
    private ResponseScanner $responseScanner;
    private RobotsTxtEnforcer $robotsEnforcer;
    private RequestFingerprinter $fingerprinter;
    private MlDetector $mlDetector;

    public function __construct(
        AiDetector $aiDetector,
        PromptInjectionDetector $promptDetector,
        HoneypotService $honeypot,
        ResponseScanner $responseScanner,
        RobotsTxtEnforcer $robotsEnforcer,
        RequestFingerprinter $fingerprinter,
        MlDetector $mlDetector,
    ) {
        $this->aiDetector = $aiDetector;
        $this->promptDetector = $promptDetector;
        $this->honeypot = $honeypot;
        $this->responseScanner = $responseScanner;
        $this->robotsEnforcer = $robotsEnforcer;
        $this->fingerprinter = $fingerprinter;
        $this->mlDetector = $mlDetector;
    }

    public function handle(Request $request, Closure $next): mixed
    {
        $config = config('ai-guard') ?? [];

        if (!($config['enabled'] ?? true)) {
            return $next($request);
        }

        if ($this->aiDetector->isWhitelisted($request)) {
            return $next($request);
        }

        // --- Inbound Detection Pipeline ---

        $allResults = [];

        // 1. Honeypot trap check (instant 100 confidence)
        $honeypotResult = $this->honeypot->detect($request);
        if ($honeypotResult['detected']) {
            $allResults[] = $honeypotResult;
        }

        // 2. Bot signature + AI crawler + data harvester detection
        $aiResult = $this->aiDetector->detect($request);
        if ($aiResult['detected']) {
            $allResults[] = $aiResult;

            // 2a. robots.txt enforcement — boost confidence if bot violates
            $botInfo = $this->aiDetector->getBotInfo($request);
            $robotsResult = $this->robotsEnforcer->check($request, $botInfo);
            if ($robotsResult['detected']) {
                $aiResult['confidence_score'] = min($aiResult['confidence_score'] + $robotsResult['confidence_score'], 100);
                $aiResult['matched_pattern'] .= ' + ' . $robotsResult['matched_pattern'];
                $allResults[array_key_last($allResults)] = $aiResult;
            }
        }

        // 3. Prompt injection detection
        $injectionResult = $this->promptDetector->detect($request);
        if ($injectionResult['detected']) {
            // 3a. ML enhancement — refine confidence for borderline detections
            $mlInput = $request->getContent();
            if (empty($mlInput)) {
                $mlInput = $injectionResult['payload_snippet'] ?? '';
            }
            $injectionResult = $this->mlDetector->analyze($mlInput, $injectionResult);
            $allResults[] = $injectionResult;
        }

        // 4. Request fingerprint analysis
        $fingerprintResult = $this->fingerprinter->analyze($request);
        if ($fingerprintResult['detected']) {
            $allResults[] = $fingerprintResult;
        }

        // Pick highest confidence threat
        $threatResult = $this->pickHighestThreat($allResults);

        if ($threatResult['detected']) {
            $this->logThreat($request, $threatResult, $config);
            $this->sendAlertIfNeeded($threatResult, $config);

            $action = $this->takeAction($request, $next, $threatResult, $config);

            // Scan response for PII leaks even on threat requests
            return $this->scanResponse($request, $action, $config);
        }

        // --- Outbound Response Scanning ---
        $response = $next($request);

        return $this->scanResponse($request, $response, $config);
    }

    private function scanResponse(Request $request, mixed $response, array $config): mixed
    {
        try {
            if (!$this->responseScanner->isEnabled()) {
                return $response;
            }

            $scanResult = $this->responseScanner->scan($response);

            if ($scanResult['detected']) {
                $this->logThreat($request, $scanResult, $config);
                $this->sendAlertIfNeeded($scanResult, $config);

                // In block mode, strip the response and return a warning
                $mode = $config['mode'] ?? 'log_only';
                if ($mode === 'block') {
                    return response()->json([
                        'error' => 'Response blocked',
                        'message' => 'PII detected in response by AI Guard',
                    ], 500);
                }
            }
        } catch (\Throwable $e) {
            Log::warning('AI Guard: Response scanning failed.', [
                'error' => $e->getMessage(),
            ]);
        }

        return $response;
    }

    private function pickHighestThreat(array $results): array
    {
        if (empty($results)) {
            return [
                'detected' => false,
                'threat_type' => null,
                'threat_source' => null,
                'confidence_score' => 0,
                'matched_pattern' => null,
            ];
        }

        $best = $results[0];
        foreach ($results as $result) {
            if ($result['confidence_score'] > $best['confidence_score']) {
                $best = $result;
            }
        }

        return $best;
    }

    private function takeAction(Request $request, Closure $next, array $result, array $config): mixed
    {
        $mode = $config['mode'] ?? 'log_only';
        $threshold = $config['confidence_threshold'] ?? 70;
        $score = $result['confidence_score'];

        if ($mode === 'block' && $score >= $threshold) {
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Request blocked by AI Guard',
                'threat_type' => $result['threat_type'],
            ], 403);
        }

        if ($mode === 'rate_limit' && $score >= $threshold) {
            try {
                $key = 'ai-guard:' . $request->ip() . ':' . substr(md5($request->userAgent() ?? ''), 0, 8);
                $maxAttempts = $config['rate_limiting']['max_attempts'] ?? 60;
                $decaySeconds = (($config['rate_limiting']['decay_minutes'] ?? 1)) * 60;

                if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
                    return response()->json([
                        'error' => 'Too many requests',
                        'message' => 'Rate limited by AI Guard',
                    ], 429);
                }

                RateLimiter::hit($key, $decaySeconds);
            } catch (\Throwable $e) {
                Log::warning('AI Guard: Rate limiter failed, skipping rate limit.', [
                    'error' => $e->getMessage(),
                    'ip' => $request->ip(),
                ]);
            }
        }

        return $next($request);
    }

    private function logThreat(Request $request, array $result, array $config): void
    {
        try {
            $mode = $config['mode'] ?? 'log_only';
            $threshold = $config['confidence_threshold'] ?? 70;
            $score = $result['confidence_score'];

            if ($mode === 'block' && $score >= $threshold) {
                $actionTaken = 'blocked';
            } elseif ($mode === 'rate_limit' && $score >= $threshold) {
                $actionTaken = 'rate_limited';
            } else {
                $actionTaken = 'logged';
            }

            $headersSnapshot = null;
            $loggingConfig = $config['logging'] ?? [];
            if ($loggingConfig['log_headers'] ?? true) {
                $headersSnapshot = [
                    'User-Agent' => $request->header('User-Agent'),
                    'Accept' => $request->header('Accept'),
                    'Accept-Language' => $request->header('Accept-Language'),
                    'Accept-Encoding' => $request->header('Accept-Encoding'),
                    'Content-Type' => $request->header('Content-Type'),
                    'Referer' => $request->header('Referer'),
                    'X-Forwarded-For' => $request->header('X-Forwarded-For'),
                    'X-Real-IP' => $request->header('X-Real-IP'),
                ];
            }

            AiThreatLog::create([
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'threat_type' => $result['threat_type'],
                'threat_source' => $result['threat_source'],
                'confidence_score' => $result['confidence_score'],
                'request_url' => $request->fullUrl(),
                'request_method' => $request->method(),
                'matched_pattern' => $result['matched_pattern'],
                'payload_snippet' => isset($result['payload_snippet'])
                    ? substr($result['payload_snippet'], 0, $loggingConfig['max_payload_length'] ?? 500)
                    : null,
                'headers_snapshot' => $headersSnapshot,
                'action_taken' => $actionTaken,
                'country_code' => null,
            ]);
        } catch (\Throwable $e) {
            Log::warning('AI Guard: Failed to log threat.', [
                'error' => $e->getMessage(),
                'threat_type' => $result['threat_type'] ?? 'unknown',
            ]);
        }
    }

    private function sendAlertIfNeeded(array $result, array $config): void
    {
        try {
            $alertsConfig = $config['alerts'] ?? [];
            $webhook = $alertsConfig['slack_webhook'] ?? null;

            if ($webhook === null) {
                return;
            }

            $threshold = $alertsConfig['alert_threshold'] ?? 90;

            if ($result['confidence_score'] < $threshold) {
                return;
            }

            $payload = [
                'text' => '🚨 AI Guard Alert',
                'attachments' => [
                    [
                        'color' => '#FF0000',
                        'fields' => [
                            [
                                'title' => 'Threat Type',
                                'value' => $result['threat_type'],
                                'short' => true,
                            ],
                            [
                                'title' => 'Source',
                                'value' => $result['threat_source'],
                                'short' => true,
                            ],
                            [
                                'title' => 'Confidence',
                                'value' => $result['confidence_score'],
                                'short' => true,
                            ],
                            [
                                'title' => 'Pattern',
                                'value' => $result['matched_pattern'],
                                'short' => true,
                            ],
                        ],
                    ],
                ],
            ];

            Http::timeout(5)->post($webhook, $payload);
        } catch (\Throwable $e) {
            Log::warning('AI Guard: Failed to send Slack alert.', [
                'error' => $e->getMessage(),
            ]);
        }
    }
}
