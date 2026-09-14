<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use JayAnta\AiGuard\Events\ThreatDetected;
use JayAnta\AiGuard\Services\AiDetector;
use JayAnta\AiGuard\Services\BotVerifier;
use JayAnta\AiGuard\Services\HoneypotService;
use JayAnta\AiGuard\Services\MlDetector;
use JayAnta\AiGuard\Services\PromptInjectionDetector;
use JayAnta\AiGuard\Services\RequestFingerprinter;
use JayAnta\AiGuard\Services\ResponseScanner;
use JayAnta\AiGuard\Services\RobotsTxtEnforcer;
use JayAnta\AiGuard\Support\ThreatLogger;

class AiGuardMiddleware
{
    private AiDetector $aiDetector;

    private PromptInjectionDetector $promptDetector;

    private HoneypotService $honeypot;

    private ResponseScanner $responseScanner;

    private RobotsTxtEnforcer $robotsEnforcer;

    private RequestFingerprinter $fingerprinter;

    private MlDetector $mlDetector;

    private BotVerifier $botVerifier;

    public function __construct(
        AiDetector $aiDetector,
        PromptInjectionDetector $promptDetector,
        HoneypotService $honeypot,
        ResponseScanner $responseScanner,
        RobotsTxtEnforcer $robotsEnforcer,
        RequestFingerprinter $fingerprinter,
        MlDetector $mlDetector,
        BotVerifier $botVerifier,
    ) {
        $this->aiDetector = $aiDetector;
        $this->promptDetector = $promptDetector;
        $this->honeypot = $honeypot;
        $this->responseScanner = $responseScanner;
        $this->robotsEnforcer = $robotsEnforcer;
        $this->fingerprinter = $fingerprinter;
        $this->mlDetector = $mlDetector;
        $this->botVerifier = $botVerifier;
    }

    public function handle(Request $request, Closure $next): mixed
    {
        $config = config('ai-guard') ?? [];

        if (! ($config['enabled'] ?? true)) {
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

        // 2a. Bot verification — Web Bot Auth signature, published IP ranges, reverse DNS
        $verification = $this->botVerifier->verify($request);

        if ($verification['status'] === BotVerifier::SPOOFED) {
            // The claimed identity is fake — report the impersonation, not the claim
            $allResults[] = $this->botVerifier->spoofedResult($verification, $aiResult);
        } elseif ($aiResult['detected']) {
            if ($verification['status'] !== null) {
                $aiResult['bot_verification'] = $verification['status'];
            }

            // 2b. robots.txt enforcement — boost confidence if bot violates
            $botInfo = $this->aiDetector->getBotInfo($request);
            $robotsResult = $this->robotsEnforcer->check($request, $botInfo);
            if ($robotsResult['detected']) {
                $aiResult['confidence_score'] = min($aiResult['confidence_score'] + $robotsResult['confidence_score'], 100);
                $aiResult['matched_pattern'] .= ' + '.$robotsResult['matched_pattern'];
            }

            $allResults[] = $aiResult;
        } elseif ($verification['status'] === BotVerifier::VERIFIED && $verification['method'] === 'web_bot_auth') {
            // A signed AI agent browsing with an ordinary browser user-agent
            $allResults[] = $this->botVerifier->signedAgentResult($verification);
        }

        // 3. Prompt injection detection
        $inspection = $this->promptDetector->inspect($request);
        $injectionResult = $inspection['result'];

        // 3a. ML — borderline candidates, or every input on classifier-first routes
        if ($this->mlDetector->shouldAnalyze($request, $injectionResult, $inspection['texts'])) {
            $injectionResult = $this->mlDetector->analyze(
                $this->mlDetector->prepareInput($inspection['texts']),
                $injectionResult,
                $this->mlDetector->isAlwaysRunRoute($request)
            );
        }

        if ($injectionResult['detected']) {
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
            $actionTaken = $this->determineAction($threatResult, $config);
            $this->logThreat($request, $threatResult, $actionTaken);
            $this->dispatchEvent($request, $threatResult, $actionTaken);
            $this->sendAlertIfNeeded($threatResult, $config, $actionTaken);

            $action = $this->takeAction($request, $next, $threatResult, $config, $actionTaken);

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
            if (! $this->responseScanner->isEnabled()) {
                return $response;
            }

            $scanResult = $this->responseScanner->scan($response);

            if ($scanResult['detected']) {
                $actionTaken = $this->determineAction($scanResult, $config);
                $this->logThreat($request, $scanResult, $actionTaken);
                $this->dispatchEvent($request, $scanResult, $actionTaken);
                $this->sendAlertIfNeeded($scanResult, $config, $actionTaken);

                // In block mode, strip the response and return a warning
                if ($actionTaken === 'blocked') {
                    return response()->json([
                        'error' => 'Response blocked',
                        'message' => $scanResult['threat_type'] === 'indirect_prompt_injection'
                            ? 'Hidden prompt injection detected in response by AI Guard'
                            : 'PII detected in response by AI Guard',
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

    private function determineAction(array $result, array $config): string
    {
        $mode = $config['mode'] ?? 'log_only';
        $threshold = $config['confidence_threshold'] ?? 70;
        $score = $result['confidence_score'];

        if ($mode === 'block' && $score >= $threshold) {
            return 'blocked';
        }

        if ($mode === 'rate_limit' && $score >= $threshold) {
            return 'rate_limited';
        }

        return 'logged';
    }

    private function takeAction(Request $request, Closure $next, array $result, array $config, string $actionTaken): mixed
    {
        if ($actionTaken === 'blocked') {
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Request blocked by AI Guard',
                'threat_type' => $result['threat_type'],
            ], 403);
        }

        if ($actionTaken === 'rate_limited' && ($config['rate_limiting']['enabled'] ?? true)) {
            try {
                $key = 'ai-guard:'.$request->ip().':'.substr(md5($request->userAgent() ?? ''), 0, 8);
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

    private function logThreat(Request $request, array $result, string $actionTaken): void
    {
        app(ThreatLogger::class)->log($request, $result, $actionTaken);
    }

    private function dispatchEvent(Request $request, array $result, string $actionTaken): void
    {
        try {
            ThreatDetected::dispatch($request, $result, $actionTaken);
        } catch (\Throwable $e) {
            Log::warning('AI Guard: ThreatDetected listener threw an exception.', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    private function sendAlertIfNeeded(array $result, array $config, string $actionTaken): void
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

            $alertOn = $alertsConfig['alert_on'] ?? null;
            if (is_array($alertOn) && $alertOn !== []) {
                // Accept legacy config values ('block', 'rate_limit') alongside action_taken values
                $normalized = array_map(
                    fn ($action) => match ($action) {
                        'block' => 'blocked',
                        'rate_limit' => 'rate_limited',
                        default => $action,
                    },
                    $alertOn
                );

                if (! in_array($actionTaken, $normalized, true)) {
                    return;
                }
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
