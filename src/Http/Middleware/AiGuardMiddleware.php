<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AiDetector;
use JayAnta\AiGuard\Services\PromptInjectionDetector;

class AiGuardMiddleware
{
    private AiDetector $aiDetector;
    private PromptInjectionDetector $promptDetector;

    public function __construct(AiDetector $aiDetector, PromptInjectionDetector $promptDetector)
    {
        $this->aiDetector = $aiDetector;
        $this->promptDetector = $promptDetector;
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

        $aiResult = $this->aiDetector->detect($request);
        $injectionResult = $this->promptDetector->detect($request);

        $threatResult = $this->pickHighestThreat($aiResult, $injectionResult);

        if ($threatResult['detected']) {
            $this->logThreat($request, $threatResult, $config);
            $this->sendAlertIfNeeded($threatResult, $config);

            return $this->takeAction($request, $next, $threatResult, $config);
        }

        return $next($request);
    }

    private function pickHighestThreat(array $aiResult, array $injectionResult): array
    {
        if ($aiResult['detected'] && $injectionResult['detected']) {
            return $injectionResult['confidence_score'] >= $aiResult['confidence_score']
                ? $injectionResult
                : $aiResult;
        }

        if ($aiResult['detected']) {
            return $aiResult;
        }

        if ($injectionResult['detected']) {
            return $injectionResult;
        }

        return $aiResult;
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
