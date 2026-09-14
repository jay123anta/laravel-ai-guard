<?php

namespace JayAnta\AiGuard\Support;

use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AuditChain;
use JayAnta\AiGuard\Services\AuditExporter;

/**
 * Writes detection results to ai_threat_logs — shared by the middleware and AiGuard::log() —
 * and hands them to the audit exporters (SIEM, OTLP, log channel).
 */
class ThreatLogger
{
    private static bool $warnedMissingV3Columns = false;

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function log(Request $request, array $result, string $actionTaken): ?AiThreatLog
    {
        try {
            $loggingConfig = $this->config['logging'] ?? [];

            $headersSnapshot = null;
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

            $attributes = [
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'threat_type' => $result['threat_type'],
                // Truncate to the column sizes — an overflow would throw and silently drop the log
                'threat_source' => isset($result['threat_source']) ? mb_substr((string) $result['threat_source'], 0, 100) : null,
                'bot_category' => $result['bot_category'] ?? null,
                'bot_verification' => $result['bot_verification'] ?? null,
                'confidence_score' => $result['confidence_score'],
                'request_url' => $request->fullUrl(),
                'request_method' => $request->method(),
                'matched_pattern' => isset($result['matched_pattern']) ? mb_substr((string) $result['matched_pattern'], 0, 255) : null,
                'payload_snippet' => isset($result['payload_snippet'])
                    ? mb_substr((string) $result['payload_snippet'], 0, $loggingConfig['max_payload_length'] ?? 500)
                    : null,
                'headers_snapshot' => $headersSnapshot,
                'action_taken' => $actionTaken,
                'country_code' => null,
            ];

            // A header or payload that is not valid UTF-8 would make the model's `array` cast
            // throw on encode — losing the whole row, which is a way to log nothing at all by
            // appending one byte to a request
            $attributes = $this->toValidUtf8($attributes);

            // Exported when the request ends, whether or not rows are written to the database
            app(AuditExporter::class)->threat($attributes);

            if (! ($loggingConfig['enabled'] ?? true)) {
                return null;
            }

            return $this->persist($attributes);
        } catch (\Throwable $e) {
            Log::warning('AI Guard: Failed to log threat.', [
                'error' => $e->getMessage(),
                'threat_type' => $result['threat_type'] ?? 'unknown',
            ]);

            return null;
        }
    }

    /**
     * Insert a log row (chained when audit.hash_chain is on). If the v3 upgrade migration
     * hasn't been run yet, the v3 columns are rejected — keep logging without them
     * instead of losing every row.
     */
    /**
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    private function toValidUtf8(array $attributes): array
    {
        foreach ($attributes as $key => $value) {
            if (is_string($value)) {
                $attributes[$key] = TextNormalizer::toValidUtf8($value);
            } elseif (is_array($value)) {
                $attributes[$key] = $this->toValidUtf8($value);
            }
        }

        return $attributes;
    }

    private function persist(array $attributes): AiThreatLog
    {
        $chain = app(AuditChain::class);

        try {
            return $chain->isEnabled() ? $chain->append($attributes) : AiThreatLog::create($attributes);
        } catch (QueryException $e) {
            // Only a rejected write is retried without the v3 columns; anything else — a
            // misconfigured chain key, for one — must be reported as itself
            unset($attributes['bot_category'], $attributes['bot_verification']);
            $log = AiThreatLog::create($attributes);

            if (! self::$warnedMissingV3Columns) {
                self::$warnedMissingV3Columns = true;
                Log::warning('AI Guard: ai_threat_logs is missing the v3 columns — run `php artisan vendor:publish --tag=ai-guard-migrations && php artisan migrate`.', [
                    'error' => $e->getMessage(),
                ]);
            }

            return $log;
        }
    }
}
