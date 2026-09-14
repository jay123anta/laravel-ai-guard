<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Support\CanonicalJson;
use JayAnta\AiGuard\Support\SensitiveDataPatterns;

/**
 * Sends threat events — and model token usage — to a SIEM webhook (JSON or CEF), an
 * OpenTelemetry collector (OTLP/HTTP JSON log records), and/or a log channel. Events are
 * buffered and sent when the request, command, or queued job ends, so exporting never
 * slows a response. A failed export is logged; it never breaks the app.
 */
class AuditExporter
{
    public const VERSION = '3.0.0';

    // Events held for one flush before the rest are dropped (ai-guard.audit.max_buffered)
    public const MAX_BUFFERED = 500;

    /** @var array<int, array<string, mixed>> */
    private array $threats = [];

    /** @var array<int, array<string, mixed>> */
    private array $usage = [];

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function isEnabled(): bool
    {
        return $this->siemUrl() !== null || $this->otlpEndpoint() !== null || $this->channel() !== null;
    }

    public function threat(array $row): void
    {
        if ($this->isEnabled() && $this->hasRoom($this->threats, 'threats')) {
            $this->threats[] = ['time' => microtime(true)] + $row;
        }
    }

    /**
     * The buffer is flushed when the request or job ends. A long-running worker, or a flood of
     * threats in one request, must not grow it without limit.
     *
     * @param  array<int, array<string, mixed>>  $buffer
     */
    private function hasRoom(array $buffer, string $kind): bool
    {
        $max = max(1, (int) ($this->config['audit']['max_buffered'] ?? self::MAX_BUFFERED));

        if (count($buffer) < $max) {
            return true;
        }

        if (count($buffer) === $max) {
            Log::warning("AI Guard: more than {$max} {$kind} buffered for export in one request; the rest are dropped.");
        }

        return false;
    }

    /**
     * @param  array{model?: string|null, input_tokens: int, output_tokens: int, cost?: float, tier?: string, subject?: string}  $usage
     */
    public function usage(array $usage): void
    {
        if ($this->otlpEndpoint() !== null && ($this->option('otlp', 'usage') ?? true) && $this->hasRoom($this->usage, 'usage records')) {
            $this->usage[] = ['time' => microtime(true)] + $usage;
        }
    }

    public function pending(): int
    {
        return count($this->threats) + count($this->usage);
    }

    public function flush(): void
    {
        [$threats, $usage] = [$this->threats, $this->usage];
        $this->threats = $this->usage = [];

        if ($threats !== []) {
            $this->attempt('SIEM webhook', fn () => $this->sendToSiem($threats));
            $this->attempt('log channel', fn () => $this->writeToChannel($threats));
        }

        if ($threats !== [] || $usage !== []) {
            $this->attempt('OTLP', fn () => $this->sendToOtlp($threats, $usage));
        }
    }

    /**
     * @param  array<int, array<string, mixed>>  $threats
     */
    private function sendToSiem(array $threats): void
    {
        $url = $this->siemUrl();
        if ($url === null) {
            return;
        }

        $cef = $this->option('siem', 'format') === 'cef';
        $body = $cef
            ? implode("\n", array_map(fn (array $threat) => $this->cef($threat), $threats))."\n"
            : CanonicalJson::text(['source' => 'laravel-ai-guard', 'version' => self::VERSION, 'events' => array_map(fn (array $threat) => $this->event($threat), $threats)]);

        $headers = [];
        $secret = $this->option('siem', 'secret');
        if (is_string($secret) && $secret !== '') {
            $headers['X-AI-Guard-Signature'] = 'sha256='.hash_hmac('sha256', $body, $secret);
        }

        Http::timeout((int) ($this->option('siem', 'timeout') ?? 3))
            ->withHeaders($headers)
            ->withBody($body, $cef ? 'text/plain; charset=UTF-8' : 'application/json')
            ->post($url)
            ->throw();
    }

    /**
     * @param  array<int, array<string, mixed>>  $threats
     */
    private function writeToChannel(array $threats): void
    {
        $channel = $this->channel();
        if ($channel === null) {
            return;
        }

        foreach ($threats as $threat) {
            Log::channel($channel)->info('AI Guard threat: '.($threat['threat_type'] ?? 'unknown'), $this->event($threat));
        }
    }

    /**
     * @param  array<int, array<string, mixed>>  $threats
     * @param  array<int, array<string, mixed>>  $usage
     */
    private function sendToOtlp(array $threats, array $usage): void
    {
        $endpoint = $this->otlpEndpoint();
        if ($endpoint === null) {
            return;
        }

        $endpoint = rtrim($endpoint, '/');
        $url = str_ends_with($endpoint, '/v1/logs') ? $endpoint : $endpoint.'/v1/logs';

        $records = [
            ...array_map(fn (array $threat) => $this->threatRecord($threat), $threats),
            ...array_map(fn (array $row) => $this->usageRecord($row), $usage),
        ];

        Http::timeout((int) ($this->option('otlp', 'timeout') ?? 3))
            ->withHeaders((array) ($this->option('otlp', 'headers') ?? []))
            ->asJson()
            ->post($url, [
                'resourceLogs' => [[
                    'resource' => ['attributes' => $this->attributes([
                        'service.name' => (string) ($this->option('otlp', 'service_name') ?: 'laravel'),
                    ])],
                    'scopeLogs' => [[
                        'scope' => ['name' => 'jayanta/laravel-ai-guard', 'version' => self::VERSION],
                        'logRecords' => $records,
                    ]],
                ]],
            ])
            ->throw();
    }

    /**
     * @return array<string, mixed>
     */
    private function event(array $threat): array
    {
        return array_filter([
            'time' => date('c', (int) $threat['time']),
            'threat_type' => $threat['threat_type'] ?? null,
            'threat_source' => $threat['threat_source'] ?? null,
            'confidence' => $threat['confidence_score'] ?? null,
            'action' => $threat['action_taken'] ?? null,
            'ip' => $threat['ip_address'] ?? null,
            'user_agent' => $threat['user_agent'] ?? null,
            'method' => $threat['request_method'] ?? null,
            'url' => $threat['request_url'] ?? null,
            'matched_pattern' => $threat['matched_pattern'] ?? null,
            'payload_snippet' => $this->payload($threat['payload_snippet'] ?? null),
            'bot_category' => $threat['bot_category'] ?? null,
            'bot_verification' => $threat['bot_verification'] ?? null,
        ], fn ($value) => $value !== null);
    }

    /**
     * The captured payload leaves the app here, so the secrets and personal data in it are
     * masked first. Set ai-guard.audit.redact_payloads to false to export it verbatim.
     */
    private function payload(mixed $snippet): ?string
    {
        if (! is_string($snippet) || $snippet === '') {
            return null;
        }

        return ($this->config['audit']['redact_payloads'] ?? true)
            ? SensitiveDataPatterns::redact($snippet)
            : $snippet;
    }

    /**
     * ArcSight Common Event Format.
     */
    private function cef(array $threat): string
    {
        // Records are newline-separated, so a newline in a header field would forge a record
        $header = fn (string $value) => str_replace(['\\', '|', "\r", "\n"], ['\\\\', '\\|', ' ', ' '], $value);
        $extension = fn (mixed $value) => str_replace(['\\', '=', "\r", "\n"], ['\\\\', '\\=', '\\r', '\\n'], (string) $value);

        $type = (string) ($threat['threat_type'] ?? 'unknown');
        $severity = min(10, intdiv((int) ($threat['confidence_score'] ?? 0) + 5, 10));

        $fields = [
            'rt' => (int) round($threat['time'] * 1000),
            'src' => $threat['ip_address'] ?? null,
            'requestMethod' => $threat['request_method'] ?? null,
            'request' => $threat['request_url'] ?? null,
            'requestClientApplication' => $threat['user_agent'] ?? null,
            'act' => $threat['action_taken'] ?? null,
        ];

        $labelled = [
            ['cn1', 'confidence', $threat['confidence_score'] ?? null],
            ['cs1', 'matchedPattern', $threat['matched_pattern'] ?? null],
            ['cs2', 'threatSource', $threat['threat_source'] ?? null],
            ['cs3', 'botCategory', $threat['bot_category'] ?? null],
        ];
        foreach ($labelled as [$key, $label, $value]) {
            if ($value !== null && $value !== '') {
                $fields[$key.'Label'] = $label;
                $fields[$key] = $value;
            }
        }

        $pairs = [];
        foreach ($fields as $key => $value) {
            if ($value !== null && $value !== '') {
                $pairs[] = $key.'='.$extension($value);
            }
        }

        return sprintf(
            'CEF:0|JayAnta|Laravel AI Guard|%s|%s|%s|%d|%s',
            self::VERSION,
            $header($type),
            $header(ucwords(str_replace('_', ' ', $type))),
            $severity,
            implode(' ', $pairs)
        );
    }

    private function threatRecord(array $threat): array
    {
        $logged = ($threat['action_taken'] ?? 'logged') === 'logged';
        $source = (string) ($threat['threat_source'] ?? '');

        return [
            'timeUnixNano' => $this->nanos((float) $threat['time']),
            'severityNumber' => $logged ? 9 : 13,
            'severityText' => $logged ? 'INFO' : 'WARN',
            'body' => ['stringValue' => 'AI Guard '.($threat['threat_type'] ?? 'threat').': '.($threat['matched_pattern'] ?? '')],
            'attributes' => $this->attributes([
                'event.name' => 'ai_guard.threat',
                'ai_guard.threat.type' => $threat['threat_type'] ?? null,
                'ai_guard.threat.source' => $threat['threat_source'] ?? null,
                'ai_guard.confidence' => isset($threat['confidence_score']) ? (int) $threat['confidence_score'] : null,
                'ai_guard.action' => $threat['action_taken'] ?? null,
                'ai_guard.bot.category' => $threat['bot_category'] ?? null,
                'ai_guard.bot.verification' => $threat['bot_verification'] ?? null,
                'client.address' => $threat['ip_address'] ?? null,
                'user_agent.original' => $threat['user_agent'] ?? null,
                'http.request.method' => $threat['request_method'] ?? null,
                'url.full' => $threat['request_url'] ?? null,
                'gen_ai.tool.name' => preg_match('/^(?:tool|mcp):(.+)$/', $source, $match) ? $match[1] : null,
            ]),
        ];
    }

    private function usageRecord(array $usage): array
    {
        return [
            'timeUnixNano' => $this->nanos((float) $usage['time']),
            'severityNumber' => 9,
            'severityText' => 'INFO',
            'body' => ['stringValue' => 'gen_ai token usage'],
            'attributes' => $this->attributes([
                'event.name' => 'gen_ai.client.token.usage',
                'gen_ai.request.model' => $usage['model'] ?? null,
                'gen_ai.usage.input_tokens' => (int) ($usage['input_tokens'] ?? 0),
                'gen_ai.usage.output_tokens' => (int) ($usage['output_tokens'] ?? 0),
                'ai_guard.cost_usd' => (float) ($usage['cost'] ?? 0.0),
                'ai_guard.budget.tier' => $usage['tier'] ?? null,
                'ai_guard.budget.subject' => $usage['subject'] ?? null,
            ]),
        ];
    }

    /**
     * @param  array<string, mixed>  $values
     * @return array<int, array{key: string, value: array<string, mixed>}>
     */
    private function attributes(array $values): array
    {
        $attributes = [];

        foreach ($values as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            $attributes[] = ['key' => $key, 'value' => match (true) {
                is_int($value) => ['intValue' => (string) $value],
                is_float($value) => ['doubleValue' => $value],
                is_bool($value) => ['boolValue' => $value],
                default => ['stringValue' => (string) $value],
            }];
        }

        return $attributes;
    }

    private function nanos(float $time): string
    {
        return sprintf('%d000', (int) round($time * 1_000_000));
    }

    private function attempt(string $sink, \Closure $send): void
    {
        try {
            $send();
        } catch (\Throwable $e) {
            Log::warning("AI Guard: {$sink} export failed.", ['error' => $e->getMessage()]);
        }
    }

    private function siemUrl(): ?string
    {
        $url = $this->option('siem', 'url');

        return is_string($url) && $url !== '' ? $url : null;
    }

    private function otlpEndpoint(): ?string
    {
        $endpoint = $this->option('otlp', 'endpoint');

        return is_string($endpoint) && $endpoint !== '' ? $endpoint : null;
    }

    private function channel(): ?string
    {
        $channel = $this->config['audit']['log_channel'] ?? null;

        return is_string($channel) && $channel !== '' ? $channel : null;
    }

    private function option(string $section, string $key): mixed
    {
        return $this->config['audit'][$section][$key] ?? null;
    }
}
