<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Harm-category moderation of input or output through a provider:
 * OpenAI's moderation endpoint (free), a Llama Guard model on Ollama, or your own endpoint.
 */
class ModerationGuard
{
    /** Llama Guard 3/4 hazard taxonomy (MLCommons) */
    public const LLAMA_GUARD_CATEGORIES = [
        'S1' => 'violent_crimes', 'S2' => 'non_violent_crimes', 'S3' => 'sex_related_crimes',
        'S4' => 'child_sexual_exploitation', 'S5' => 'defamation', 'S6' => 'specialized_advice',
        'S7' => 'privacy', 'S8' => 'intellectual_property', 'S9' => 'indiscriminate_weapons',
        'S10' => 'hate', 'S11' => 'suicide_and_self_harm', 'S12' => 'sexual_content',
        'S13' => 'elections', 'S14' => 'code_interpreter_abuse',
    ];

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function isEnabled(): bool
    {
        return (bool) ($this->option('enabled') ?? false);
    }

    /**
     * @param  string  $direction  'input' (user text) or 'output' (model text)
     */
    public function moderate(string $text, string $direction = 'input'): array
    {
        if (! $this->isEnabled() || trim($text) === '') {
            return $this->emptyResult();
        }

        $driver = (string) ($this->option('driver') ?? 'openai');

        // A driver name nothing answers to is a configuration mistake, not an outage: say so,
        // and let fail_closed decide what happens to the request
        if (! in_array($driver, ['openai', 'ollama', 'custom'], true)) {
            Log::warning('AI Guard: unknown moderation driver; no moderation was performed.', ['driver' => $driver]);
        }

        $verdict = match ($driver) {
            'openai' => $this->queryOpenAi($text),
            'ollama' => $this->queryOllama($text, $direction),
            'custom' => $this->queryCustom($text),
            default => null,
        };

        if ($verdict === null) {
            // Provider unreachable: fail open unless told otherwise
            if ($this->option('fail_closed')) {
                return $this->result($driver, $direction, ['moderation_unavailable'], 70);
            }

            return $this->emptyResult();
        }

        $categories = $verdict['categories'];
        $blockOnly = $this->option('block_categories') ?? [];
        if (is_array($blockOnly) && $blockOnly !== [] && $categories !== []) {
            $categories = array_values(array_intersect($categories, $blockOnly));
        }

        if ($categories === []) {
            return $this->emptyResult();
        }

        return $this->result($driver, $direction, $categories, $verdict['confidence']);
    }

    /**
     * @return array{categories: array<int, string>, confidence: int}|null
     */
    private function queryOpenAi(string $text): ?array
    {
        $cfg = $this->driverConfig('openai');
        if (empty($cfg['api_key'])) {
            return null;
        }

        try {
            $response = Http::timeout((int) ($cfg['timeout'] ?? 3))
                ->withToken((string) $cfg['api_key'])
                ->post((string) ($cfg['url'] ?? 'https://api.openai.com/v1/moderations'), [
                    'model' => $cfg['model'] ?? 'omni-moderation-latest',
                    'input' => $text,
                ]);

            $result = $response->successful() ? $response->json('results.0') : null;
            if (! is_array($result) || ! isset($result['flagged'])) {
                return null;
            }

            $categories = array_keys(array_filter((array) ($result['categories'] ?? []), fn ($flagged) => $flagged === true));
            $scores = array_map('floatval', (array) ($result['category_scores'] ?? []));
            $top = $scores === [] ? 0.0 : max($scores);

            // A flagged verdict is the provider's decision. Scoring it by the raw category score
            // would leave a flagged message below the block threshold and only logged, and a
            // provider that flags without naming a category would be dropped altogether.
            return [
                'categories' => $result['flagged'] ? ($categories === [] ? ['flagged'] : $categories) : [],
                'confidence' => max($this->flaggedConfidence(), min(100, (int) round($top * 100))),
            ];
        } catch (\Throwable $e) {
            Log::warning('AI Guard: OpenAI moderation failed.', ['error' => $e->getMessage()]);

            return null;
        }
    }

    /**
     * Llama Guard answers "safe" or "unsafe" followed by hazard codes such as "S1,S10".
     *
     * @return array{categories: array<int, string>, confidence: int}|null
     */
    private function queryOllama(string $text, string $direction): ?array
    {
        $cfg = $this->driverConfig('ollama');

        $messages = $direction === 'output'
            ? [['role' => 'user', 'content' => '(the user request is not available)'], ['role' => 'assistant', 'content' => $text]]
            : [['role' => 'user', 'content' => $text]];

        try {
            $response = Http::timeout((int) ($cfg['timeout'] ?? 5))
                ->post((string) ($cfg['url'] ?? 'http://localhost:11434/api/chat'), [
                    'model' => $cfg['model'] ?? 'llama-guard3:1b',
                    'messages' => $messages,
                    'stream' => false,
                    'options' => ['temperature' => 0],
                ]);

            $answer = $response->successful() ? $response->json('message.content') : null;
            if (! is_string($answer)) {
                return null;
            }

            $answer = strtolower(trim($answer));
            if (str_starts_with($answer, 'safe')) {
                return ['categories' => [], 'confidence' => 0];
            }

            if (! str_starts_with($answer, 'unsafe')) {
                return null;
            }

            preg_match_all('/s(\d{1,2})/', $answer, $codes);
            $categories = array_map(
                fn (string $n) => self::LLAMA_GUARD_CATEGORIES['S'.$n] ?? 'S'.$n,
                $codes[1]
            );

            return ['categories' => $categories === [] ? ['unsafe'] : array_values(array_unique($categories)), 'confidence' => 90];
        } catch (\Throwable $e) {
            Log::warning('AI Guard: Ollama moderation failed.', ['error' => $e->getMessage()]);

            return null;
        }
    }

    /**
     * @return array{categories: array<int, string>, confidence: int}|null
     */
    private function queryCustom(string $text): ?array
    {
        $cfg = $this->driverConfig('custom');
        if (empty($cfg['url'])) {
            return null;
        }

        try {
            $request = Http::timeout((int) ($cfg['timeout'] ?? 3));
            if (! empty($cfg['api_key'])) {
                $request = $request->withToken((string) $cfg['api_key']);
            }

            $response = $request->post((string) $cfg['url'], ['input' => $text]);
            if (! $response->successful()) {
                return null;
            }

            $flagged = $response->json((string) ($cfg['flagged_field'] ?? 'flagged'));

            // Endpoints answer with 1, "true" or "yes" as readily as with a JSON boolean, and
            // reading those as "provider unreachable" would quietly moderate nothing at all
            if (is_string($flagged) || is_int($flagged)) {
                $flagged = in_array(strtolower((string) $flagged), ['1', 'true', 'yes', 'flagged'], true);
            }

            if (! is_bool($flagged)) {
                Log::warning('AI Guard: custom moderation endpoint returned no usable verdict.', [
                    'field' => (string) ($cfg['flagged_field'] ?? 'flagged'),
                ]);

                return null;
            }

            $categories = (array) $response->json((string) ($cfg['categories_field'] ?? 'categories'), []);
            $categories = array_values(array_filter(array_map(
                fn ($value, $key) => is_string($value) ? $value : ($value === true ? (string) $key : null),
                $categories,
                array_keys($categories)
            )));

            return ['categories' => $flagged ? ($categories ?: ['flagged']) : [], 'confidence' => 85];
        } catch (\Throwable $e) {
            Log::warning('AI Guard: custom moderation endpoint failed.', ['error' => $e->getMessage()]);

            return null;
        }
    }

    /**
     * The score given to a verdict the provider itself flagged; at or above the package's
     * confidence threshold, so 'block' mode blocks it.
     */
    private function flaggedConfidence(): int
    {
        $configured = $this->option('flagged_confidence');

        return is_numeric($configured) ? max(0, min(100, (int) $configured)) : 80;
    }

    /**
     * @param  array<int, string>  $categories
     */
    private function result(string $driver, string $direction, array $categories, int $confidence): array
    {
        return [
            'detected' => true,
            'threat_type' => 'content_moderation',
            'threat_source' => 'moderation:'.$driver,
            'confidence_score' => $confidence,
            'matched_pattern' => mb_substr($direction.': '.implode(', ', $categories), 0, 255),
            'categories' => $categories,
            'direction' => $direction,
        ];
    }

    private function emptyResult(): array
    {
        return [
            'detected' => false,
            'threat_type' => null,
            'threat_source' => null,
            'confidence_score' => 0,
            'matched_pattern' => null,
            'categories' => [],
        ];
    }

    private function driverConfig(string $driver): array
    {
        return (array) ($this->config['llm_guard']['moderation']['drivers'][$driver] ?? []);
    }

    private function option(string $key): mixed
    {
        return $this->config['llm_guard']['moderation'][$key] ?? null;
    }
}
