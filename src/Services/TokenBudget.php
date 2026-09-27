<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Support\Facades\Cache;
use JayAnta\AiGuard\Support\BudgetDecision;

/**
 * Per-user (or per-IP) token and spend budgets for LLM calls — OWASP LLM10
 * "Unbounded Consumption". Counters live in the cache, in fixed windows.
 */
class TokenBudget
{
    private const MICRO = 1_000_000;

    // Internal: the estimate the ai-guard.llm middleware reserved for the current request
    public const RESERVATION_ATTRIBUTE = 'ai_guard.budget_reservation';

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function isEnabled(): bool
    {
        return (bool) ($this->option('enabled') ?? true);
    }

    /**
     * Rough token count: ~4 characters per token for English (configurable). CJK, Kana, and
     * Hangul are counted separately — tokenizers spend about one token per character there,
     * so dividing everything by four would under-count a Japanese prompt fourfold.
     */
    public function estimateTokens(string $text): int
    {
        $charsPerToken = max(0.1, (float) ($this->option('chars_per_token') ?? 4));
        $cjkPerToken = max(0.1, (float) ($this->option('chars_per_token_cjk') ?? 1));

        $cjk = (int) preg_match_all(
            '/[\x{1100}-\x{11FF}\x{2E80}-\x{303F}\x{3040}-\x{A4CF}\x{A960}-\x{A97F}\x{AC00}-\x{D7FF}\x{F900}-\x{FAFF}\x{FE30}-\x{FE4F}\x{FF00}-\x{FFEF}\x{20000}-\x{2FA1F}]/u',
            $text
        );

        return (int) ceil(max(0, mb_strlen($text) - $cjk) / $charsPerToken + $cjk / $cjkPerToken);
    }

    /**
     * Would a call with this many input tokens fit? Does not consume anything.
     */
    public function check(string $subject, int $estimatedInputTokens, string $tier = 'default'): BudgetDecision
    {
        $maxInput = $this->option('max_input_tokens');
        if (is_numeric($maxInput) && $estimatedInputTokens > (int) $maxInput) {
            return BudgetDecision::deny(BudgetDecision::INPUT_TOO_LARGE, (int) $maxInput, $estimatedInputTokens);
        }

        $limits = $this->limits($tier);
        $keys = $this->keys($subject, $tier);

        $checks = [
            'requests_per_minute' => [$keys['rpm'], 1, $this->secondsToNextMinute()],
            'tokens_per_minute' => [$keys['tpm'], $estimatedInputTokens, $this->secondsToNextMinute()],
            'tokens_per_day' => [$keys['tpd'], $estimatedInputTokens, $this->secondsToMidnight()],
        ];

        foreach ($checks as $limit => [$key, $adding, $retryAfter]) {
            if (! isset($limits[$limit]) || ! is_numeric($limits[$limit])) {
                continue;
            }

            $used = (int) Cache::get($key, 0);
            if ($used + $adding > (int) $limits[$limit]) {
                return BudgetDecision::deny($limit, (int) $limits[$limit], $used, $retryAfter);
            }
        }

        if (isset($limits['cost_per_day']) && is_numeric($limits['cost_per_day'])) {
            $spent = (int) Cache::get($keys['cpd'], 0) / self::MICRO;
            if ($spent >= (float) $limits['cost_per_day']) {
                return BudgetDecision::deny('cost_per_day', (float) $limits['cost_per_day'], round($spent, 4), $this->secondsToMidnight());
            }
        }

        $global = $this->option('global_cost_per_day');
        if (is_numeric($global)) {
            $spent = (int) Cache::get($this->globalCostKey(), 0) / self::MICRO;
            if ($spent >= (float) $global) {
                return BudgetDecision::deny('global_cost_per_day', (float) $global, round($spent, 4), $this->secondsToMidnight());
            }
        }

        return BudgetDecision::allow();
    }

    /**
     * Count a request and hold its estimated input tokens, so concurrent calls see each other.
     */
    public function reserve(string $subject, int $estimatedInputTokens, string $tier = 'default'): void
    {
        $keys = $this->keys($subject, $tier);

        $this->add($keys['rpm'], 1, 120);
        $this->add($keys['tpm'], $estimatedInputTokens, 120);
        $this->add($keys['tpd'], $estimatedInputTokens, 90_000);
    }

    /**
     * Check and reserve in one step, which is what a caller enforcing a quota wants: with a
     * separate check() and reserve() any number of simultaneous requests read the same total
     * and all pass. Counters are raised first and put back when the call is refused.
     */
    public function consume(string $subject, int $estimatedInputTokens, string $tier = 'default'): BudgetDecision
    {
        $maxInput = $this->option('max_input_tokens');
        if (is_numeric($maxInput) && $estimatedInputTokens > (int) $maxInput) {
            return BudgetDecision::deny(BudgetDecision::INPUT_TOO_LARGE, (int) $maxInput, $estimatedInputTokens);
        }

        $limits = $this->limits($tier);
        $keys = $this->keys($subject, $tier);
        $taken = [];

        $windows = [
            ['requests_per_minute', $keys['rpm'], 1, 120, $this->secondsToNextMinute()],
            ['tokens_per_minute', $keys['tpm'], $estimatedInputTokens, 120, $this->secondsToNextMinute()],
            ['tokens_per_day', $keys['tpd'], $estimatedInputTokens, 90_000, $this->secondsToMidnight()],
        ];

        foreach ($windows as [$name, $key, $adding, $ttl, $retryAfter]) {
            $used = $this->add($key, $adding, $ttl);
            $taken[] = [$key, $adding];

            if (isset($limits[$name]) && is_numeric($limits[$name]) && $used > (int) $limits[$name]) {
                return $this->release($taken, BudgetDecision::deny($name, (int) $limits[$name], $used - $adding, $retryAfter));
            }
        }

        // Spend is only known after a call, so these are compared against what is already spent
        if (isset($limits['cost_per_day']) && is_numeric($limits['cost_per_day'])) {
            $spent = (int) Cache::get($keys['cpd'], 0) / self::MICRO;
            if ($spent >= (float) $limits['cost_per_day']) {
                return $this->release($taken, BudgetDecision::deny('cost_per_day', (float) $limits['cost_per_day'], round($spent, 4), $this->secondsToMidnight()));
            }
        }

        $global = $this->option('global_cost_per_day');
        if (is_numeric($global)) {
            $spent = (int) Cache::get($this->globalCostKey(), 0) / self::MICRO;
            if ($spent >= (float) $global) {
                return $this->release($taken, BudgetDecision::deny('global_cost_per_day', (float) $global, round($spent, 4), $this->secondsToMidnight()));
            }
        }

        return BudgetDecision::allow();
    }

    /**
     * @param  array<int, array{0: string, 1: int}>  $taken
     */
    private function release(array $taken, BudgetDecision $decision): BudgetDecision
    {
        foreach ($taken as [$key, $amount]) {
            if ($amount > 0) {
                Cache::decrement($key, $amount);
            }
        }

        return $decision;
    }

    /**
     * Record actual usage after the call. Input tokens already reserved are not counted twice.
     *
     * @return array{tokens: int, cost: float}
     */
    public function record(
        string $subject,
        int $inputTokens,
        int $outputTokens,
        ?string $model = null,
        string $tier = 'default',
        int $reservedInputTokens = 0,
    ): array {
        $keys = $this->keys($subject, $tier);
        $newTokens = max(0, $inputTokens - $reservedInputTokens) + $outputTokens;

        $this->add($keys['tpm'], $newTokens, 120);
        $this->add($keys['tpd'], $newTokens, 90_000);

        $cost = $this->cost($inputTokens, $outputTokens, $model);
        $micro = (int) round($cost * self::MICRO);
        if ($micro > 0) {
            $this->add($keys['cpd'], $micro, 90_000);
            $this->add($this->globalCostKey(), $micro, 90_000);
        }

        app(AuditExporter::class)->usage([
            'model' => $model,
            'input_tokens' => $inputTokens,
            'output_tokens' => $outputTokens,
            'cost' => $cost,
            'tier' => $tier,
            'subject' => $subject,
        ]);

        return ['tokens' => $inputTokens + $outputTokens, 'cost' => $cost];
    }

    /**
     * Current usage against the tier's limits.
     *
     * @return array<string, array{used: int|float, limit: int|float|null}>
     */
    public function usage(string $subject, string $tier = 'default'): array
    {
        $limits = $this->limits($tier);
        $keys = $this->keys($subject, $tier);

        return [
            'requests_per_minute' => ['used' => (int) Cache::get($keys['rpm'], 0), 'limit' => $limits['requests_per_minute'] ?? null],
            'tokens_per_minute' => ['used' => (int) Cache::get($keys['tpm'], 0), 'limit' => $limits['tokens_per_minute'] ?? null],
            'tokens_per_day' => ['used' => (int) Cache::get($keys['tpd'], 0), 'limit' => $limits['tokens_per_day'] ?? null],
            'cost_per_day' => ['used' => round((int) Cache::get($keys['cpd'], 0) / self::MICRO, 4), 'limit' => $limits['cost_per_day'] ?? null],
        ];
    }

    /**
     * Price of a call in USD, from llm_guard.budgets.prices (USD per 1M tokens).
     */
    public function cost(int $inputTokens, int $outputTokens, ?string $model = null): float
    {
        $prices = $this->option('prices') ?? [];
        $price = ($model !== null && isset($prices[$model])) ? $prices[$model] : ($prices['default'] ?? ['input' => 0, 'output' => 0]);

        return ($inputTokens * (float) ($price['input'] ?? 0) + $outputTokens * (float) ($price['output'] ?? 0)) / self::MICRO;
    }

    /**
     * The budget key for a user or, when nobody is signed in, the client IP.
     */
    public function subject(?object $user, ?string $ip): string
    {
        $keyBy = $this->option('key_by') ?? 'user';

        if ($keyBy === 'user' && $user !== null && method_exists($user, 'getAuthIdentifier')) {
            return 'user:'.$user->getAuthIdentifier();
        }

        return 'ip:'.($ip ?? 'unknown');
    }

    /**
     * @return array<string, mixed>
     */
    private function limits(string $tier): array
    {
        $tiers = $this->option('tiers') ?? [];

        return is_array($tiers[$tier] ?? null) ? $tiers[$tier] : (is_array($tiers['default'] ?? null) ? $tiers['default'] : []);
    }

    /**
     * @return array{rpm: string, tpm: string, tpd: string, cpd: string}
     */
    private function keys(string $subject, string $tier): array
    {
        $base = 'ai-guard:budget:'.$tier.':'.sha1($subject);
        $minute = intdiv($this->now(), 60);
        $day = $this->day();

        return [
            'rpm' => "{$base}:rpm:{$minute}",
            'tpm' => "{$base}:tpm:{$minute}",
            'tpd' => "{$base}:tpd:{$day}",
            'cpd' => "{$base}:cpd:{$day}",
        ];
    }

    private function globalCostKey(): string
    {
        return 'ai-guard:budget:global:cpd:'.$this->day();
    }

    // The application clock (not time()), so windows follow Carbon::setTestNow() and travel()
    private function now(): int
    {
        return now()->getTimestamp();
    }

    private function day(): string
    {
        return now()->utc()->format('Ymd');
    }

    /**
     * Raise a counter and return its new total.
     */
    private function add(string $key, int $amount, int $ttl): int
    {
        if ($amount <= 0) {
            return (int) Cache::get($key, 0);
        }

        Cache::add($key, 0, $ttl);
        $total = Cache::increment($key, $amount);

        // Not every cache store returns the new value
        return is_numeric($total) ? (int) $total : (int) Cache::get($key, 0);
    }

    private function secondsToNextMinute(): int
    {
        return 60 - ($this->now() % 60);
    }

    private function secondsToMidnight(): int
    {
        return 86400 - ($this->now() % 86400);
    }

    private function option(string $key): mixed
    {
        return $this->config['llm_guard']['budgets'][$key] ?? null;
    }
}
