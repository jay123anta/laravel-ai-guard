<?php

namespace JayAnta\AiGuard\Support;

/**
 * Whether an LLM call fits the caller's budget, and if not, which limit it hit.
 */
final class BudgetDecision
{
    public const INPUT_TOO_LARGE = 'input_too_large';

    public function __construct(
        public readonly bool $allowed,
        public readonly ?string $limit = null,
        public readonly int|float|null $max = null,
        public readonly int|float|null $used = null,
        public readonly int $retryAfter = 0,
    ) {}

    public static function allow(): self
    {
        return new self(true);
    }

    public static function deny(string $limit, int|float $max, int|float $used, int $retryAfter = 0): self
    {
        return new self(false, $limit, $max, $used, $retryAfter);
    }

    public function httpStatus(): int
    {
        return $this->limit === self::INPUT_TOO_LARGE ? 413 : 429;
    }

    public function message(): string
    {
        return match ($this->limit) {
            null => 'Within budget',
            self::INPUT_TOO_LARGE => "Input is too large ({$this->used} estimated tokens, limit {$this->max}).",
            'cost_per_day', 'global_cost_per_day' => sprintf('Daily AI spending limit reached ($%.2f of $%.2f).', (float) $this->used, (float) $this->max),
            default => "AI usage limit reached ({$this->limit}: {$this->used} of {$this->max}).",
        };
    }
}
