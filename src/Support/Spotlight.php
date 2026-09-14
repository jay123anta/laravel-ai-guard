<?php

namespace JayAnta\AiGuard\Support;

/**
 * Untrusted text transformed so a model can tell it apart from instructions,
 * plus the sentence to add to the system prompt that explains the marking.
 */
final class Spotlight implements \Stringable
{
    public function __construct(
        public readonly string $text,
        public readonly string $instructions,
        public readonly string $mode,
        public readonly string $id,
    ) {}

    public function __toString(): string
    {
        return $this->text;
    }
}
