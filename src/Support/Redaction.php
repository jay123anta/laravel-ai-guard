<?php

namespace JayAnta\AiGuard\Support;

/**
 * Text with sensitive values swapped for placeholders like [[EMAIL_1]], plus
 * the map needed to put the safe ones back into a model's reply.
 */
final class Redaction implements \Stringable
{
    /**
     * @param  array<string, array{type: string, value: string}>  $map  placeholder => original
     * @param  array<int, string>  $restoreTypes  types restore() puts back ('*' = all)
     */
    public function __construct(
        public readonly string $text,
        private readonly array $map = [],
        private readonly array $restoreTypes = [],
    ) {}

    public function hasRedactions(): bool
    {
        return $this->map !== [];
    }

    public function count(): int
    {
        return count($this->map);
    }

    /**
     * @return array<int, string>
     */
    public function types(): array
    {
        return array_values(array_unique(array_column($this->map, 'type')));
    }

    /**
     * @return array<int, string>
     */
    public function placeholders(): array
    {
        return array_keys($this->map);
    }

    /**
     * Put the original values back into a reply — only for restorable types.
     * Secrets (API keys, card numbers, ...) stay masked unless configured otherwise.
     */
    public function restore(string $reply): string
    {
        $replacements = [];

        foreach ($this->map as $placeholder => $entry) {
            if (in_array('*', $this->restoreTypes, true) || in_array($entry['type'], $this->restoreTypes, true)) {
                $replacements[$placeholder] = $entry['value'];
            }
        }

        return $replacements === [] ? $reply : strtr($reply, $replacements);
    }

    /**
     * Serializable form for carrying a redaction across a queue boundary.
     * It contains the original values — encrypt it before storing.
     *
     * @return array{text: string, map: array<string, array{type: string, value: string}>, restore: array<int, string>}
     */
    public function toArray(): array
    {
        return ['text' => $this->text, 'map' => $this->map, 'restore' => $this->restoreTypes];
    }

    /**
     * @param  array{text: string, map?: array<string, array{type: string, value: string}>, restore?: array<int, string>}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data['text'], $data['map'] ?? [], $data['restore'] ?? []);
    }

    public function __toString(): string
    {
        return $this->text;
    }
}
