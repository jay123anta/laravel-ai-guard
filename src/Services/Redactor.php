<?php

namespace JayAnta\AiGuard\Services;

use JayAnta\AiGuard\Support\Redaction;
use JayAnta\AiGuard\Support\SensitiveDataPatterns;

/**
 * Masks personal data and secrets before text is sent to a model provider.
 */
class Redactor
{
    public const DEFAULT_RESTORE = ['email', 'phone'];

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * @param  array<int, string>|null  $types  SensitiveDataPatterns keys to mask (null = config)
     */
    public function redact(string $text, ?array $types = null): Redaction
    {
        $types ??= $this->types();
        $map = [];
        $counters = [];
        $placeholderFor = [];

        // Text that already looks like a placeholder is defused first: otherwise a poisoned
        // document could carry [[EMAIL_1]] through the model and have restore() fill in a real
        // address that was never in that sentence
        $text = (string) preg_replace('/\[\[([A-Z][A-Z0-9_]*_\d+)\]\]/', '[ [$1] ]', $text);

        foreach (SensitiveDataPatterns::all() as $key => $pattern) {
            if (! in_array($key, $types, true)) {
                continue;
            }

            $text = (string) preg_replace_callback($pattern['regex'], function (array $match) use ($key, &$map, &$counters, &$placeholderFor) {
                $value = $match[0];

                // The same value always gets the same placeholder, so the model can still refer to it
                if (isset($placeholderFor[$value])) {
                    return $placeholderFor[$value];
                }

                $counters[$key] = ($counters[$key] ?? 0) + 1;
                $placeholder = '[['.strtoupper($key).'_'.$counters[$key].']]';

                $placeholderFor[$value] = $placeholder;
                $map[$placeholder] = ['type' => $key, 'value' => $value];

                return $placeholder;
            }, $text);
        }

        return new Redaction($text, $map, $this->restoreTypes());
    }

    /**
     * @return array<int, string>
     */
    public function types(): array
    {
        $configured = $this->config['llm_guard']['redaction']['types'] ?? null;

        if (is_array($configured)) {
            return array_values($configured);
        }

        // Internal IPs are too common in legitimate text to mask by default
        return array_values(array_diff(array_keys(SensitiveDataPatterns::all()), ['ip_address']));
    }

    /**
     * @return array<int, string>
     */
    private function restoreTypes(): array
    {
        $configured = $this->config['llm_guard']['redaction']['restore'] ?? self::DEFAULT_RESTORE;

        return is_array($configured) ? array_values($configured) : self::DEFAULT_RESTORE;
    }
}
