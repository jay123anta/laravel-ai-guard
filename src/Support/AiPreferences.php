<?php

namespace JayAnta\AiGuard\Support;

/**
 * Machine-readable AI usage preferences:
 *  - Content-Usage (IETF AIPREF drafts): "train-ai=n, search=y"
 *  - Content-Signal (Cloudflare Content Signals Policy): "search=yes, ai-input=yes, ai-train=no"
 */
class AiPreferences
{
    public static function isValidContentUsage(string $value): bool
    {
        return preg_match('/^\s*[a-z][a-z0-9-]*\s*=\s*[yn]\s*(?:,\s*[a-z][a-z0-9-]*\s*=\s*[yn]\s*)*$/i', $value) === 1;
    }

    public static function isValidContentSignal(string $value): bool
    {
        return preg_match('/^\s*[a-z][a-z0-9-]*\s*=\s*(?:yes|no)\s*(?:,\s*[a-z][a-z0-9-]*\s*=\s*(?:yes|no)\s*)*$/i', $value) === 1;
    }

    /**
     * Canonical spacing and lower case: "Train-AI = N,search=y" → "train-ai=n, search=y".
     */
    public static function normalize(string $value): string
    {
        $pairs = array_map(
            fn (string $pair) => (string) preg_replace('/\s*=\s*/', '=', strtolower(trim($pair))),
            explode(',', $value)
        );

        return implode(', ', array_filter($pairs, fn (string $pair) => $pair !== ''));
    }
}
