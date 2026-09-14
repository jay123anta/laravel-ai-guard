<?php

namespace JayAnta\AiGuard\Support;

/**
 * One JSON spelling for a value, whatever order its keys arrived in — the form used
 * whenever something is hashed, signed, or compared (approval tokens, tool-definition pins).
 *
 * json_encode() returns false on invalid UTF-8 or a deep structure, and a false cast to a
 * string is '': every unencodable value would hash alike, so a signature or a pin could be
 * satisfied by a different payload. Nothing here can return an empty string for a value.
 */
final class CanonicalJson
{
    private const FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR;

    public static function encode(mixed $value): string
    {
        $json = json_encode(self::sort($value), self::FLAGS, 128);

        if (is_string($json)) {
            return $json;
        }

        // Nothing left that JSON can express: keep a representation that still tells values apart
        return 'php:'.print_r($value, true);
    }

    /**
     * The same safety, keeping the order the value was built in — for payloads that are read
     * by people or by another system rather than hashed.
     */
    public static function text(mixed $value, int $extraFlags = 0): string
    {
        $json = json_encode($value, self::FLAGS | $extraFlags, 512);

        return is_string($json) ? $json : 'php:'.print_r($value, true);
    }

    public static function hash(mixed $value): string
    {
        return hash('sha256', self::encode($value));
    }

    private static function sort(mixed $value, int $depth = 0): mixed
    {
        // Below the depth limit the contents are folded into a digest rather than dropped: a
        // placeholder would give every deeply nested value the same hash, and these hashes bind
        // approval tokens to their arguments and pin MCP tool definitions
        if ($depth > 64) {
            return 'ai-guard:deep:'.hash('sha256', print_r($value, true));
        }

        if (is_object($value)) {
            $value = method_exists($value, 'toArray') ? $value->toArray() : get_object_vars($value);
        }

        // Invalid UTF-8 is kept apart rather than collapsed onto U+FFFD by the encoder, which
        // would make "\xB1" and "\xB2" hash alike
        if (is_string($value)) {
            return mb_check_encoding($value, 'UTF-8') ? $value : 'ai-guard:b64:'.base64_encode($value);
        }

        if (! is_array($value)) {
            return $value;
        }

        if (! array_is_list($value)) {
            ksort($value);
        }

        return array_map(fn ($item) => self::sort($item, $depth + 1), $value);
    }
}
