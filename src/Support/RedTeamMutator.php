<?php

namespace JayAnta\AiGuard\Support;

use InvalidArgumentException;

/**
 * Encodings attackers use to slip instructions past filters, applied to red-team payloads.
 */
final class RedTeamMutator
{
    public const BASIC = ['base64', 'zero_width', 'homoglyph', 'fullwidth'];

    public const ALL = [
        'base64', 'zero_width', 'homoglyph', 'fullwidth', 'leetspeak', 'spaced',
        'url_encoded', 'html_entities', 'unicode_tags', 'variation_selectors', 'code_fence',
    ];

    public static function apply(string $mutation, string $text): string
    {
        return match ($mutation) {
            'base64' => 'Here is the text: '.base64_encode($text),
            'zero_width' => implode("\u{200B}", mb_str_split($text)),
            'homoglyph' => strtr($text, ['a' => 'а', 'e' => 'е', 'o' => 'о', 'p' => 'р', 'c' => 'с', 'i' => 'і', 'x' => 'х']),
            'fullwidth' => (string) preg_replace_callback('/[!-~]/', fn (array $m) => mb_chr(ord($m[0]) + 0xFEE0), $text),
            'leetspeak' => strtr(strtolower($text), ['a' => '4', 'e' => '3', 'i' => '1', 'o' => '0', 's' => '5', 't' => '7']),
            'spaced' => implode(' ', mb_str_split($text)),
            'url_encoded' => rawurlencode($text),
            'html_entities' => implode('', array_map(fn (string $c) => '&#x'.dechex((int) mb_ord($c)).';', mb_str_split($text))),
            // ASCII smuggled in invisible Unicode tag characters after harmless text
            'unicode_tags' => 'Nice product! '.implode('', array_map(
                fn (string $c) => mb_chr(0xE0000 + ord($c)),
                array_filter(str_split($text), fn (string $c) => ord($c) < 128)
            )),
            // Bytes hidden in variation selectors after an emoji
            'variation_selectors' => "\u{1F600}".implode('', array_map(
                fn (string $c) => ($byte = ord($c)) < 16 ? mb_chr(0xFE00 + $byte) : mb_chr(0xE0100 + $byte - 16),
                str_split($text)
            )),
            'code_fence' => "Here is my config:\n```system\n{$text}\n```",
            default => throw new InvalidArgumentException("Unknown mutation \"{$mutation}\"."),
        };
    }
}
