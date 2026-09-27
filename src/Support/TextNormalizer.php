<?php

namespace JayAnta\AiGuard\Support;

/**
 * Produces matchable variants of untrusted text so obfuscated prompt
 * injections (zero-width characters inside words, fullwidth letters, homoglyphs, base64,
 * Unicode tag smuggling) are seen the same way as their plain form.
 */
class TextNormalizer
{
    // Zero-width, bidi control, soft hyphen, and other invisible formatting characters
    private const INVISIBLE = '/[\x{00AD}\x{034F}\x{061C}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180E}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{3164}\x{FEFF}\x{FFA0}]/u';

    // Unicode "tag" block — invisible characters that mirror ASCII (used for ASCII smuggling)
    private const TAG_RUN = '/[\x{E0000}-\x{E007F}]+/u';

    // A subdivision flag as Unicode defines it: 🏴, 2-7 tag lowercase letters or digits (the region
    // and subdivision code, e.g. "gbsct"), then the cancel tag (England, Scotland, Wales, …)
    private const FLAG_SEQUENCE = '/\x{1F3F4}([\x{E0061}-\x{E007A}\x{E0030}-\x{E0039}]{2,7})\x{E007F}/u';

    // Variation selectors: an emoji followed by a run of these can carry arbitrary bytes
    // (VS1–VS16 = 0–15, VS17–VS256 = 16–255). A lone VS16 after an emoji is normal.
    private const VARIATION_SELECTORS = '/[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]/u';

    private const VARIATION_RUN = '/[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]{4,}/u';

    /**
     * Text that every /u pattern can actually be run against.
     *
     * preg_match() returns false — never a match — when the subject is not valid UTF-8, so one
     * stray byte anywhere in a request would otherwise retire every pattern at once. Invalid
     * bytes are dropped rather than substituted, so a byte planted inside a word ("ig\xFFnore")
     * leaves the word matchable.
     */
    public static function toValidUtf8(string $text, string $replacement = ''): string
    {
        if ($text === '' || mb_check_encoding($text, 'UTF-8')) {
            return $text;
        }

        // Dropping suits a byte planted inside a word; a space suits one standing in for a space.
        // Callers that cannot know which it was check both.
        $previous = mb_substitute_character();
        mb_substitute_character($replacement === '' ? 'none' : mb_ord($replacement));

        try {
            return (string) mb_convert_encoding($text, 'UTF-8', 'UTF-8');
        } finally {
            mb_substitute_character($previous);
        }
    }

    private const MAX_DECODED_CANDIDATES = 5;

    private const MAX_DECODED_LENGTH = 4096;

    /** Cyrillic and Greek letters that render identically to Latin ones */
    private const CONFUSABLES = [
        'а' => 'a', 'в' => 'b', 'е' => 'e', 'ё' => 'e', 'к' => 'k', 'м' => 'm', 'н' => 'h', 'о' => 'o',
        'р' => 'p', 'с' => 'c', 'т' => 't', 'у' => 'y', 'х' => 'x', 'і' => 'i', 'ї' => 'i', 'ј' => 'j',
        'ѕ' => 's', 'ԁ' => 'd', 'ԛ' => 'q', 'ԝ' => 'w', 'ɡ' => 'g', 'һ' => 'h', 'ӏ' => 'l',
        'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M', 'Н' => 'H', 'О' => 'O', 'Р' => 'P',
        'С' => 'C', 'Т' => 'T', 'Х' => 'X', 'У' => 'Y', 'І' => 'I', 'Ј' => 'J', 'Ѕ' => 'S', 'Ԁ' => 'D',
        'α' => 'a', 'ε' => 'e', 'ι' => 'i', 'κ' => 'k', 'ν' => 'v', 'ο' => 'o', 'ρ' => 'p', 'τ' => 't',
        'υ' => 'u', 'χ' => 'x', 'ω' => 'w',
        'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H', 'Ι' => 'I', 'Κ' => 'K', 'Μ' => 'M',
        'Ν' => 'N', 'Ο' => 'O', 'Ρ' => 'P', 'Τ' => 'T', 'Υ' => 'Y', 'Χ' => 'X',
    ];

    /**
     * @return array{
     *     variants: array<int, array{text: string, via: string}>,
     *     tag_chars: int,
     *     invisible_chars: int,
     *     variation_selector_bytes: int
     * }
     */
    public function analyze(string $text): array
    {
        $variants = [['text' => $text, 'via' => 'raw']];
        $seen = [$text => true];

        $add = function (string $candidate, string $via) use (&$variants, &$seen): void {
            if ($candidate !== '' && ! isset($seen[$candidate])) {
                $seen[$candidate] = true;
                $variants[] = ['text' => $candidate, 'via' => $via];
            }
        };

        [$normalized, $tagChars, $invisibleChars] = $this->normalizeWithStats($text);
        $add($normalized, $tagChars > 0 ? 'unicode_tags' : 'normalized');

        $skeleton = $this->skeleton($normalized);
        $add($skeleton, 'homoglyph');

        // Leetspeak ("1gn0r3 4ll") and letter-spaced text ("i g n o r e") dodge word matching
        if (preg_match('/[a-z][0-9@$]|[0-9@$][a-z]/i', $skeleton)) {
            $add($this->unleet($skeleton), 'leetspeak');
        }
        if (preg_match('/(?:\S ){3,}\S/u', $skeleton)) {
            $add($this->unspace($skeleton), 'spacing');
        }

        foreach ($this->decodeEmbedded($normalized) as [$decoded, $via]) {
            $add($this->normalize($decoded), $via);
        }

        $variationBytes = 0;
        foreach ($this->decodeVariationSelectors($text) as $decoded) {
            $variationBytes += strlen($decoded);
            $add($this->normalize($decoded), 'variation_selectors');
        }

        return [
            'variants' => $variants,
            'tag_chars' => $tagChars,
            'invisible_chars' => $invisibleChars,
            'variation_selector_bytes' => $variationBytes,
        ];
    }

    /**
     * Text smuggled in runs of variation selectors (the "emoji smuggling" technique).
     *
     * @return array<int, string>
     */
    private function decodeVariationSelectors(string $text): array
    {
        if (! mb_check_encoding($text, 'UTF-8') || ! preg_match_all(self::VARIATION_RUN, $text, $runs)) {
            return [];
        }

        $decoded = [];

        foreach ($runs[0] as $run) {
            $bytes = '';
            foreach (mb_str_split($run) as $char) {
                $cp = mb_ord($char);
                $bytes .= chr($cp <= 0xFE0F ? $cp - 0xFE00 : $cp - 0xE0100 + 16);
            }

            if (mb_check_encoding($bytes, 'UTF-8') && trim($bytes) !== '') {
                $decoded[] = $bytes;
            }
        }

        return $decoded;
    }

    /**
     * Decode tag characters, strip invisible characters, and fold compatibility forms (NFKC).
     */
    public function normalize(string $text): string
    {
        return $this->normalizeWithStats($text)[0];
    }

    /**
     * Map look-alike Cyrillic/Greek letters to Latin.
     */
    public function skeleton(string $text): string
    {
        return strtr($text, self::CONFUSABLES);
    }

    /**
     * Read digits and symbols as letters ("1gn0r3 4ll", "wh47 15"). Only used for the
     * leetspeak variant, which exists only when the text mixes digits into words.
     */
    private function unleet(string $text): string
    {
        return (string) preg_replace_callback(
            '/(?<![\w@$])[\w@$]*[0-9@$][\w@$]*/',
            fn (array $match) => strtr($match[0], ['0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a', '$' => 's']),
            $text
        );
    }

    /**
     * Join runs of single characters separated by single spaces ("i g n o r e" becomes
     * "ignore", "m e" becomes "me"). Words separated by wider gaps stay apart.
     */
    private function unspace(string $text): string
    {
        return (string) preg_replace_callback('/(?:\S ){1,}\S/u', fn (array $match) => str_replace(' ', '', $match[0]), $text);
    }

    /**
     * @return array{0: string, 1: int, 2: int}
     */
    private function normalizeWithStats(string $text): array
    {
        if (! mb_check_encoding($text, 'UTF-8')) {
            return [$text, 0, 0];
        }

        // Every tag character counts except those inside a well-formed subdivision flag (🏴 + tag
        // letters + the cancel tag). Counting only the longest run let smuggled text hide as
        // several short runs; counting everything called two flag emoji in one sentence smuggling.
        $tagChars = 0;
        if (preg_match_all(self::FLAG_SEQUENCE, $text, $flags)) {
            foreach ($flags[1] as $code) {
                $tagChars -= mb_strlen($code) + 1;   // the code letters and the cancel tag
            }
        }
        $text = (string) preg_replace_callback(self::TAG_RUN, function (array $match) use (&$tagChars) {
            $decoded = '';
            foreach (mb_str_split($match[0]) as $char) {
                $tagChars++;
                $ascii = mb_ord($char) - 0xE0000;
                if ($ascii >= 0x20 && $ascii <= 0x7E) {
                    $decoded .= chr($ascii);
                }
            }

            // Surround with spaces so the smuggled text is matched as separate words
            return $decoded === '' ? '' : ' '.$decoded.' ';
        }, $text);

        $invisibleChars = 0;
        $text = (string) preg_replace_callback(self::INVISIBLE, function (array $match) use (&$invisibleChars) {
            // Zero-width joiner is routine inside emoji sequences — strip it but don't count it
            if ($match[0] !== "\u{200D}") {
                $invisibleChars++;
            }

            return '';
        }, $text);

        // Variation selectors are invisible too; drop them so a word split by them still matches
        $text = (string) preg_replace(self::VARIATION_SELECTORS, '', $text);

        return [$this->foldCompatibilityForms($text), $tagChars, $invisibleChars];
    }

    private function foldCompatibilityForms(string $text): string
    {
        if (class_exists(\Normalizer::class)) {
            $folded = \Normalizer::normalize($text, \Normalizer::FORM_KC);
            if (is_string($folded)) {
                $text = $folded;
            }
        }

        // Pure-PHP fallback (and safety net) for the forms most used to dodge filters
        $text = str_replace("\u{3000}", ' ', $text);

        return (string) preg_replace_callback(
            '/[\x{FF01}-\x{FF5E}\x{1D400}-\x{1D7FF}\x{24B6}-\x{24E9}\x{249C}-\x{24B5}\x{1F130}-\x{1F189}]/u',
            fn (array $match) => $this->foldCharacter($match[0]),
            $text
        );
    }

    private function foldCharacter(string $char): string
    {
        $cp = mb_ord($char);

        return match (true) {
            // Fullwidth ASCII
            $cp >= 0xFF01 && $cp <= 0xFF5E => chr($cp - 0xFEE0),
            // Mathematical alphanumerics: consecutive 52-letter alphabets (A–Z, a–z)
            $cp >= 0x1D400 && $cp <= 0x1D6A3 => $this->letterAt(($cp - 0x1D400) % 52),
            $cp >= 0x1D7CE && $cp <= 0x1D7FF => chr(0x30 + ($cp - 0x1D7CE) % 10),
            // Circled and parenthesized letters
            $cp >= 0x24B6 && $cp <= 0x24CF => chr(0x41 + $cp - 0x24B6),
            $cp >= 0x24D0 && $cp <= 0x24E9 => chr(0x61 + $cp - 0x24D0),
            $cp >= 0x249C && $cp <= 0x24B5 => chr(0x61 + $cp - 0x249C),
            // Squared / negative circled / negative squared capitals
            $cp >= 0x1F130 && $cp <= 0x1F189 => chr(0x41 + ($cp - 0x1F130) % 26),
            default => $char,
        };
    }

    private function letterAt(int $index): string
    {
        return $index < 26 ? chr(0x41 + $index) : chr(0x61 + $index - 26);
    }

    /**
     * Payloads hidden inside encodings: base64 blocks, URL encoding, HTML entities, escape sequences.
     *
     * @return array<int, array{0: string, 1: string}>
     */
    private function decodeEmbedded(string $text): array
    {
        $decoded = [];

        if (preg_match_all('/[A-Za-z0-9+\/_-]{16,}={0,2}/', $text, $matches)) {
            foreach (array_slice($matches[0], 0, self::MAX_DECODED_CANDIDATES) as $block) {
                $plain = base64_decode(strtr($block, '-_', '+/'), true);

                // Repaired rather than rejected: one invalid byte appended to a payload must not
                // make the decoded text disappear
                if ($plain !== false && $this->isReadableText($plain = self::toValidUtf8($plain))) {
                    $decoded[] = [mb_substr($plain, 0, self::MAX_DECODED_LENGTH), 'base64'];
                }
            }
        }

        if (preg_match('/%[0-9a-f]{2}/i', $text)) {
            $plain = self::toValidUtf8(rawurldecode($text));
            if ($plain !== $text) {
                $decoded[] = [$plain, 'url_encoding'];
            }
        }

        if (preg_match('/&(#\d+|#x[0-9a-f]+|[a-z]+);/i', $text)) {
            $plain = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($plain !== $text) {
                $decoded[] = [$plain, 'html_entities'];
            }
        }

        if (preg_match('/\\\\(u[0-9a-f]{4}|x[0-9a-f]{2})/i', $text)) {
            $plain = (string) preg_replace_callback(
                '/\\\\(?:u([0-9a-f]{4})|x([0-9a-f]{2}))/i',
                fn (array $m) => mb_chr((int) hexdec($m[1] !== '' ? $m[1] : $m[2])) ?: '',
                $text
            );
            if ($plain !== $text) {
                $decoded[] = [$plain, 'escape_sequences'];
            }
        }

        return $decoded;
    }

    private function isReadableText(string $candidate): bool
    {
        if ($candidate === '' || ! mb_check_encoding($candidate, 'UTF-8')) {
            return false;
        }

        $length = mb_strlen($candidate);
        $readable = preg_match_all('/[\p{L}\p{N}\p{P}\p{Zs}\n\r\t]/u', $candidate);

        return $length >= 8 && $readable !== false && $readable / $length >= 0.9;
    }
}
