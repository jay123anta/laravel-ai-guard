<?php

namespace JayAnta\AiGuard\Support;

/**
 * The community ai.robots.txt list (https://github.com/ai-robots-txt/ai.robots.txt, MIT):
 * a JSON object keyed by user-agent token, each with the operator's stated function.
 * Tokens are sorted into AI training, AI search, or user-triggered AI agents.
 */
final class SignatureFeed
{
    public const DEFAULT_URL = 'https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json';

    public const CATEGORIES = ['ai_training', 'ai_search', 'ai_agents'];

    // A feed is a remote list, so it is treated as untrusted input: an entry that would match
    // ordinary browsers or every request is refused, however it got into the file.
    private const DENIED = [
        'mozilla', 'chrome', 'chromium', 'safari', 'webkit', 'applewebkit', 'gecko', 'firefox', 'edge', 'edg',
        'opera', 'opr', 'msie', 'trident', 'android', 'iphone', 'ipad', 'macintosh', 'windows', 'linux', 'x11',
        'khtml', 'like', 'mobile', 'version', 'bot', 'crawler', 'spider', 'agent', 'http', 'https', 'www',
    ];

    private const MAX_TOKENS = 2000;

    /**
     * @return array<string, array<int, string>>|null category => tokens, or null when the body is not the feed
     */
    public static function parse(string $json): ?array
    {
        $data = json_decode($json, true);
        if (! is_array($data) || $data === [] || array_is_list($data)) {
            return null;
        }

        $tokens = array_fill_keys(self::CATEGORIES, []);
        $count = 0;

        foreach ($data as $token => $meta) {
            $token = trim((string) $token);

            if (! self::isUsableToken($token) || ++$count > self::MAX_TOKENS) {
                continue;
            }

            $about = is_array($meta) ? ($meta['function'] ?? '').' '.($meta['description'] ?? '') : '';
            $tokens[self::categorize($token, (string) $about)][] = $token;
        }

        return $tokens;
    }

    /**
     * A token is matched against every User-Agent header, so one that names a browser, an
     * engine, or a word every agent carries would block the whole web. Length and shape are
     * limited too: tokens become User-agent lines and regex alternatives.
     */
    public static function isUsableToken(string $token): bool
    {
        if (! preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._\/-]{2,79}$/', $token)) {
            return false;
        }

        foreach (preg_split('/[ ._\/-]+/', strtolower($token)) ?: [] as $word) {
            if (in_array($word, self::DENIED, true)) {
                return false;
            }
        }

        return true;
    }

    public static function categorize(string $token, string $about): string
    {
        $text = strtolower($token.' '.$about);

        if (preg_match('/-user\b|on behalf|user[- ](initiated|triggered|prompt|request)|assistant|agent|brows/', $text)) {
            return 'ai_agents';
        }

        if (preg_match('/search|index|retriev|answer engine|citation/', $text)) {
            return 'ai_search';
        }

        return 'ai_training';
    }

    public static function path(): string
    {
        $path = config('ai-guard.bot_signatures.feed.path');

        return is_string($path) && $path !== '' ? $path : storage_path('app/ai-guard/bot-signatures.json');
    }

    /**
     * @return array<string, array<int, string>>
     */
    public static function load(string $path): array
    {
        $data = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;
        $tokens = [];
        $budget = self::MAX_TOKENS;

        // Checked again here, not only when the feed is fetched: the file on disk may have been
        // written by an older version, edited by hand, or replaced
        foreach (self::CATEGORIES as $category) {
            $list = is_array($data['tokens'][$category] ?? null) ? $data['tokens'][$category] : [];
            $usable = array_values(array_filter($list, fn ($token) => is_string($token) && self::isUsableToken($token)));

            $tokens[$category] = array_slice($usable, 0, max(0, $budget));
            $budget -= count($tokens[$category]);
        }

        return $tokens;
    }

    /**
     * @param  array<string, array<int, string>>  $tokens
     */
    public static function save(string $path, array $tokens, string $source): void
    {
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0755, true);
        }

        file_put_contents($path, json_encode([
            'source' => $source,
            'licence' => 'MIT (ai.robots.txt contributors)',
            'fetched_at' => now()->toIso8601String(),
            'tokens' => $tokens,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
    }
}
