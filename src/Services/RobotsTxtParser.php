<?php

namespace JayAnta\AiGuard\Services;

/**
 * RFC 9309 robots.txt parser: consecutive User-agent lines share one group,
 * a bot-specific group replaces the "*" group, and the longest matching
 * Allow/Disallow rule wins (Allow wins a tie).
 */
class RobotsTxtParser
{
    /**
     * @var array<int, array{agents: array<int, string>, rules: array<int, array{type: string, path: string}>}>
     */
    private array $groups;

    public function __construct(string $content)
    {
        $this->groups = $this->parse($content);
    }

    /**
     * Normalize a bot name or User-agent line value for comparison.
     */
    public static function productToken(string $name): string
    {
        return strtolower(rtrim(trim($name), '/ -'));
    }

    /**
     * Rules that apply to the given bot: every group naming it, or the "*" groups when none does.
     *
     * @return array<int, array{type: string, path: string}>
     */
    public function rulesFor(string $bot): array
    {
        $token = self::productToken($bot);
        $specific = [];
        $wildcard = [];
        $hasSpecificGroup = false;

        foreach ($this->groups as $group) {
            if ($token !== '' && in_array($token, $group['agents'], true)) {
                $hasSpecificGroup = true;
                $specific = array_merge($specific, $group['rules']);
            } elseif (in_array('*', $group['agents'], true)) {
                $wildcard = array_merge($wildcard, $group['rules']);
            }
        }

        return $hasSpecificGroup ? $specific : $wildcard;
    }

    /**
     * @return array{allowed: bool, rule: array{type: string, path: string}|null}
     */
    public function check(string $bot, string $path): array
    {
        if ($path === '/robots.txt') {
            return ['allowed' => true, 'rule' => null];
        }

        $best = null;
        $bestLength = -1;

        foreach ($this->rulesFor($bot) as $rule) {
            if (! self::matches($rule['path'], $path)) {
                continue;
            }

            $length = strlen($rule['path']);

            if ($length > $bestLength || ($length === $bestLength && $rule['type'] === 'allow')) {
                $best = $rule;
                $bestLength = $length;
            }
        }

        return [
            'allowed' => $best === null || $best['type'] === 'allow',
            'rule' => $best,
        ];
    }

    public function isAllowed(string $bot, string $path): bool
    {
        return $this->check($bot, $path)['allowed'];
    }

    /**
     * @return array<int, string>
     */
    public function disallowedPaths(string $bot): array
    {
        $paths = [];

        foreach ($this->rulesFor($bot) as $rule) {
            if ($rule['type'] === 'disallow') {
                $paths[] = $rule['path'];
            }
        }

        return array_values(array_unique($paths));
    }

    /**
     * Match a rule path against a request path. Supports "*" (any sequence) and a trailing "$" (end anchor).
     */
    public static function matches(string $pattern, string $path): bool
    {
        $anchored = str_ends_with($pattern, '$');
        if ($anchored) {
            $pattern = substr($pattern, 0, -1);
        }

        $regex = '#^'.str_replace('\*', '.*', preg_quote($pattern, '#')).($anchored ? '$' : '').'#';

        return preg_match($regex, $path) === 1;
    }

    /**
     * @return array<int, array{agents: array<int, string>, rules: array<int, array{type: string, path: string}>}>
     */
    private function parse(string $content): array
    {
        $groups = [];
        $current = null;
        $collectingAgents = false;

        foreach (preg_split('/\r\n|\r|\n/', $content) ?: [] as $rawLine) {
            $line = trim((string) preg_replace('/#.*$/', '', $rawLine));

            if ($line === '' || ! str_contains($line, ':')) {
                continue;
            }

            [$key, $value] = array_map('trim', explode(':', $line, 2));
            $key = strtolower($key);

            if ($key === 'user-agent') {
                // A User-agent line after rules starts a new group
                if ($current === null || ! $collectingAgents) {
                    if ($current !== null) {
                        $groups[] = $current;
                    }
                    $current = ['agents' => [], 'rules' => []];
                }

                $current['agents'][] = self::productToken($value);
                $collectingAgents = true;

                continue;
            }

            $collectingAgents = false;

            if ($current === null || ($key !== 'allow' && $key !== 'disallow')) {
                continue;
            }

            // An empty Disallow means "allow everything" — it adds no rule
            if ($value !== '') {
                $current['rules'][] = ['type' => $key, 'path' => $value];
            }
        }

        if ($current !== null) {
            $groups[] = $current;
        }

        return $groups;
    }
}
