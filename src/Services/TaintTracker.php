<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Support\Facades\Cache;

/**
 * Remembers when untrusted content (web pages, emails, documents, tool results)
 * entered a conversation. The scope 'request' lives for the current request or
 * job; any other scope (e.g. a conversation ID) persists in the cache.
 *
 * Registered as a scoped binding, so request-level state never leaks between
 * requests on Octane or between queued jobs.
 */
class TaintTracker
{
    public const REQUEST_SCOPE = 'request';

    /** @var array<string, array<int, string>> */
    private array $sources = [];

    /** @var array<string, int> */
    private array $toolCalls = [];

    private int $ttlSeconds;

    public function __construct(int $ttlSeconds = 86400)
    {
        $this->ttlSeconds = $ttlSeconds;
    }

    public function taint(string $scope, string $source): void
    {
        $this->sources[$scope][] = $source;

        if ($scope !== self::REQUEST_SCOPE) {
            $stored = (array) Cache::get($this->key($scope), []);
            $stored[] = $source;
            Cache::put($this->key($scope), array_values(array_unique($stored)), $this->ttlSeconds);
        }
    }

    public function isTainted(string $scope): bool
    {
        return $this->sources($scope) !== [];
    }

    /**
     * @return array<int, string>
     */
    public function sources(string $scope): array
    {
        $sources = $this->sources[$scope] ?? [];

        if ($scope !== self::REQUEST_SCOPE) {
            $sources = array_merge($sources, (array) Cache::get($this->key($scope), []));
        }

        return array_values(array_unique($sources));
    }

    public function clear(string $scope): void
    {
        unset($this->sources[$scope], $this->toolCalls[$scope]);
        Cache::forget($this->key($scope));
        Cache::forget($this->key($scope).':calls');
    }

    /**
     * Count a tool call in the scope and return the new total. A conversation scope keeps its
     * count in the cache: an agent loop usually spans several requests, and a cap that started
     * again at zero on each of them would not cap anything.
     */
    public function countToolCall(string $scope): int
    {
        $count = $this->toolCalls[$scope] = ($this->toolCalls[$scope] ?? 0) + 1;

        if ($scope === self::REQUEST_SCOPE) {
            return $count;
        }

        $key = $this->key($scope).':calls';
        Cache::add($key, 0, $this->ttlSeconds);
        $total = Cache::increment($key);

        return is_numeric($total) ? (int) $total : $count;
    }

    private function key(string $scope): string
    {
        return 'ai-guard:taint:'.sha1($scope);
    }
}
