<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Support\IpRangeSet;

/**
 * Published IP range lists — crawler operators (Googlebot, GPTBot, ...) and cloud
 * networks (AWS, Google Cloud, Oracle, ...) — fetched, compiled into an IpRangeSet,
 * and cached. A list that cannot be fetched or parsed reads as unavailable, never as
 * empty: an empty list would put every IP "outside" and mark real crawlers spoofed.
 */
class IpRangeRepository
{
    // Retry a list that could not be fetched after 5 minutes
    private const RETRY_SECONDS = 300;

    // How long a compiled list is held in this process. Under Octane a worker lives for hours,
    // and without this it would keep the first list it ever loaded — ai-guard:refresh-ranges
    // updates the cache but cannot reach into a running worker's memory.
    private const MEMO_SECONDS = 60;

    /** @var array<string, IpRangeSet|null> */
    private array $memo = [];

    /** @var array<string, float> */
    private array $memoAt = [];

    public function __construct(
        private int $timeout = 3,
        private int $cacheMinutes = 1440,
    ) {}

    /**
     * true = in one of the lists, false = in none, null = no list could be loaded.
     * Each source is a list URL or a literal CIDR.
     *
     * @param  array<int, string>  $sources
     */
    public function contains(string $ip, array $sources, bool $fetch = true): ?bool
    {
        $loaded = false;
        $literal = [];

        foreach ($sources as $source) {
            $source = trim((string) $source);

            if (! preg_match('#^https?://#i', $source)) {
                $literal[] = $source;

                continue;
            }

            $set = $this->set($source, $fetch);
            if ($set === null) {
                continue;
            }

            $loaded = true;
            if ($set->contains($ip)) {
                return true;
            }
        }

        if ($literal !== []) {
            $key = 'literal:'.sha1(implode(',', $literal));
            $loaded = true;

            if (($this->memo[$key] ??= IpRangeSet::fromCidrs($literal))->contains($ip)) {
                return true;
            }
        }

        return $loaded ? false : null;
    }

    /**
     * The compiled list, or null when it is unavailable (or not cached and $fetch is false).
     */
    public function set(string $url, bool $fetch = true): ?IpRangeSet
    {
        if (array_key_exists($url, $this->memo) && microtime(true) - ($this->memoAt[$url] ?? 0) < self::MEMO_SECONDS) {
            return $this->memo[$url];
        }

        if ($this->cacheMinutes > 0) {
            $cached = Cache::get($this->cacheKey($url));
            if (is_array($cached)) {
                $this->memoAt[$url] = microtime(true);

                return $this->memo[$url] = $cached['ok'] ? IpRangeSet::fromArray((array) $cached['set']) : null;
            }
        }

        if (! $fetch) {
            return null;
        }

        $cidrs = $this->fetch($url);
        $set = $cidrs === null ? null : IpRangeSet::fromCidrs($cidrs);

        if ($this->cacheMinutes > 0) {
            Cache::put(
                $this->cacheKey($url),
                ['ok' => $set !== null, 'set' => $set?->toArray() ?? []],
                $set !== null ? $this->cacheMinutes * 60 : self::RETRY_SECONDS
            );
        }

        $this->memoAt[$url] = microtime(true);

        return $this->memo[$url] = $set;
    }

    /**
     * Fetch the list again, replacing the cached copy.
     */
    public function refresh(string $url): ?IpRangeSet
    {
        unset($this->memo[$url], $this->memoAt[$url]);
        Cache::forget($this->cacheKey($url));

        return $this->set($url);
    }

    /**
     * @return array<int, string>|null
     */
    public function fetch(string $url): ?array
    {
        try {
            $response = Http::timeout($this->timeout)
                ->withHeaders(['Accept' => 'application/json, text/plain;q=0.9, */*;q=0.5'])
                ->get($url);

            return $response->successful() ? self::parse($response->body()) : null;
        } catch (\Throwable $e) {
            Log::warning('AI Guard: IP range list fetch failed.', ['url' => $url, 'error' => $e->getMessage()]);

            return null;
        }
    }

    /**
     * CIDRs in a JSON range list (any shape: Google, OpenAI, AWS, Google Cloud, Oracle, ...)
     * or a text list with one range per line (CSV feeds: the range comes first).
     *
     * @return array<int, string>|null
     */
    public static function parse(string $body): ?array
    {
        $found = [];
        $data = json_decode($body, true);

        if (is_array($data)) {
            array_walk_recursive($data, function ($value) use (&$found) {
                if (is_string($value) && self::isCidr($value)) {
                    $found[] = $value;
                }
            });

            // Valid JSON that holds no range is not a list either — an empty result would
            // otherwise be saved and replace the ranges already in place
            return $found === [] ? null : $found;
        }

        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || $line[0] === ';') {
                continue;
            }

            $first = (string) (preg_split('/[\s,;]+/', $line)[0] ?? '');
            if (self::isCidr($first)) {
                $found[] = $first;
            }
        }

        // An HTML error page or any other body without ranges is not a list
        return $found === [] ? null : $found;
    }

    public static function isCidr(string $value): bool
    {
        [$address, $bits] = array_pad(explode('/', $value, 2), 2, null);

        return filter_var($address, FILTER_VALIDATE_IP) !== false
            && ($bits === null || (ctype_digit($bits) && (int) $bits <= 128));
    }

    private function cacheKey(string $url): string
    {
        return 'ai-guard:ip-set:'.sha1($url);
    }
}
