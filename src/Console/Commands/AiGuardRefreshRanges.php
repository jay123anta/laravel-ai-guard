<?php

namespace JayAnta\AiGuard\Console\Commands;

use Illuminate\Console\Command;
use JayAnta\AiGuard\Services\IpRangeRepository;

class AiGuardRefreshRanges extends Command
{
    protected $signature = 'ai-guard:refresh-ranges';

    protected $description = 'Fetch and cache the published IP range lists (verified crawlers and datacenter networks)';

    public function handle(): int
    {
        $config = (array) config('ai-guard');
        $verification = (array) ($config['bot_verification'] ?? []);
        $datacenter = (array) ($config['fingerprinting']['datacenter'] ?? []);

        $lists = [
            [new IpRangeRepository((int) ($verification['timeout'] ?? 3), (int) ($verification['cache_minutes'] ?? 1440)), $this->crawlerLists($verification)],
            [new IpRangeRepository((int) ($datacenter['timeout'] ?? 5), (int) ($datacenter['cache_minutes'] ?? 1440)), $this->datacenterLists($datacenter)],
        ];

        $rows = [];
        $failed = 0;

        foreach ($lists as [$repository, $sources]) {
            foreach ($sources as $url => $name) {
                $set = $repository->refresh($url);
                $failed += $set === null ? 1 : 0;
                $rows[] = [$name, $url, $set === null ? 'failed' : number_format($set->count()).' ranges'];
            }
        }

        if ($rows === []) {
            $this->line('No IP range lists are configured.');

            return self::SUCCESS;
        }

        $this->table(['Source', 'List', 'Result'], $rows);

        if ($failed > 0) {
            $this->warn("{$failed} list(s) could not be fetched; they will be retried in 5 minutes.");

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * @return array<string, string> url => crawler
     */
    private function crawlerLists(array $verification): array
    {
        $lists = [];

        foreach ((array) ($verification['crawlers'] ?? []) as $crawler => $rule) {
            foreach ((array) ($rule['ip_ranges'] ?? []) as $url) {
                $lists[(string) $url] ??= (string) $crawler;
            }
        }

        return $lists;
    }

    /**
     * @return array<string, string> url => network
     */
    private function datacenterLists(array $datacenter): array
    {
        $lists = [];

        foreach ((array) ($datacenter['ranges'] ?? []) as $network => $sources) {
            foreach ((array) $sources as $source) {
                if (preg_match('#^https?://#i', (string) $source)) {
                    $lists[(string) $source] ??= (string) $network;
                }
            }
        }

        return $lists;
    }
}
