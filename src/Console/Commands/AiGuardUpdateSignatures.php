<?php

namespace JayAnta\AiGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Support\SignatureFeed;

class AiGuardUpdateSignatures extends Command
{
    protected $signature = 'ai-guard:update-signatures
        {--url= : Feed URL (default: config bot_signatures.feed.url, the ai.robots.txt project)}
        {--dry-run : Show the new tokens without saving them}';

    protected $description = 'Add AI crawler tokens from the community ai.robots.txt list (MIT) to the signature database';

    public function handle(): int
    {
        $url = (string) ($this->option('url') ?: (config('ai-guard.bot_signatures.feed.url') ?: SignatureFeed::DEFAULT_URL));

        try {
            $response = Http::timeout(15)->get($url);
        } catch (\Throwable $e) {
            $this->error("Could not fetch {$url}: {$e->getMessage()}");

            return self::FAILURE;
        }

        $feed = $response->successful() ? SignatureFeed::parse($response->body()) : null;
        if ($feed === null) {
            $this->error("{$url} did not return the ai.robots.txt JSON list (HTTP {$response->status()}).");

            return self::FAILURE;
        }

        // Only what the built-in database lacks; earlier feed tokens are kept because the
        // comparison is against the built-in list, not the extended one
        $new = [];
        foreach ($feed as $category => $tokens) {
            $new[$category] = array_values(array_filter($tokens, fn (string $token) => ! BotSignatures::isBuiltInToken($token)));
        }

        $count = array_sum(array_map('count', $new));
        $this->table(['Category', 'Tokens not in the built-in list'], array_map(
            fn (string $category) => [$category, count($new[$category]).($new[$category] === [] ? '' : ': '.implode(', ', array_slice($new[$category], 0, 8)).(count($new[$category]) > 8 ? ', ...' : ''))],
            array_keys($new)
        ));

        if ($this->option('dry-run')) {
            $this->info("Dry run: {$count} token(s) would be saved.");

            return self::SUCCESS;
        }

        $path = SignatureFeed::path();
        SignatureFeed::save($path, $new, $url);

        BotSignatures::reset();
        BotSignatures::extend($new);

        $this->info("Saved {$count} token(s) to {$path}. They are detected from the next request, and");
        $this->line('included by ai-guard:robots-txt. Schedule this command weekly to stay current.');

        return self::SUCCESS;
    }
}
