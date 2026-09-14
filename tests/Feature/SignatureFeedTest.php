<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Support\Facades\Http;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Support\SignatureFeed;
use JayAnta\AiGuard\Tests\TestCase;

class SignatureFeedTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir().'/ai-guard-signatures-'.bin2hex(random_bytes(4)).'/bot-signatures.json';
        config()->set('ai-guard.bot_signatures.feed.path', $this->path);
    }

    protected function tearDown(): void
    {
        BotSignatures::reset();
        @unlink($this->path);
        @rmdir(dirname($this->path));

        parent::tearDown();
    }

    private function feed(): string
    {
        return (string) json_encode([
            'GPTBot' => ['operator' => 'OpenAI', 'function' => 'Scrapes data to train OpenAI models.'],
            'NovaTrainBot' => ['operator' => 'Nova Labs', 'function' => 'Collects pages to train language models.'],
            'NovaSearchBot' => ['operator' => 'Nova Labs', 'function' => 'Indexes pages for AI search answers.'],
            'Nova-User' => ['operator' => 'Nova Labs', 'function' => 'Fetches a page when a user asks the assistant.'],
            'bad<token>' => ['function' => 'Injected'],
        ]);
    }

    public function test_the_feed_is_parsed_and_categorized(): void
    {
        $this->assertSame([
            'ai_training' => ['GPTBot', 'NovaTrainBot'],
            'ai_search' => ['NovaSearchBot'],
            'ai_agents' => ['Nova-User'],
        ], SignatureFeed::parse($this->feed()));

        $this->assertNull(SignatureFeed::parse('["a", "b"]'));
        $this->assertNull(SignatureFeed::parse('<html>rate limited</html>'));
    }

    public function test_a_feed_entry_that_would_match_browsers_is_refused(): void
    {
        $poisoned = (string) json_encode([
            'GPTBot' => ['function' => 'Scrapes data to train OpenAI models.'],
            'Mozilla' => ['function' => 'Scrapes data to train models.'],
            'Chrome/120' => ['function' => 'Scrapes data to train models.'],
            'AppleWebKit' => ['function' => 'Scrapes data to train models.'],
            'a' => ['function' => 'Scrapes data to train models.'],
            'bot' => ['function' => 'Scrapes data to train models.'],
        ]);

        $this->assertSame(['GPTBot'], SignatureFeed::parse($poisoned)['ai_training']);

        // The same check runs when the saved file is read, not only when it is fetched
        SignatureFeed::save($this->path, ['ai_training' => ['NovaTrainBot', 'Mozilla'], 'ai_search' => [], 'ai_agents' => []], 'test');
        $this->assertSame(['NovaTrainBot'], SignatureFeed::load($this->path)['ai_training']);

        BotSignatures::loadFeed($this->path);
        $chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
        $this->assertNull(BotSignatures::findBot($chrome));
    }

    public function test_update_signatures_adds_new_tokens_to_detection_and_robots_txt(): void
    {
        Http::fake([SignatureFeed::DEFAULT_URL => Http::response($this->feed())]);

        $this->artisan('ai-guard:update-signatures', ['--dry-run' => true])
            ->expectsOutputToContain('Dry run: 3 token(s) would be saved.')
            ->assertSuccessful();
        $this->assertFileDoesNotExist($this->path);
        $this->assertNull(BotSignatures::findBot('Mozilla/5.0 (compatible; NovaTrainBot/1.0)'));

        $this->artisan('ai-guard:update-signatures')->assertSuccessful();
        $this->assertFileExists($this->path);

        $this->assertSame('ai_training', BotSignatures::findBot('Mozilla/5.0 (compatible; NovaTrainBot/1.0)')['category']);
        $this->assertSame('ai_agents', BotSignatures::findBot('Nova-User/2.0')['category']);
        $this->assertTrue(BotSignatures::isKnownToken('NovaSearchBot'));
        $this->assertFalse(BotSignatures::isBuiltInToken('NovaSearchBot'));

        $this->artisan('ai-guard:robots-txt')->expectsOutputToContain('User-agent: NovaSearchBot')->assertSuccessful();

        // A second run keeps what the first one added
        $this->artisan('ai-guard:update-signatures')->assertSuccessful();
        $saved = SignatureFeed::load($this->path);
        $this->assertSame(['NovaTrainBot'], $saved['ai_training']);
        $this->assertSame(['NovaSearchBot'], $saved['ai_search']);
        $this->assertSame(['Nova-User'], $saved['ai_agents']);
    }

    public function test_saved_tokens_load_on_boot_without_duplicates(): void
    {
        SignatureFeed::save($this->path, ['ai_training' => ['NovaTrainBot', 'GPTBot'], 'ai_search' => [], 'ai_agents' => []], 'test');

        $this->assertSame(1, BotSignatures::loadFeed($this->path), 'GPTBot is already known');
        $this->assertSame(0, BotSignatures::loadFeed($this->path), 'Loading twice adds nothing');
        $this->assertSame(0, BotSignatures::loadFeed($this->path.'.missing'));
        $this->assertSame('ai_training', BotSignatures::findBot('NovaTrainBot/1.0')['category']);
    }

    public function test_feed_failures_leave_the_database_alone(): void
    {
        Http::fake([SignatureFeed::DEFAULT_URL => Http::response('<html>rate limited</html>', 429)]);

        $this->artisan('ai-guard:update-signatures')
            ->expectsOutputToContain('did not return the ai.robots.txt JSON list (HTTP 429)')
            ->assertFailed();

        $this->assertFileDoesNotExist($this->path);
    }

    public function test_google_agent_is_a_user_triggered_agent(): void
    {
        $this->assertSame('ai_agents', BotSignatures::findBot('Mozilla/5.0 (compatible; Google-Agent)')['category']);
    }
}
