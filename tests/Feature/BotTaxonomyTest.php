<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Tests\TestCase;

class BotTaxonomyTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        // Package API routes read this when they load, before any test body runs
        $app['config']->set('ai-guard.api.middleware', ['api']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(AiGuardMiddleware::class)->get('/page', fn () => response('ok'));
    }

    private function visit(string $userAgent): TestResponse
    {
        return $this->withHeaders(['User-Agent' => $userAgent, 'Accept-Language' => 'en'])->get('/page');
    }

    public function test_upgrade_migration_adds_v3_columns(): void
    {
        $this->assertTrue(Schema::hasColumn('ai_threat_logs', 'bot_category'));
        $this->assertTrue(Schema::hasColumn('ai_threat_logs', 'bot_verification'));
    }

    public function test_default_policy_blocks_training_but_only_logs_search_and_agents(): void
    {
        config()->set('ai-guard.mode', 'block');
        $this->refreshAiGuard();

        $this->visit('GPTBot/1.1')->assertStatus(403);
        $this->visit('OAI-SearchBot/1.0')->assertOk();
        $this->visit('ChatGPT-User/1.0')->assertOk();

        $this->assertSame(['ai_training', 'ai_search', 'ai_agents'], AiThreatLog::orderBy('id')->pluck('bot_category')->all());
        $this->assertSame(['blocked', 'logged', 'logged'], AiThreatLog::orderBy('id')->pluck('action_taken')->all());
    }

    public function test_confidence_override_blocks_agents(): void
    {
        config()->set('ai-guard.mode', 'block');
        config()->set('ai-guard.bot_signatures.confidence', ['ai_agents' => 90]);
        $this->refreshAiGuard();

        $this->visit('ChatGPT-User/1.0')->assertStatus(403);
        $this->assertSame(90, AiThreatLog::first()->confidence_score);
    }

    public function test_stats_break_down_ai_purposes(): void
    {
        $this->visit('GPTBot/1.1');
        $this->visit('ClaudeBot/1.0');
        $this->visit('Claude-SearchBot/1.0');
        $this->visit('Claude-User/1.0');

        $stats = AiThreatLog::getThreatSummary(1);

        $this->assertSame(4, $stats['ai_crawlers']);
        $this->assertSame(2, $stats['ai_training_crawlers']);
        $this->assertSame(1, $stats['ai_search_crawlers']);
        $this->assertSame(1, $stats['ai_agents']);
        $this->assertSame(2, AiThreatLog::botCategory('ai_training')->count());
    }

    public function test_api_filters_by_bot_category(): void
    {
        $this->visit('GPTBot/1.1');
        $this->visit('Claude-User/1.0');
        $this->visit('Perplexity-User/1.0');

        $response = $this->getJson('/ai-guard/api/threats?bot_category=ai_agents');

        $response->assertOk();
        $this->assertCount(2, $response->json('data.data'));
        $this->assertSame(['ai_agents', 'ai_agents'], array_column($response->json('data.data'), 'bot_category'));

        // Unknown category is ignored rather than returning nothing
        $this->assertCount(3, $this->getJson('/ai-guard/api/threats?bot_category=nope')->json('data.data'));
    }

    public function test_stats_command_shows_v3_rows(): void
    {
        $this->visit('Claude-User/1.0');

        $this->withoutMockingConsoleOutput();
        Artisan::call('ai-guard:stats');
        $output = Artisan::output();

        $this->assertStringContainsString('AI Agents', $output);
        $this->assertStringContainsString('Spoofed Bots', $output);
        $this->assertStringContainsString('Honeypot Traps', $output);
    }

    public function test_robots_txt_command_uses_purpose_categories(): void
    {
        $this->withoutMockingConsoleOutput();
        Artisan::call('ai-guard:robots-txt', ['--categories' => 'ai_assistants']);
        $aliased = Artisan::output();

        $this->assertStringContainsString("User-agent: ChatGPT-User\nDisallow: /", $aliased);
        $this->assertStringContainsString("User-agent: PerplexityBot\nDisallow: /", $aliased);
        $this->assertStringNotContainsString('User-agent: GPTBot', $aliased);
        $this->assertStringContainsString('# Categories: ai_search, ai_agents', $aliased);

        Artisan::call('ai-guard:robots-txt');
        $default = Artisan::output();

        $this->assertStringContainsString("robots.txt-only control token (never sent as a User-Agent)\nUser-agent: Google-Extended", $default);
        $this->assertStringContainsString("# legacy token (retired by the vendor)\nUser-agent: Claude-Web", $default);
        $this->assertStringContainsString("User-agent: GPTBot\nDisallow: /", $default);
    }

    public function test_robots_txt_all_excludes_search_engines_and_counts_unique_tokens(): void
    {
        $this->withoutMockingConsoleOutput();
        Artisan::call('ai-guard:robots-txt', ['--all' => true]);
        $output = Artisan::output();

        $this->assertStringNotContainsString("User-agent: Googlebot\nDisallow", $output);
        $this->assertStringContainsString("User-agent: Googlebot\nAllow: /", $output);

        $expected = [];
        foreach (BotSignatures::getCategories() as $key => $category) {
            if ($key === 'search_engines') {
                continue;
            }
            foreach ($category['bots'] as $bot) {
                $expected[strtolower(rtrim($bot, '/ -'))] = true;
            }
        }
        foreach (BotSignatures::CONTROL_TOKENS as $token) {
            $expected[strtolower($token)] = true;
        }

        $this->assertStringContainsString('# Bots blocked: '.count($expected), $output);
    }
}
