<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Tests\TestCase;

class RobotsTxtEnforcementTest extends TestCase
{
    private string $robotsPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->robotsPath = (string) tempnam(sys_get_temp_dir(), 'ai-guard-robots');
        file_put_contents($this->robotsPath, implode("\n", [
            'User-agent: GPTBot',
            'User-agent: ClaudeBot',
            'Disallow: /private',
            'Allow: /private/press',
            '',
            'User-agent: *',
            'Disallow: /tmp',
        ]));

        config()->set('ai-guard.robots_txt.enabled', true);
        config()->set('ai-guard.robots_txt.path', $this->robotsPath);
        $this->refreshAiGuard();

        Route::middleware(AiGuardMiddleware::class)->group(function () {
            Route::get('/private/{page}', fn () => response('ok'));
            Route::get('/tmp/{page}', fn () => response('ok'));
        });
    }

    protected function tearDown(): void
    {
        @unlink($this->robotsPath);

        parent::tearDown();
    }

    public function test_every_agent_in_a_grouped_block_is_enforced(): void
    {
        foreach (['GPTBot/1.1', 'ClaudeBot/1.0'] as $userAgent) {
            $this->withHeaders(['User-Agent' => $userAgent, 'Accept-Language' => 'en'])->get('/private/data');
        }

        $logs = AiThreatLog::orderBy('id')->get();
        $this->assertCount(2, $logs);

        foreach ($logs as $log) {
            $this->assertSame(100, $log->confidence_score);
            $this->assertStringContainsString('robots.txt disallow: /private', $log->matched_pattern);
        }
    }

    public function test_allow_rule_overrides_shorter_disallow(): void
    {
        $this->withHeaders(['User-Agent' => 'GPTBot/1.1', 'Accept-Language' => 'en'])->get('/private/press');

        $log = AiThreatLog::first();
        $this->assertSame(95, $log->confidence_score);
        $this->assertStringNotContainsString('robots.txt', $log->matched_pattern);
    }

    public function test_named_bot_is_not_bound_by_wildcard_group(): void
    {
        // GPTBot has its own group, so the "*" Disallow: /tmp does not apply to it
        $this->withHeaders(['User-Agent' => 'GPTBot/1.1', 'Accept-Language' => 'en'])->get('/tmp/cache');
        $this->assertSame(95, AiThreatLog::first()->confidence_score);

        // CCBot has no group of its own — the wildcard applies
        $this->withHeaders(['User-Agent' => 'CCBot/2.0', 'Accept-Language' => 'en'])->get('/tmp/cache');
        $ccbot = AiThreatLog::where('threat_source', 'CCBot')->first();
        $this->assertSame(100, $ccbot->confidence_score);
        $this->assertStringContainsString('robots.txt disallow: /tmp', $ccbot->matched_pattern);
    }
}
