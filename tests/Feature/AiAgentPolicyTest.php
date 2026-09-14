<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Tests\TestCase;

class AiAgentPolicyTest extends TestCase
{
    private const CHATGPT_USER = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot';

    protected function setUp(): void
    {
        parent::setUp();

        Route::get('/checkout', fn () => 'checkout')->middleware('ai-guard.agents');
        Route::get('/account', fn () => 'account')->middleware('ai-guard.agents:deny');
        Route::get('/docs', fn () => 'docs')->middleware('ai-guard.agents:allow');

        Http::fake(['openai.com/chatgpt-user.json' => Http::response(['prefixes' => [['ipv4Prefix' => '20.171.0.0/16']]])]);
    }

    private function verification(bool $enabled = true): void
    {
        config()->set('ai-guard.bot_verification.enabled', $enabled);
        config()->set('ai-guard.bot_verification.methods', ['ip_ranges']);
        $this->refreshAiGuard();
    }

    public function test_unverified_agents_are_refused_and_logged_in_any_mode(): void
    {
        $this->get('/checkout', ['User-Agent' => self::CHATGPT_USER])
            ->assertForbidden()
            ->assertSee('Only verified AI agents may use this page.');

        $log = AiThreatLog::sole();
        $this->assertSame('ai_agent_denied', $log->threat_type);
        $this->assertSame('ChatGPT-User', $log->threat_source);
        $this->assertSame('blocked', $log->action_taken);
        $this->assertSame('verified: ChatGPT-User (unverified)', $log->matched_pattern);

        $this->getJson('/checkout', ['User-Agent' => self::CHATGPT_USER])->assertForbidden()->assertJsonPath('error', 'Access denied');
    }

    public function test_verified_agents_pass(): void
    {
        $this->verification();

        $this->withServerVariables(['REMOTE_ADDR' => '20.171.4.2'])
            ->get('/checkout', ['User-Agent' => self::CHATGPT_USER])
            ->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])
            ->get('/checkout', ['User-Agent' => self::CHATGPT_USER])
            ->assertForbidden();

        $this->assertSame('verified: ChatGPT-User (spoofed)', AiThreatLog::latest('id')->first()->matched_pattern);
    }

    public function test_deny_and_allow_policies(): void
    {
        $this->verification();

        $this->withServerVariables(['REMOTE_ADDR' => '20.171.4.2'])
            ->get('/account', ['User-Agent' => self::CHATGPT_USER])
            ->assertForbidden()
            ->assertSee('AI agents may not use this page.');

        $this->get('/docs', ['User-Agent' => self::CHATGPT_USER])->assertOk();
    }

    public function test_people_and_non_agent_crawlers_are_not_affected(): void
    {
        $browser = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

        $this->get('/account', ['User-Agent' => $browser])->assertOk();
        $this->get('/account', ['User-Agent' => 'GPTBot/1.1'])->assertOk();
        $this->assertSame(0, AiThreatLog::count());
    }
}
