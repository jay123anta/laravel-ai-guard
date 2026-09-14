<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use JayAnta\AiGuard\Facades\AiGuard;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Support\DnsResolver;
use JayAnta\AiGuard\Tests\Support\FakeDnsResolver;
use JayAnta\AiGuard\Tests\TestCase;

class BotVerificationTest extends TestCase
{
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    private const GPTBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)';

    private FakeDnsResolver $dns;

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('ai-guard.api.middleware', ['api']);
        $app['config']->set('ai-guard.dashboard.middleware', ['web']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->dns = new FakeDnsResolver;
        $this->app->instance(DnsResolver::class, $this->dns);

        config()->set('ai-guard.bot_verification.enabled', true);
        $this->refreshAiGuard();

        Http::fake([
            'https://developers.google.com/*' => Http::response([
                'creationTime' => '2026-09-01T00:00:00.000000',
                'prefixes' => [['ipv4Prefix' => '66.249.64.0/27'], ['ipv6Prefix' => '2001:4860:4801:10::/64']],
            ]),
            'https://openai.com/gptbot.json' => Http::response(['prefixes' => [['ipv4Prefix' => '20.171.206.0/24']]]),
            '*' => Http::response('unavailable', 503),
        ]);

        Route::middleware(AiGuardMiddleware::class)->get('/page', fn () => response('ok'));
    }

    private function visitFrom(string $ip, string $userAgent): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->withHeaders(['User-Agent' => $userAgent, 'Accept-Language' => 'en'])
            ->get('/page');
    }

    private function verifyFrom(string $ip, string $userAgent): array
    {
        return AiGuard::verifyBot(Request::create('/page', 'GET', [], [], [], [
            'REMOTE_ADDR' => $ip,
            'HTTP_USER_AGENT' => $userAgent,
        ]));
    }

    // -------------------------------------------------------------------------
    // Published IP ranges
    // -------------------------------------------------------------------------

    public function test_real_googlebot_is_verified_by_published_ranges(): void
    {
        $this->visitFrom('66.249.64.5', self::GOOGLEBOT)->assertOk();
        $this->assertDatabaseCount('ai_threat_logs', 0);

        $verdict = $this->verifyFrom('66.249.64.5', self::GOOGLEBOT);
        $this->assertSame('verified', $verdict['status']);
        $this->assertSame('ip_ranges', $verdict['method']);
        $this->assertSame('Googlebot', $verdict['token']);
        $this->assertSame('search_engines', $verdict['category']);

        $this->assertSame('verified', $this->verifyFrom('2001:4860:4801:10::1', self::GOOGLEBOT)['status']);
    }

    public function test_fake_googlebot_is_spoofed_and_blocked(): void
    {
        config()->set('ai-guard.mode', 'block');
        $this->refreshAiGuard();

        $response = $this->visitFrom('203.0.113.9', self::GOOGLEBOT);

        $response->assertStatus(403);
        $response->assertJson(['threat_type' => 'spoofed_bot']);

        $log = AiThreatLog::first();
        $this->assertSame('Googlebot', $log->threat_source);
        $this->assertSame('spoofed', $log->bot_verification);
        $this->assertSame('search_engines', $log->bot_category);
        $this->assertSame(90, $log->confidence_score);
        $this->assertStringContainsString('IP not in published ranges', $log->matched_pattern);
        $this->assertStringContainsString('reverse DNS does not confirm', $log->matched_pattern);
        $this->assertSame('Spoofed Bot', $log->getThreatTypeLabel());
    }

    // -------------------------------------------------------------------------
    // Forward-confirmed reverse DNS
    // -------------------------------------------------------------------------

    public function test_reverse_dns_verifies_when_forward_confirmed(): void
    {
        $this->dns->ptr['17.58.101.2'] = '17-58-101-2.applebot.apple.com.';
        $this->dns->addresses['17-58-101-2.applebot.apple.com'] = ['17.58.101.2'];

        $verdict = $this->verifyFrom('17.58.101.2', 'Mozilla/5.0 (Macintosh) Applebot/0.1');

        $this->assertSame('verified', $verdict['status']);
        $this->assertSame('reverse_dns', $verdict['method']);
    }

    public function test_reverse_dns_without_forward_confirmation_is_spoofed(): void
    {
        // Attacker controls the PTR record for their own IP, but not Apple's forward zone
        $this->dns->ptr['198.51.100.20'] = 'crawl.applebot.apple.com';
        $this->dns->addresses['crawl.applebot.apple.com'] = ['17.58.101.2'];

        $this->assertSame('spoofed', $this->verifyFrom('198.51.100.20', 'Applebot/0.1')['status']);
    }

    public function test_look_alike_ptr_suffix_is_spoofed(): void
    {
        $this->dns->ptr['198.51.100.21'] = 'crawl.applebot.apple.com.evil.example';
        $this->dns->addresses['crawl.applebot.apple.com.evil.example'] = ['198.51.100.21'];

        $this->assertSame('spoofed', $this->verifyFrom('198.51.100.21', 'Applebot/0.1')['status']);
    }

    // -------------------------------------------------------------------------
    // AI crawlers
    // -------------------------------------------------------------------------

    public function test_spoofed_ai_crawler_is_reported_as_spoofed_bot(): void
    {
        $this->visitFrom('198.51.100.7', self::GPTBOT);

        $log = AiThreatLog::first();
        $this->assertSame('spoofed_bot', $log->threat_type);
        $this->assertSame('ai_training', $log->bot_category);
        // max(spoofed_confidence 90, the claim's own 95)
        $this->assertSame(95, $log->confidence_score);
    }

    public function test_verified_ai_crawler_is_annotated(): void
    {
        $this->visitFrom('20.171.206.9', self::GPTBOT);

        $log = AiThreatLog::first();
        $this->assertSame('ai_crawler', $log->threat_type);
        $this->assertSame('verified', $log->bot_verification);
        $this->assertSame('Verified', $log->getVerificationLabel());
    }

    public function test_unreachable_range_list_is_unverified_not_spoofed(): void
    {
        $this->visitFrom('198.51.100.8', 'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)');

        $log = AiThreatLog::first();
        $this->assertSame('ai_crawler', $log->threat_type);
        $this->assertSame('unverified', $log->bot_verification);

        $verdict = $this->verifyFrom('198.51.100.8', 'OAI-SearchBot/1.0');
        $this->assertSame('published ranges unavailable', $verdict['detail']);
    }

    // -------------------------------------------------------------------------
    // Caching and opt-in
    // -------------------------------------------------------------------------

    public function test_verdicts_and_range_lists_are_cached(): void
    {
        $this->visitFrom('20.171.206.9', self::GPTBOT);
        $this->visitFrom('20.171.206.9', self::GPTBOT);
        $this->visitFrom('20.171.206.10', self::GPTBOT);

        // One range fetch serves all three requests
        Http::assertSentCount(1);

        $this->visitFrom('203.0.113.9', self::GOOGLEBOT);
        $lookups = $this->dns->lookups;
        $this->visitFrom('203.0.113.9', self::GOOGLEBOT);
        $this->assertSame($lookups, $this->dns->lookups);
    }

    public function test_disabled_verification_makes_no_lookups(): void
    {
        config()->set('ai-guard.bot_verification.enabled', false);
        $this->refreshAiGuard();

        $this->visitFrom('203.0.113.9', self::GOOGLEBOT)->assertOk();

        Http::assertNothingSent();
        $this->assertSame(0, $this->dns->lookups);
        $this->assertDatabaseCount('ai_threat_logs', 0);
        $this->assertNull($this->verifyFrom('203.0.113.9', self::GOOGLEBOT)['status']);
    }

    // -------------------------------------------------------------------------
    // Verdicts surface in stats, API, and dashboard
    // -------------------------------------------------------------------------

    public function test_verdicts_are_reported_everywhere(): void
    {
        $this->visitFrom('203.0.113.9', self::GOOGLEBOT);
        $this->visitFrom('20.171.206.9', self::GPTBOT);

        $this->assertSame(1, AiThreatLog::getThreatSummary(1)['spoofed_bots']);
        $this->assertSame(1, AiThreatLog::spoofedBots()->count());

        $api = $this->getJson('/ai-guard/api/threats?bot_verification=spoofed');
        $api->assertOk();
        $this->assertCount(1, $api->json('data.data'));
        $this->assertSame('Googlebot', $api->json('data.data.0.threat_source'));

        $dashboard = $this->get('/ai-guard');
        $dashboard->assertOk();
        $dashboard->assertSee('Spoofed');
        $dashboard->assertSee('Verified');
    }
}
