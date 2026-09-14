<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\RequestFingerprinter;
use JayAnta\AiGuard\Tests\TestCase;

class EdgeFingerprintTest extends TestCase
{
    private const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    private const BROWSER_JA4 = 't13d1516h2_8daaf6152771_02713d6af862';

    private const HTTP1_JA4 = 't13d1812h1_85036bcba153_b26ce05bbdd6';

    private const AWS = 'https://ip-ranges.amazonaws.com/ip-ranges.json';

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('ai-guard.fingerprinting.enabled', true);
        config()->set('ai-guard.fingerprinting.datacenter.ranges', ['aws' => self::AWS]);
        $this->refreshAiGuard();

        Http::fake([
            'ip-ranges.amazonaws.com/*' => Http::response([
                'prefixes' => [['ip_prefix' => '3.5.140.0/22']],
                'ipv6_prefixes' => [['ipv6_prefix' => '2600:1f14::/35']],
            ]),
            'ranges.example.test/*' => Http::response("45.33.0.0/16,US\n"),
            'down.example.test/*' => Http::response('', 503),
        ]);
    }

    protected function tearDown(): void
    {
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        if (method_exists(TrustProxies::class, 'flushState')) {
            TrustProxies::flushState();
        } elseif (method_exists(TrustProxies::class, 'at')) {
            TrustProxies::at([]);
        }

        parent::tearDown();
    }

    /**
     * Trust the test client as a proxy. Laravel 11+ resets trusted proxies in its
     * TrustProxies middleware on every request, so it is configured there too.
     */
    private function trustLocalProxy(): void
    {
        Request::setTrustedProxies(['127.0.0.1'], Request::HEADER_X_FORWARDED_FOR);

        if (method_exists(TrustProxies::class, 'at')) {
            TrustProxies::at('127.0.0.1');
        }
    }

    private function browserHeaders(array $overrides = []): array
    {
        return array_merge([
            'User-Agent' => self::CHROME,
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' => 'en-US,en;q=0.9',
            'Accept-Encoding' => 'gzip, deflate, br',
            'Sec-CH-UA' => '"Chromium";v="128"',
            'Sec-CH-UA-Mobile' => '?0',
            'Sec-CH-UA-Platform' => '"Windows"',
            'Sec-Fetch-Dest' => 'document',
            'Sec-Fetch-Mode' => 'navigate',
            'Sec-Fetch-Site' => 'none',
            'Upgrade-Insecure-Requests' => '1',
            'Connection' => 'keep-alive',
        ], $overrides);
    }

    private function analyze(array $headers = [], string $ip = '198.18.0.10', bool $trusted = true): array
    {
        Request::setTrustedProxies($trusted ? [$ip] : [], Request::HEADER_X_FORWARDED_FOR);

        $server = ['REMOTE_ADDR' => $ip];
        foreach ($this->browserHeaders($headers) as $name => $value) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
        }

        return app(RequestFingerprinter::class)->analyze(Request::create('/page', 'GET', [], [], [], $server));
    }

    public function test_a_real_browser_passes(): void
    {
        $this->assertFalse($this->analyze(['cf-ja4' => self::BROWSER_JA4, 'cf-bot-score' => '97'])['detected']);
    }

    public function test_ja4_that_contradicts_a_browser_user_agent_is_flagged(): void
    {
        $result = $this->analyze(['cf-ja4' => self::HTTP1_JA4]);

        $this->assertTrue($result['detected']);
        $this->assertSame('suspicious_fingerprint', $result['threat_type']);
        $this->assertSame('ja4_user_agent_mismatch', $result['matched_pattern']);
        $this->assertSame(35, $result['confidence_score']);

        $this->assertTrue($this->analyze(['CloudFront-Viewer-JA4-Fingerprint' => 't13i1516h2_8daaf6152771_02713d6af862'])['detected'], 'No SNI');
    }

    public function test_edge_headers_count_only_from_a_trusted_proxy(): void
    {
        $this->assertFalse($this->analyze(['cf-ja4' => self::HTTP1_JA4, 'cf-bot-score' => '1'], trusted: false)['detected']);

        config()->set('ai-guard.fingerprinting.edge.require_trusted_proxy', false);
        $this->refreshAiGuard();
        $this->assertTrue($this->analyze(['cf-ja4' => self::HTTP1_JA4], trusted: false)['detected']);
    }

    public function test_listed_http_clients_and_bot_scores(): void
    {
        config()->set('ai-guard.fingerprinting.edge.client_ja4', ['t13d1516h2_8daaf6152771*']);
        $this->refreshAiGuard();

        $this->assertStringContainsString('ja4_http_client', (string) $this->analyze(['cf-ja4' => self::BROWSER_JA4])['matched_pattern']);

        $this->assertSame('edge_bot_score:1', $this->analyze(['cf-bot-score' => '1'])['matched_pattern']);
        $this->assertFalse($this->analyze(['cf-bot-score' => '12'])['detected'], '25 alone is below min_score');
        $this->assertFalse($this->analyze(['cf-bot-score' => 'high'])['detected']);
    }

    public function test_browser_user_agents_from_datacenter_networks(): void
    {
        config()->set('ai-guard.fingerprinting.datacenter.enabled', true);
        config()->set('ai-guard.fingerprinting.min_score', 25);
        $this->refreshAiGuard();

        $this->assertSame('datacenter_ip:aws', $this->analyze(ip: '3.5.141.9', trusted: false)['matched_pattern']);
        $this->assertSame('datacenter_ip:aws', $this->analyze(ip: '2600:1f14:1abc::1', trusted: false)['matched_pattern']);
        $this->assertFalse($this->analyze(ip: '2600:1f14:abcd::1', trusted: false)['detected'], 'Outside the /35');
        $this->assertFalse($this->analyze(ip: '3.5.144.1', trusted: false)['detected']);

        // Declared bots and private addresses are not datacenter-scored
        $this->assertFalse($this->analyze(['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)'], '3.5.141.9', false)['detected']);
        $this->assertFalse($this->analyze(ip: '10.0.0.5', trusted: false)['detected']);

        Http::assertSentCount(1);
    }

    public function test_text_lists_literal_cidrs_and_unavailable_lists(): void
    {
        config()->set('ai-guard.fingerprinting.datacenter.enabled', true);
        config()->set('ai-guard.fingerprinting.min_score', 25);
        config()->set('ai-guard.fingerprinting.datacenter.ranges', [
            'down' => 'https://down.example.test/list.json',
            'linode' => 'https://ranges.example.test/list.csv',
            'lab' => ['51.15.0.0/16'],
        ]);
        $this->refreshAiGuard();

        $this->assertSame('datacenter_ip:linode', $this->analyze(ip: '45.33.12.1', trusted: false)['matched_pattern']);
        $this->assertSame('datacenter_ip:lab', $this->analyze(ip: '51.15.3.3', trusted: false)['matched_pattern']);
        $this->assertFalse($this->analyze(ip: '8.8.8.8', trusted: false)['detected']);
    }

    public function test_cold_lists_can_be_left_to_the_refresh_command(): void
    {
        config()->set('ai-guard.fingerprinting.datacenter.enabled', true);
        config()->set('ai-guard.fingerprinting.datacenter.fetch_on_request', false);
        config()->set('ai-guard.fingerprinting.min_score', 25);
        config()->set('ai-guard.bot_verification.crawlers', ['GPTBot' => ['ip_ranges' => ['https://down.example.test/gptbot.json']]]);
        $this->refreshAiGuard();

        $this->assertFalse($this->analyze(ip: '3.5.141.9', trusted: false)['detected']);
        Http::assertNothingSent();

        $this->artisan('ai-guard:refresh-ranges')
            ->expectsOutputToContain('2 ranges')
            ->expectsOutputToContain('failed')
            ->assertFailed();

        $this->refreshAiGuard();
        $this->assertSame('datacenter_ip:aws', $this->analyze(ip: '3.5.141.9', trusted: false)['matched_pattern']);
    }

    public function test_edge_signals_reach_the_middleware(): void
    {
        $this->trustLocalProxy();
        Route::get('/edge-page', fn () => 'ok')->middleware(AiGuardMiddleware::class);

        $this->get('/edge-page', $this->browserHeaders(['cf-ja4' => self::HTTP1_JA4]))->assertOk();

        $log = AiThreatLog::sole();
        $this->assertSame('suspicious_fingerprint', $log->threat_type);
        $this->assertStringContainsString('ja4_user_agent_mismatch', (string) $log->matched_pattern);
    }
}
