<?php

namespace JayAnta\AiGuard\Tests\Unit;

use Illuminate\Http\Request;
use JayAnta\AiGuard\Services\AiDetector;
use PHPUnit\Framework\TestCase;

class AiDetectorTest extends TestCase
{
    private array $config;
    private AiDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = [
            'ai_crawlers' => [
                'enabled' => true,
                'user_agents' => [
                    'GPTBot', 'ChatGPT-User', 'ClaudeBot', 'anthropic-ai',
                    'CCBot', 'PerplexityBot', 'Bytespider', 'Diffbot',
                ],
            ],
            'data_harvesters' => [
                'enabled' => true,
                'check_accept_language' => true,
                'generic_user_agents' => ['curl', 'python-requests', 'Go-http-client', 'Wget'],
            ],
            'false_positives' => [
                'whitelist_ips' => [],
                'whitelist_user_agents' => [],
            ],
        ];

        $this->detector = new AiDetector($this->config);
    }

    // -------------------------------------------------------------------------
    // Full Cycle: AI Crawler Detection Pipeline
    // -------------------------------------------------------------------------

    public function test_full_cycle_gptbot_detection(): void
    {
        $request = Request::create('/api/data', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
        ]);

        // Step 1: Run full detection pipeline
        $result = $this->detector->detect($request);

        // Step 2: Verify detection result structure
        $this->assertTrue($result['detected']);
        $this->assertSame('ai_crawler', $result['threat_type']);
        $this->assertSame('GPTBot', $result['threat_source']);
        $this->assertSame(95, $result['confidence_score']);
        $this->assertSame('GPTBot', $result['matched_pattern']);

        // Step 3: Verify individual detector also works
        $crawlerResult = $this->detector->detectAiCrawler($request);
        $this->assertTrue($crawlerResult['detected']);
        $this->assertSame($result['threat_type'], $crawlerResult['threat_type']);

        // Step 4: Verify this request is NOT a data harvester
        $harvesterResult = $this->detector->detectDataHarvester($request);
        $this->assertFalse($harvesterResult['detected']);

        // Step 5: Verify not whitelisted
        $this->assertFalse($this->detector->isWhitelisted($request));
    }

    public function test_full_cycle_all_ai_crawlers_detected(): void
    {
        $crawlers = [
            'GPTBot/1.0' => 'GPTBot',
            'ChatGPT-User' => 'ChatGPT-User',
            'ClaudeBot/1.0' => 'ClaudeBot',
            'anthropic-ai/1.0' => 'anthropic-ai',
            'CCBot/2.0 (https://commoncrawl.org)' => 'CCBot',
            'PerplexityBot/1.0' => 'PerplexityBot',
            'Mozilla/5.0 (compatible; Bytespider)' => 'Bytespider',
            'Diffbot/0.1' => 'Diffbot',
        ];

        foreach ($crawlers as $userAgent => $expectedSource) {
            $request = Request::create('/test', 'GET', [], [], [], [
                'HTTP_USER_AGENT' => $userAgent,
                'HTTP_ACCEPT_LANGUAGE' => 'en',
            ]);

            $result = $this->detector->detect($request);

            $this->assertTrue($result['detected'], "Failed to detect: {$userAgent}");
            $this->assertSame('ai_crawler', $result['threat_type'], "Wrong type for: {$userAgent}");
            $this->assertSame($expectedSource, $result['threat_source'], "Wrong source for: {$userAgent}");
            $this->assertSame(95, $result['confidence_score'], "Wrong score for: {$userAgent}");
        }
    }

    // -------------------------------------------------------------------------
    // Full Cycle: Data Harvester Detection Pipeline
    // -------------------------------------------------------------------------

    public function test_full_cycle_curl_detection_with_confidence_stacking(): void
    {
        // Step 1: curl WITH Accept-Language = 80 confidence
        $request = Request::create('/api/users', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'curl/7.88.1',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US',
        ]);

        $result = $this->detector->detect($request);
        $this->assertTrue($result['detected']);
        $this->assertSame('data_harvester', $result['threat_type']);
        $this->assertSame('curl', $result['threat_source']);
        $this->assertSame(80, $result['confidence_score']);

        // Step 2: curl WITHOUT Accept-Language = 100 (80 + 20)
        // Request::create adds a default Accept-Language, so we must explicitly clear it
        $requestNoLang = Request::create('/api/users', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'curl/7.88.1',
            'HTTP_ACCEPT_LANGUAGE' => '',
        ]);

        $resultNoLang = $this->detector->detect($requestNoLang);
        $this->assertTrue($resultNoLang['detected']);
        $this->assertSame('data_harvester', $resultNoLang['threat_type']);
        $this->assertSame(100, $resultNoLang['confidence_score']);

        // Step 3: Verify stacking added 20, not something else
        $this->assertSame(20, $resultNoLang['confidence_score'] - $result['confidence_score']);
    }

    public function test_full_cycle_all_harvester_tools_detected(): void
    {
        $tools = [
            'curl/7.68.0' => 'curl',
            'python-requests/2.28.0' => 'python-requests',
            'Go-http-client/1.1' => 'Go-http-client',
            'Wget/1.21' => 'Wget',
        ];

        foreach ($tools as $userAgent => $expectedSource) {
            $request = Request::create('/test', 'GET', [], [], [], [
                'HTTP_USER_AGENT' => $userAgent,
                'HTTP_ACCEPT_LANGUAGE' => 'en',
            ]);

            $result = $this->detector->detect($request);

            $this->assertTrue($result['detected'], "Failed to detect: {$userAgent}");
            $this->assertSame('data_harvester', $result['threat_type'], "Wrong type for: {$userAgent}");
            $this->assertSame($expectedSource, $result['threat_source'], "Wrong source for: {$userAgent}");
            $this->assertGreaterThanOrEqual(80, $result['confidence_score'], "Low score for: {$userAgent}");
        }
    }

    public function test_full_cycle_missing_accept_language_only(): void
    {
        // A browser-like UA with no Accept-Language triggers low-confidence harvester detection
        // Request::create adds a default Accept-Language, so we must explicitly clear it
        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'SomeUnknownAgent/1.0',
            'HTTP_ACCEPT_LANGUAGE' => '',
        ]);

        $result = $this->detector->detect($request);

        // Missing Accept-Language alone adds 20
        $this->assertTrue($result['detected']);
        $this->assertSame('data_harvester', $result['threat_type']);
        $this->assertSame(20, $result['confidence_score']);
        $this->assertSame('missing_accept_language', $result['matched_pattern']);
    }

    // -------------------------------------------------------------------------
    // Full Cycle: Normal Browser → Clean Pass
    // -------------------------------------------------------------------------

    public function test_full_cycle_normal_browsers_pass_clean(): void
    {
        $browsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
        ];

        foreach ($browsers as $ua) {
            $request = Request::create('/test', 'GET', [], [], [], [
                'HTTP_USER_AGENT' => $ua,
                'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
            ]);

            $result = $this->detector->detect($request);
            $this->assertFalse($result['detected'], "False positive for: {$ua}");
            $this->assertNull($result['threat_type']);
            $this->assertSame(0, $result['confidence_score']);
        }
    }

    // -------------------------------------------------------------------------
    // Full Cycle: AI Crawler Takes Priority Over Data Harvester
    // -------------------------------------------------------------------------

    public function test_full_cycle_ai_crawler_beats_harvester_in_scoring(): void
    {
        // AI crawler score (95) should always beat harvester (80-100)
        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'GPTBot/1.0',
            'HTTP_ACCEPT_LANGUAGE' => 'en',
        ]);

        $result = $this->detector->detect($request);

        // AI crawler (95) wins over any harvester signal
        $this->assertSame('ai_crawler', $result['threat_type']);
        $this->assertSame(95, $result['confidence_score']);
    }

    // -------------------------------------------------------------------------
    // Full Cycle: Whitelist → Complete Bypass
    // -------------------------------------------------------------------------

    public function test_full_cycle_ip_whitelist(): void
    {
        $config = $this->config;
        $config['false_positives']['whitelist_ips'] = ['10.0.0.1', '192.168.1.100'];
        $detector = new AiDetector($config);

        // Whitelisted IP
        $request = Request::create('/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.100',
            'HTTP_USER_AGENT' => 'GPTBot/1.0',
        ]);
        $this->assertTrue($detector->isWhitelisted($request));

        // Non-whitelisted IP
        $requestOther = Request::create('/test', 'GET', [], [], [], [
            'REMOTE_ADDR' => '8.8.8.8',
            'HTTP_USER_AGENT' => 'GPTBot/1.0',
        ]);
        $this->assertFalse($detector->isWhitelisted($requestOther));
    }

    public function test_full_cycle_user_agent_whitelist(): void
    {
        $config = $this->config;
        $config['false_positives']['whitelist_user_agents'] = ['UptimeRobot', 'Pingdom'];
        $detector = new AiDetector($config);

        // Whitelisted UA — case-insensitive
        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'UptimeRobot/2.0',
        ]);
        $this->assertTrue($detector->isWhitelisted($request));

        // Non-whitelisted UA
        $requestOther = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'GPTBot/1.0',
        ]);
        $this->assertFalse($detector->isWhitelisted($requestOther));
    }

    // -------------------------------------------------------------------------
    // Full Cycle: Disabled Detectors → No Detection
    // -------------------------------------------------------------------------

    public function test_full_cycle_disabled_ai_crawlers(): void
    {
        $config = $this->config;
        $config['ai_crawlers']['enabled'] = false;
        $detector = new AiDetector($config);

        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'GPTBot/1.0',
            'HTTP_ACCEPT_LANGUAGE' => 'en',
        ]);

        $result = $detector->detect($request);

        // AI crawler detection disabled — but harvester still runs
        // GPTBot isn't in harvester patterns, so should not be detected as harvester
        $this->assertNotSame('ai_crawler', $result['threat_type']);
    }

    public function test_full_cycle_disabled_harvesters(): void
    {
        $config = $this->config;
        $config['data_harvesters']['enabled'] = false;
        $detector = new AiDetector($config);

        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'curl/7.88.0',
            'HTTP_ACCEPT_LANGUAGE' => 'en',
        ]);

        $result = $detector->detect($request);

        // Harvester disabled — curl not detected
        $this->assertFalse($result['detected']);
    }

    // -------------------------------------------------------------------------
    // Full Cycle: Detector Info
    // -------------------------------------------------------------------------

    public function test_full_cycle_detector_info(): void
    {
        $info = $this->detector->getDetectorInfo();

        $this->assertSame(8, $info['crawler_patterns_count']);
        $this->assertSame(4, $info['harvester_patterns_count']);
        $this->assertTrue($info['ai_crawlers_enabled']);
        $this->assertTrue($info['data_harvesters_enabled']);

        // Verify with different config
        $config = $this->config;
        $config['ai_crawlers']['enabled'] = false;
        $detector = new AiDetector($config);
        $info = $detector->getDetectorInfo();
        $this->assertFalse($info['ai_crawlers_enabled']);
    }

    // -------------------------------------------------------------------------
    // Full Cycle: Empty/Null User Agent
    // -------------------------------------------------------------------------

    public function test_full_cycle_null_user_agent(): void
    {
        $request = Request::create('/test', 'GET');

        $result = $this->detector->detect($request);

        // No UA — not a crawler, but missing Accept-Language triggers harvester
        $this->assertNotSame('ai_crawler', $result['threat_type']);
    }
}
