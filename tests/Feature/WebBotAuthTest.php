<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Support\DnsResolver;
use JayAnta\AiGuard\Tests\Support\FakeDnsResolver;
use JayAnta\AiGuard\Tests\Support\WebBotAuthSigner;
use JayAnta\AiGuard\Tests\TestCase;

class WebBotAuthTest extends TestCase
{
    private const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    private const DIRECTORY = 'https://chatgpt.com/.well-known/http-message-signatures-directory';

    private string $secret;

    private string $public;

    protected function setUp(): void
    {
        parent::setUp();

        [$this->secret, $this->public] = WebBotAuthSigner::keypair();

        config()->set('ai-guard.bot_verification.enabled', true);
        config()->set('ai-guard.bot_verification.web_bot_auth.trusted_agents', ['https://chatgpt.com']);
        $this->refreshAiGuard();

        Http::fake([
            self::DIRECTORY => Http::response(['keys' => [WebBotAuthSigner::jwk($this->public)]]),
        ]);

        Route::middleware(AiGuardMiddleware::class)->get('/page', fn () => response('ok'));
    }

    private function signedGet(array $options = [], ?string $signingKey = null, string $userAgent = self::CHROME): TestResponse
    {
        $headers = WebBotAuthSigner::headers(
            $signingKey ?? $this->secret,
            $this->public,
            $options['authority'] ?? 'localhost',
            $options['agent'] ?? 'https://chatgpt.com',
            $options
        );

        return $this->withHeaders(array_merge(['User-Agent' => $userAgent, 'Accept-Language' => 'en'], $headers))->get('/page');
    }

    public function test_signed_agent_with_browser_user_agent_is_identified(): void
    {
        $this->signedGet()->assertOk();

        $log = AiThreatLog::first();
        $this->assertNotNull($log, 'A verified signed agent should be visible in the logs');
        $this->assertSame('ai_crawler', $log->threat_type);
        $this->assertSame('chatgpt.com', $log->threat_source);
        $this->assertSame('ai_agents', $log->bot_category);
        $this->assertSame('verified', $log->bot_verification);
        $this->assertSame(60, $log->confidence_score);
        $this->assertSame('web-bot-auth: chatgpt.com', $log->matched_pattern);

        Http::assertSent(fn (HttpRequest $request) => $request->url() === self::DIRECTORY);
    }

    public function test_signature_from_the_wrong_key_is_spoofed_and_blocked(): void
    {
        config()->set('ai-guard.mode', 'block');
        $this->refreshAiGuard();

        [$attackerKey] = WebBotAuthSigner::keypair();

        $response = $this->signedGet([], $attackerKey);

        $response->assertStatus(403);
        $response->assertJson(['threat_type' => 'spoofed_bot']);

        $log = AiThreatLog::first();
        $this->assertSame('spoofed', $log->bot_verification);
        $this->assertStringContainsString('signature does not verify', $log->matched_pattern);
    }

    public function test_signature_for_another_host_does_not_verify(): void
    {
        $this->signedGet(['authority' => 'evil.example']);

        $this->assertSame('spoofed_bot', AiThreatLog::first()->threat_type);
    }

    public function test_expired_signature_is_not_trusted_and_no_directory_is_fetched(): void
    {
        $this->signedGet(['created' => time() - 3600, 'expires' => time() - 3000])->assertOk();

        $this->assertDatabaseCount('ai_threat_logs', 0);
        Http::assertNothingSent();
    }

    public function test_untrusted_agent_directory_is_never_fetched(): void
    {
        $this->signedGet(['agent' => 'https://random-agent.example'])->assertOk();

        $this->assertDatabaseCount('ai_threat_logs', 0);
        Http::assertNothingSent();
    }

    public function test_allow_any_agent_still_refuses_internal_hosts(): void
    {
        $dns = new FakeDnsResolver;
        $dns->addresses['internal.corp'] = ['10.0.0.5'];
        $dns->addresses['public-agent.example'] = ['93.184.216.34'];
        $this->app->instance(DnsResolver::class, $dns);

        config()->set('ai-guard.bot_verification.web_bot_auth.allow_any_agent', true);
        $this->refreshAiGuard();

        Http::fake([
            'https://public-agent.example/.well-known/http-message-signatures-directory' => Http::response(['keys' => [WebBotAuthSigner::jwk($this->public)]]),
        ]);

        $this->signedGet(['agent' => 'https://internal.corp']);
        $this->signedGet(['agent' => 'https://127.0.0.1']);
        Http::assertNothingSent();

        $this->signedGet(['agent' => 'https://public-agent.example']);
        $this->assertSame('public-agent.example', AiThreatLog::first()->threat_source);
        $this->assertSame('verified', AiThreatLog::first()->bot_verification);
    }

    public function test_unknown_keyid_is_not_verified(): void
    {
        [, $otherPublic] = WebBotAuthSigner::keypair();

        $this->signedGet(['keyid' => WebBotAuthSigner::keyid($otherPublic)])->assertOk();

        $this->assertDatabaseCount('ai_threat_logs', 0);
    }

    public function test_a_signature_must_cover_the_target_host(): void
    {
        // Covering neither @authority nor @target-uri makes the signature valid on every host:
        // a request signed for one site could be replayed at any other
        $this->signedGet(['components' => ['signature-agent']])->assertOk();

        // Read as an ordinary browser: never verified, and not branded spoofed either
        $this->assertSame(0, AiThreatLog::where('bot_verification', 'verified')->count());
        $this->assertSame(0, AiThreatLog::where('bot_verification', 'spoofed')->count());
    }

    public function test_the_signature_agent_header_must_be_covered(): void
    {
        // An uncovered Signature-Agent can be rewritten in transit to point at another directory
        $this->signedGet(['components' => ['@authority']])->assertOk();

        $this->assertSame(0, AiThreatLog::where('bot_verification', 'verified')->count());
    }

    public function test_target_uri_satisfies_the_coverage_rule(): void
    {
        $this->signedGet(['components' => ['@target-uri', 'signature-agent'], 'target_uri' => 'http://localhost/page'])->assertOk();

        $this->assertSame('verified', AiThreatLog::sole()->bot_verification);
    }

    public function test_a_signed_agent_is_verified_once_per_request_across_middlewares(): void
    {
        // Both middlewares on one route: the second used to re-verify, find the nonce already
        // spent, and deny the agent it had just verified as spoofed
        Route::middleware([AiGuardMiddleware::class, 'ai-guard.agents'])->get('/both', fn () => response('ok'));

        $headers = WebBotAuthSigner::headers($this->secret, $this->public, 'localhost', 'https://chatgpt.com', ['nonce' => 'nonce-'.bin2hex(random_bytes(4))]);

        $this->withHeaders(array_merge(['User-Agent' => self::CHROME, 'Accept-Language' => 'en'], $headers))
            ->get('/both')
            ->assertOk();

        $this->assertSame(['verified'], AiThreatLog::pluck('bot_verification')->all());
        $this->assertSame(0, AiThreatLog::where('threat_type', 'ai_agent_denied')->count());
    }

    public function test_replayed_nonce_is_rejected(): void
    {
        $options = ['nonce' => 'nonce-'.bin2hex(random_bytes(4))];

        $this->signedGet($options);
        $this->signedGet($options);

        $logs = AiThreatLog::orderBy('id')->get();
        $this->assertSame('verified', $logs[0]->bot_verification);
        $this->assertSame('spoofed_bot', $logs[1]->threat_type);
        $this->assertStringContainsString('replayed nonce', $logs[1]->matched_pattern);
    }

    public function test_key_directory_is_cached(): void
    {
        $this->signedGet();
        $this->signedGet();

        Http::assertSentCount(1);
    }

    public function test_dictionary_form_signature_agent_is_supported(): void
    {
        $this->signedGet(['agent_header' => 'sig1="https://chatgpt.com"']);

        $this->assertSame('verified', AiThreatLog::first()->bot_verification);
    }

    public function test_user_agent_detection_is_annotated_with_the_signature_verdict(): void
    {
        $this->signedGet([], null, 'Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)');

        $log = AiThreatLog::first();
        $this->assertSame('ChatGPT-User', $log->threat_source);
        $this->assertSame('verified', $log->bot_verification);
    }
}
