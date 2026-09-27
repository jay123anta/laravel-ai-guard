<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Services\BotVerifier;
use JayAnta\AiGuard\Support\DnsResolver;
use JayAnta\AiGuard\Tests\Support\FakeDnsResolver;
use JayAnta\AiGuard\Tests\Support\WebBotAuthSigner;
use JayAnta\AiGuard\Tests\TestCase;
use ReflectionClass;
use ReflectionNamedType;
use ReflectionProperty;

/**
 * Pins the ai-guard.verdict/1 contract. Other code depends on these names and shapes without
 * importing anything from this package, so this file deliberately imports no event class
 * either: every event is referred to by its class-name string, the way a consumer would.
 * A failure here means the contract changed — update the fixture, the README and the
 * CHANGELOG's "Interop contract" heading on purpose, or undo the change.
 */
class InteropContractTest extends TestCase
{
    private const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    private const GPTBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)';

    /** @var array<string, mixed> */
    private array $fixture;

    /** @var array<string, array<int, object>> */
    private array $seen = [];

    private string $secret;

    private string $public;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fixture = json_decode((string) file_get_contents(__DIR__.'/../Fixtures/interop/verdict-v1.json'), true);
        [$this->secret, $this->public] = WebBotAuthSigner::keypair();

        $this->app->instance(DnsResolver::class, new FakeDnsResolver);
        config()->set('ai-guard.bot_verification.enabled', true);
        config()->set('ai-guard.bot_verification.web_bot_auth.trusted_agents', ['https://chatgpt.com']);
        $this->refreshAiGuard();

        Http::fake([
            'https://chatgpt.com/.well-known/http-message-signatures-directory' => Http::response(['keys' => [WebBotAuthSigner::jwk($this->public)]]),
            'https://developers.google.com/*' => Http::response(['prefixes' => [['ipv4Prefix' => '66.249.64.0/27']]]),
            '*' => Http::response('unavailable', 503),
        ]);

        // Subscribed by string, as a consumer without this package installed would
        foreach ($this->fixture['events'] as $class) {
            Event::listen($class, function (object $event) use ($class) {
                $this->seen[$class][] = $event;
            });
        }

        $verdict = fn (Request $request) => response()->json(['verdict' => $request->attributes->get('ai_guard.verdict')]);
        Route::middleware(AiGuardMiddleware::class)->get('/page', $verdict);
        Route::middleware([AiGuardMiddleware::class, 'ai-guard.agents'])->get('/checkout', $verdict);
    }

    private function event(string $key): string
    {
        return $this->fixture['events'][$key];
    }

    private function fired(string $key): int
    {
        return count($this->seen[$this->event($key)] ?? []);
    }

    private function visit(string $path, string $userAgent, string $ip = '127.0.0.1', array $headers = []): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->withHeaders(array_merge(['User-Agent' => $userAgent, 'Accept-Language' => 'en'], $headers))
            ->get($path);
    }

    private function signedVisit(string $path = '/checkout'): TestResponse
    {
        $headers = WebBotAuthSigner::headers($this->secret, $this->public, 'localhost', 'https://chatgpt.com', ['nonce' => 'nonce-'.bin2hex(random_bytes(4))]);

        return $this->visit($path, self::CHROME, '127.0.0.1', $headers);
    }

    /**
     * @return array<string, mixed>
     */
    private static function shape(array $value): array
    {
        return array_map(fn ($item) => is_array($item) ? self::shape($item) : 'leaf', $value);
    }

    // -------------------------------------------------------------------------
    // Names and shapes
    // -------------------------------------------------------------------------

    public function test_the_event_classes_exist_under_their_contract_names(): void
    {
        foreach ($this->fixture['events'] as $class) {
            $this->assertTrue(class_exists($class), "{$class} is part of the contract");
            $this->assertSame('ai-guard.verdict/1', constant($class.'::SCHEMA'));
        }
    }

    public function test_every_event_carries_exactly_the_contract_properties(): void
    {
        foreach ($this->fixture['events'] as $class) {
            $properties = [];

            foreach ((new ReflectionClass($class))->getProperties(ReflectionProperty::IS_PUBLIC) as $property) {
                $type = $property->getType();
                $this->assertInstanceOf(ReflectionNamedType::class, $type);
                $this->assertTrue($property->isReadOnly(), "{$class}::\${$property->getName()} must be readonly");

                $properties[$property->getName()] = ($type->allowsNull() ? '?' : '').$type->getName();
            }

            $this->assertEquals($this->fixture['event_properties'], $properties, $class);
        }
    }

    public function test_the_attribute_and_the_event_payload_match_the_fixture(): void
    {
        $this->travelTo(now()->parse('2026-09-27T10:15:00+00:00'));

        $attribute = $this->signedVisit()->assertOk()->json('verdict');
        $event = $this->seen[$this->event('bot_classified')][0]->toArray();

        $this->assertSame(self::shape($this->fixture['attribute']), self::shape($attribute));
        $this->assertSame(self::shape($this->fixture['event']), self::shape($event));

        // The fixture's example is this request, value for value
        $this->assertSame($this->fixture['attribute'], $attribute);
        $this->assertSame($this->fixture['event'], $event);
    }

    public function test_the_enums_are_the_values_the_package_can_produce(): void
    {
        $this->assertSame($this->fixture['enums']['bot.category'], array_keys(BotSignatures::getCategories()));
        $this->assertSame($this->fixture['enums']['verification.status'], [BotVerifier::VERIFIED, BotVerifier::SPOOFED, BotVerifier::UNVERIFIED]);
        $this->assertSame($this->fixture['enums']['verification.method'], BotVerifier::METHODS);
    }

    // -------------------------------------------------------------------------
    // Behaviour
    // -------------------------------------------------------------------------

    public function test_a_signed_agent_through_both_middlewares_is_announced_once(): void
    {
        $this->signedVisit()->assertOk();

        $this->assertSame(1, $this->fired('bot_classified'));
        $this->assertSame(1, $this->fired('agent_verified'));
        $this->assertSame(0, $this->fired('spoofed_bot_detected'));

        $event = $this->seen[$this->event('agent_verified')][0];
        $this->assertSame(['ai_agents', 'chatgpt.com', 'verified', 'web_bot_auth', 'checkout'], [$event->category, $event->identity, $event->status, $event->method, $event->path]);
    }

    public function test_a_spoofed_crawler_is_announced(): void
    {
        $this->visit('/page', self::GOOGLEBOT, '203.0.113.9');

        $this->assertSame(1, $this->fired('bot_classified'));
        $this->assertSame(1, $this->fired('spoofed_bot_detected'));
        $this->assertSame(0, $this->fired('agent_verified'));
        $this->assertSame('spoofed', $this->seen[$this->event('spoofed_bot_detected')][0]->status);
    }

    public function test_the_verdict_reports_identity_even_for_a_disabled_category(): void
    {
        // search_engines is in disabled_categories by default: not acted on, but still identified
        $verdict = $this->visit('/page', self::GOOGLEBOT, '66.249.64.1')->assertOk()->json('verdict');

        $this->assertSame(['category' => 'search_engines', 'token' => 'Googlebot', 'identity' => 'Googlebot'], $verdict['bot']);
        $this->assertSame(['status' => 'verified', 'method' => 'ip_ranges'], $verdict['verification']);
        $this->assertSame(1, $this->fired('agent_verified'));
    }

    public function test_a_recognised_bot_is_classified_without_verification(): void
    {
        config()->set('ai-guard.bot_verification.enabled', false);
        $this->refreshAiGuard();

        $verdict = $this->visit('/page', self::GPTBOT)->json('verdict');

        $this->assertSame(['category' => 'ai_training', 'token' => 'GPTBot', 'identity' => null], $verdict['bot']);
        $this->assertSame(['status' => null, 'method' => null], $verdict['verification']);
        $this->assertSame(1, $this->fired('bot_classified'));
        $this->assertSame(0, $this->fired('agent_verified') + $this->fired('spoofed_bot_detected'));
    }

    public function test_an_ordinary_visitor_is_evaluated_but_not_announced(): void
    {
        $verdict = $this->visit('/page', self::CHROME)->assertOk()->json('verdict');

        $this->assertSame('ai-guard.verdict/1', $verdict['schema']);
        $this->assertSame(['category' => null, 'token' => null, 'identity' => null], $verdict['bot']);
        $this->assertSame([], $this->seen);
    }

    public function test_the_kill_switch_stops_the_events_but_keeps_the_attribute(): void
    {
        config()->set('ai-guard.interop.enabled', false);

        $verdict = $this->signedVisit()->assertOk()->json('verdict');

        $this->assertSame('verified', $verdict['verification']['status']);
        $this->assertSame([], $this->seen);
    }

    public function test_a_throwing_listener_does_not_change_the_response(): void
    {
        Event::listen($this->event('agent_verified'), function () {
            throw new \RuntimeException('listener bug');
        });

        $this->signedVisit()->assertOk();
        $this->assertSame(1, $this->fired('bot_classified'));
    }

    public function test_a_whitelisted_request_is_not_evaluated(): void
    {
        config()->set('ai-guard.false_positives.whitelist_user_agents', ['GPTBot']);
        $this->refreshAiGuard();

        // Neither by the main middleware nor by the agent policy
        $this->assertNull($this->visit('/page', self::GPTBOT)->json('verdict'));
        $this->assertNull($this->visit('/checkout', self::GPTBOT)->assertOk()->json('verdict'));
        $this->assertSame([], $this->seen);
    }

    public function test_a_forged_signature_is_announced_as_spoofed(): void
    {
        [$attackerKey] = WebBotAuthSigner::keypair();
        $headers = WebBotAuthSigner::headers($attackerKey, $this->public, 'localhost', 'https://chatgpt.com');

        $this->visit('/page', self::CHROME, '127.0.0.1', $headers);

        $this->assertSame(1, $this->fired('bot_classified'));
        $this->assertSame(1, $this->fired('spoofed_bot_detected'));
        $event = $this->seen[$this->event('spoofed_bot_detected')][0];
        $this->assertSame(['ai_agents', 'chatgpt.com', 'spoofed', 'web_bot_auth'], [$event->category, $event->identity, $event->status, $event->method]);
    }

    public function test_the_agent_policy_alone_evaluates_the_request(): void
    {
        Route::middleware('ai-guard.agents')->get('/agents-only', fn (Request $request) => response()->json(['verdict' => $request->attributes->get('ai_guard.verdict')]));

        $verdict = $this->signedVisit('/agents-only')->assertOk()->json('verdict');

        $this->assertSame('verified', $verdict['verification']['status']);
        $this->assertSame(1, $this->fired('agent_verified'));
    }
}
