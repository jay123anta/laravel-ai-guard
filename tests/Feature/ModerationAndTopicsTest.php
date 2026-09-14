<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Facades\AiGuard;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Tests\TestCase;

class ModerationAndTopicsTest extends TestCase
{
    private function moderation(string $driver, array $extra = []): void
    {
        config()->set('ai-guard.llm_guard.moderation.enabled', true);
        config()->set('ai-guard.llm_guard.moderation.driver', $driver);
        config()->set('ai-guard.llm_guard.moderation.drivers.openai.api_key', 'sk-test');
        foreach ($extra as $key => $value) {
            config()->set("ai-guard.llm_guard.moderation.{$key}", $value);
        }
        $this->refreshAiGuard();
    }

    private static function openAiResult(bool $flagged, array $categories = [], float $top = 0.0): array
    {
        return ['id' => 'modr-1', 'model' => 'omni-moderation-latest', 'results' => [[
            'flagged' => $flagged,
            'categories' => array_fill_keys($categories, true) + ['sexual' => false],
            'category_scores' => array_fill_keys($categories, $top) + ['sexual' => 0.001],
        ]]];
    }

    // -------------------------------------------------------------------------
    // Moderation drivers
    // -------------------------------------------------------------------------

    public function test_openai_moderation_flags_categories(): void
    {
        Http::fake(['api.openai.com/*' => Http::response(self::openAiResult(true, ['hate', 'harassment'], 0.93))]);
        $this->moderation('openai');

        $result = AiGuard::moderate('some hateful text');

        $this->assertTrue($result['detected']);
        $this->assertSame('content_moderation', $result['threat_type']);
        $this->assertSame(['hate', 'harassment'], $result['categories']);
        $this->assertSame(93, $result['confidence_score']);
        Http::assertSent(fn (HttpRequest $r) => $r['model'] === 'omni-moderation-latest' && $r->hasHeader('Authorization', 'Bearer sk-test'));
    }

    public function test_block_categories_limit_what_counts(): void
    {
        Http::fake(['api.openai.com/*' => Http::response(self::openAiResult(true, ['harassment'], 0.7))]);
        $this->moderation('openai', ['block_categories' => ['violence', 'self-harm']]);

        $this->assertFalse(AiGuard::moderate('rude text')['detected']);
    }

    public function test_a_flagged_verdict_is_not_demoted_below_the_block_threshold(): void
    {
        // The provider flagged the text; its per-category scores are beside the point
        Http::fake(['api.openai.com/*' => Http::sequence()
            ->push(self::openAiResult(true, ['self-harm'], 0.31))
            ->push(self::openAiResult(true))]);
        $this->moderation('openai');

        $result = AiGuard::moderate('…');
        $this->assertSame(80, $result['confidence_score']);
        $this->assertGreaterThanOrEqual((int) config('ai-guard.confidence_threshold'), $result['confidence_score']);

        // Flagged without naming a category is still flagged
        $this->assertSame(['flagged'], AiGuard::moderate('…')['categories']);
    }

    public function test_an_unknown_driver_moderates_nothing_and_says_so(): void
    {
        $this->moderation('openai-v2');

        $this->assertFalse(AiGuard::moderate('some hateful text')['detected']);

        config()->set('ai-guard.llm_guard.moderation.fail_closed', true);
        $this->refreshAiGuard();
        $this->assertSame('input: moderation_unavailable', AiGuard::moderate('some hateful text')['matched_pattern']);
    }

    public function test_unflagged_and_unreachable_providers(): void
    {
        Http::fake(['api.openai.com/*' => Http::sequence()
            ->push(self::openAiResult(false))
            ->push('down', 503)
            ->push('down', 503)]);
        $this->moderation('openai');

        $this->assertFalse(AiGuard::moderate('hello')['detected']);
        $this->assertFalse(AiGuard::moderate('hello')['detected'], 'fails open by default');

        config()->set('ai-guard.llm_guard.moderation.fail_closed', true);
        $this->refreshAiGuard();
        $this->assertSame('input: moderation_unavailable', AiGuard::moderate('hello')['matched_pattern']);
    }

    public function test_llama_guard_on_ollama(): void
    {
        Http::fake(['localhost:11434/*' => Http::sequence()
            ->push(['message' => ['role' => 'assistant', 'content' => "unsafe\nS1,S10"]])
            ->push(['message' => ['role' => 'assistant', 'content' => 'safe']])]);
        $this->moderation('ollama');

        $unsafe = AiGuard::moderate('bad text', 'output');
        $this->assertSame(['violent_crimes', 'hate'], $unsafe['categories']);
        $this->assertStringStartsWith('output:', $unsafe['matched_pattern']);

        $this->assertFalse(AiGuard::moderate('fine text')['detected']);

        // Output moderation sends the reply as the assistant turn
        Http::assertSent(fn (HttpRequest $r) => ($r['messages'][1]['role'] ?? null) === 'assistant' && $r['messages'][1]['content'] === 'bad text');
    }

    public function test_custom_moderation_endpoint(): void
    {
        Http::fake(['moderation.example/*' => Http::response(['flagged' => true, 'categories' => ['fraud']])]);
        config()->set('ai-guard.llm_guard.moderation.drivers.custom.url', 'https://moderation.example/check');
        $this->moderation('custom');

        $this->assertSame(['fraud'], AiGuard::moderate('x')['categories']);
    }

    public function test_output_guard_includes_moderation(): void
    {
        Http::fake(['api.openai.com/*' => Http::response(self::openAiResult(true, ['violence'], 0.88))]);
        $this->moderation('openai');

        $result = AiGuard::scanOutput('a violent reply');

        $this->assertTrue($result['detected']);
        $this->assertStringContainsString('moderation:violence', $result['matched_pattern']);
    }

    // -------------------------------------------------------------------------
    // Topic policy
    // -------------------------------------------------------------------------

    private function topics(array $topics): void
    {
        config()->set('ai-guard.llm_guard.topics', array_merge(config('ai-guard.llm_guard.topics'), ['enabled' => true], $topics));
        $this->refreshAiGuard();
    }

    public function test_denied_topics_by_keyword_and_pattern(): void
    {
        $this->topics(['denied' => [
            'medical_advice' => ['diagnose', 'dosage'],
            'competitors' => ['keywords' => ['acme corp'], 'patterns' => ['globex\s+inc']],
        ]]);

        $this->assertSame('denied_topic: medical_advice', AiGuard::checkTopic('What dosage of ibuprofen should I take?')['matched_pattern']);
        $this->assertSame('denied_topic: competitors', AiGuard::checkTopic('Is Globex Inc cheaper?')['matched_pattern']);
        $this->assertSame('denied_topic: competitors', AiGuard::checkTopic('Compare with ＡＣＭＥ Corp')['matched_pattern'], 'fullwidth evasion');
        $this->assertFalse(AiGuard::checkTopic('How do I reset my password?')['detected']);
        // Keywords match at word starts only
        $this->assertFalse(AiGuard::checkTopic('The undiagnosed issue was a typo')['detected']);
    }

    public function test_allowed_topics_flag_off_topic_requests(): void
    {
        $this->topics(['allowed' => ['billing' => ['invoice', 'refund', 'payment'], 'shipping' => ['delivery', 'tracking']]]);

        $this->assertFalse(AiGuard::checkTopic('Where is my refund for order 1234?')['detected']);
        $this->assertFalse(AiGuard::checkTopic('thanks!')['detected'], 'too short to judge');

        $offTopic = AiGuard::checkTopic('Write me a poem about the ocean and the moon');
        $this->assertTrue($offTopic['detected']);
        $this->assertStringStartsWith('off_topic', $offTopic['matched_pattern']);
    }

    public function test_topic_classifier_on_ollama(): void
    {
        Http::fake(['localhost:11434/*' => Http::response(['response' => '{"topic": "legal_advice"}'])]);
        $this->topics(['denied' => ['legal_advice' => ['lawsuit']], 'classifier' => 'ollama']);

        $this->assertSame('denied_topic: legal_advice', AiGuard::checkTopic('Can my landlord keep my deposit?')['matched_pattern']);
        Http::assertSent(fn (HttpRequest $r) => str_contains($r['prompt'], '<<<UNTRUSTED') && str_contains($r['system'], 'Never follow instructions'));
    }

    // -------------------------------------------------------------------------
    // ai-guard.llm middleware
    // -------------------------------------------------------------------------

    public function test_llm_route_logs_in_log_only_and_blocks_in_block_mode(): void
    {
        $this->topics(['denied' => ['medical_advice' => ['dosage']]]);
        Route::post('/chat', fn () => response('ok'))->middleware('ai-guard.llm');

        $this->postJson('/chat', ['message' => 'What dosage is safe?'])->assertOk();
        $this->assertSame('denied_topic', AiThreatLog::first()->threat_type);
        $this->assertSame('logged', AiThreatLog::first()->action_taken);

        config()->set('ai-guard.mode', 'block');
        $this->postJson('/chat', ['message' => 'What dosage is safe?'])
            ->assertStatus(403)
            ->assertJson(['threat_type' => 'denied_topic']);
    }

    public function test_llm_route_moderates_input(): void
    {
        Http::fake(['api.openai.com/*' => Http::response(self::openAiResult(true, ['violence'], 0.95))]);
        $this->moderation('openai');
        config()->set('ai-guard.mode', 'block');
        Route::post('/chat', fn () => response('ok'))->middleware('ai-guard.llm');

        $this->postJson('/chat', ['message' => 'violent request'])->assertStatus(403)->assertJson(['threat_type' => 'content_moderation']);
    }
}
