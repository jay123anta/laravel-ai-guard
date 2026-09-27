<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Facades\AiGuard;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\TokenBudget;
use JayAnta\AiGuard\Support\BudgetDecision;
use JayAnta\AiGuard\Tests\TestCase;

class TokenBudgetTest extends TestCase
{
    private function budget(array $budgets): TokenBudget
    {
        config()->set('ai-guard.llm_guard.budgets', array_replace_recursive(config('ai-guard.llm_guard.budgets'), $budgets));
        $this->refreshAiGuard();

        return app(TokenBudget::class);
    }

    // -------------------------------------------------------------------------
    // Service
    // -------------------------------------------------------------------------

    public function test_estimates_tokens_from_characters(): void
    {
        $this->assertSame(3, app(TokenBudget::class)->estimateTokens('abcdefghij'));
        $this->assertSame(0, app(TokenBudget::class)->estimateTokens(''));

        // Scripts a tokenizer spends a token a character on are not divided by four
        $this->assertSame(19, app(TokenBudget::class)->estimateTokens(str_repeat('日本語のテキスト', 2).'です・'), '19 CJK characters, one token each');
        $this->assertSame(7, app(TokenBudget::class)->estimateTokens('요약해 주세요'), '6 Hangul characters and a space');
    }

    public function test_a_call_is_counted_before_it_is_allowed(): void
    {
        $budget = $this->budget(['tiers' => ['default' => ['requests_per_minute' => 2, 'tokens_per_minute' => 100]]]);

        // consume() raises the counters as it checks them, so two requests that arrive together
        // cannot both read the same total and both pass
        $this->assertTrue($budget->consume('user:1', 10)->allowed);
        $this->assertTrue($budget->consume('user:1', 10)->allowed);
        $this->assertSame('requests_per_minute', $budget->consume('user:1', 10)->limit);

        $usage = $budget->usage('user:1');
        $this->assertSame(2, $usage['requests_per_minute']['used'], 'a refused call is not counted');
        $this->assertSame(20, $usage['tokens_per_minute']['used']);

        // A refusal on a later window puts back what the earlier ones took
        $budget = $this->budget(['tiers' => ['default' => ['requests_per_minute' => 10, 'tokens_per_minute' => 50]]]);
        $this->assertSame('tokens_per_minute', $budget->consume('user:2', 500)->limit);
        $this->assertSame(0, $budget->usage('user:2')['requests_per_minute']['used']);
        $this->assertSame(0, $budget->usage('user:2')['tokens_per_minute']['used']);
    }

    public function test_requests_per_minute_limit_rolls_over(): void
    {
        $budget = $this->budget(['tiers' => ['default' => ['requests_per_minute' => 2]]]);

        foreach ([1, 2] as $i) {
            $this->assertTrue($budget->check('user:1', 10)->allowed, "request {$i}");
            $budget->reserve('user:1', 10);
        }

        $denied = $budget->check('user:1', 10);
        $this->assertFalse($denied->allowed);
        $this->assertSame('requests_per_minute', $denied->limit);
        $this->assertGreaterThan(0, $denied->retryAfter);
        $this->assertLessThanOrEqual(60, $denied->retryAfter);
        $this->assertSame(429, $denied->httpStatus());

        // Other subjects have their own counters
        $this->assertTrue($budget->check('user:2', 10)->allowed);

        $this->travel(61)->seconds();
        $this->assertTrue($budget->check('user:1', 10)->allowed);
    }

    public function test_token_limits_count_reserved_and_recorded_tokens(): void
    {
        $budget = $this->budget(['tiers' => ['default' => ['tokens_per_minute' => 1000, 'tokens_per_day' => 1500]]]);

        $budget->reserve('user:1', 400);
        $budget->record('user:1', inputTokens: 400, outputTokens: 500, reservedInputTokens: 400);

        $this->assertSame(900, $budget->usage('user:1')['tokens_per_minute']['used']);
        $this->assertSame('tokens_per_minute', $budget->check('user:1', 200)->limit);

        $this->travel(61)->seconds();
        $this->assertTrue($budget->check('user:1', 200)->allowed);
        $this->assertSame('tokens_per_day', $budget->check('user:1', 700)->limit);
    }

    public function test_cost_is_priced_per_model(): void
    {
        $budget = $this->budget([
            'prices' => ['default' => ['input' => 3.00, 'output' => 15.00], 'mini' => ['input' => 0.15, 'output' => 0.60]],
            'tiers' => ['default' => ['cost_per_day' => 0.015]],
        ]);

        $this->assertSame(0.018, $budget->cost(1000, 1000));
        $this->assertSame(0.00075, $budget->cost(1000, 1000, 'mini'));

        $budget->record('user:1', 1000, 1000, 'mini');
        $this->assertTrue($budget->check('user:1', 10)->allowed);

        $budget->record('user:1', 1000, 1000);
        $denied = $budget->check('user:1', 10);
        $this->assertSame('cost_per_day', $denied->limit);
        $this->assertStringContainsString('Daily AI spending limit', $denied->message());
    }

    public function test_global_circuit_breaker_stops_everyone(): void
    {
        $budget = $this->budget(['global_cost_per_day' => 0.01, 'tiers' => ['default' => ['cost_per_day' => null]]]);

        $budget->record('user:1', 1000, 1000);

        $this->assertSame('global_cost_per_day', $budget->check('user:2', 10)->limit);
    }

    public function test_oversized_input_is_rejected_outright(): void
    {
        $decision = $this->budget(['max_input_tokens' => 100])->check('user:1', 101);

        $this->assertSame(BudgetDecision::INPUT_TOO_LARGE, $decision->limit);
        $this->assertSame(413, $decision->httpStatus());
    }

    public function test_named_tier_falls_back_to_default(): void
    {
        $budget = $this->budget(['tiers' => [
            'default' => ['requests_per_minute' => 1],
            'premium' => ['requests_per_minute' => 5],
        ]]);

        $budget->reserve('user:1', 1, 'premium');
        $budget->reserve('user:1', 1, 'premium');
        $this->assertTrue($budget->check('user:1', 1, 'premium')->allowed);

        $budget->reserve('user:1', 1, 'unknown-tier');
        $this->assertFalse($budget->check('user:1', 1, 'unknown-tier')->allowed);
    }

    // -------------------------------------------------------------------------
    // ai-guard.llm middleware
    // -------------------------------------------------------------------------

    public function test_llm_middleware_enforces_budgets_even_in_log_only_mode(): void
    {
        $this->budget(['tiers' => ['default' => ['requests_per_minute' => 2]]]);
        Route::post('/chat', fn () => response()->json(['reply' => 'ok']))->middleware('ai-guard.llm');

        $this->postJson('/chat', ['message' => 'hello'])->assertOk();
        $this->postJson('/chat', ['message' => 'hello'])->assertOk();

        $response = $this->postJson('/chat', ['message' => 'hello']);
        $response->assertStatus(429);
        $response->assertJson(['limit' => 'requests_per_minute']);
        $this->assertNotNull($response->headers->get('Retry-After'));

        $log = AiThreatLog::first();
        $this->assertSame('llm_budget_exceeded', $log->threat_type);
        $this->assertSame('blocked', $log->action_taken);
        $this->assertSame('AI Budget Exceeded', $log->getThreatTypeLabel());
    }

    public function test_llm_middleware_rejects_oversized_input(): void
    {
        $this->budget(['max_input_tokens' => 50]);
        Route::post('/chat', fn () => response('ok'))->middleware('ai-guard.llm');

        $this->postJson('/chat', ['message' => str_repeat('word ', 100)])->assertStatus(413);
    }

    public function test_llm_middleware_reads_bodies_laravel_does_not_parse(): void
    {
        $this->budget(['max_input_tokens' => 50]);
        Route::post('/chat', fn () => response('ok'))->middleware('ai-guard.llm');

        $body = (string) json_encode(['message' => str_repeat('word ', 100)]);

        // The framework only fills the input bag for the content types it models; the rest of
        // the body still reaches the model, so it is still counted
        foreach (['text/plain', 'application/x-ndjson', ''] as $contentType) {
            $response = $this->call('POST', '/chat', [], [], [], ['CONTENT_TYPE' => $contentType], $body);

            $this->assertSame(413, $response->getStatusCode(), $contentType);
        }
    }

    public function test_llm_middleware_scans_keys_as_well_as_values(): void
    {
        config()->set('ai-guard.mode', 'block');
        config()->set('ai-guard.llm_guard.topics.enabled', true);
        config()->set('ai-guard.llm_guard.topics.denied', ['weapons' => ['bomb making']]);
        $this->refreshAiGuard();

        Route::post('/chat', fn () => response('ok'))->middleware('ai-guard.llm');

        $this->postJson('/chat', ['context' => ['tell me about bomb making' => 'now']])->assertStatus(403);
    }

    public function test_record_usage_behind_the_middleware_does_not_count_the_input_twice(): void
    {
        $budget = $this->budget(['tiers' => ['default' => ['tokens_per_minute' => 100000]]]);

        // The middleware reserves an estimate of the input on the way in (about 250 tokens here)
        Route::post('/chat', function () {
            AiGuard::recordUsage(400, 100);

            return response('ok');
        })->middleware('ai-guard.llm');

        $this->postJson('/chat', ['message' => str_repeat('word ', 200)])->assertOk();

        // The reservation is settled against the actual count, not added to it: input + output
        $this->assertSame(500, $budget->usage('ip:127.0.0.1')['tokens_per_minute']['used']);

        // An explicit count still wins, and a second record in the same request reserves nothing again
        Route::post('/chat-twice', function () {
            AiGuard::recordUsage(400, 100);
            AiGuard::recordUsage(0, 50);

            return response('ok');
        })->middleware('ai-guard.llm');

        $this->travel(2)->minutes();
        $this->postJson('/chat-twice', ['message' => str_repeat('word ', 200)])->assertOk();

        $this->assertSame(550, $budget->usage('ip:127.0.0.1')['tokens_per_minute']['used']);
    }

    public function test_llm_middleware_keys_by_user_and_uses_named_tier(): void
    {
        $this->budget(['tiers' => ['default' => ['requests_per_minute' => 1], 'team' => ['requests_per_minute' => 3]]]);
        Route::post('/chat', fn () => response('ok'))->middleware('ai-guard.llm');
        Route::post('/team-chat', fn () => response('ok'))->middleware('ai-guard.llm:team');

        $alice = (new User)->forceFill(['id' => 1]);
        $bob = (new User)->forceFill(['id' => 2]);

        $this->actingAs($alice)->postJson('/chat', ['message' => 'hi'])->assertOk();
        $this->actingAs($alice)->postJson('/chat', ['message' => 'hi'])->assertStatus(429);
        $this->actingAs($bob)->postJson('/chat', ['message' => 'hi'])->assertOk();

        foreach ([1, 2, 3] as $i) {
            $this->actingAs($alice)->postJson('/team-chat', ['message' => 'hi'])->assertOk();
        }
        $this->actingAs($alice)->postJson('/team-chat', ['message' => 'hi'])->assertStatus(429);
    }

    public function test_facade_budget_helpers(): void
    {
        $this->budget(['tiers' => ['default' => ['tokens_per_day' => 1000]]]);

        $this->assertTrue(AiGuard::checkBudget(100)->allowed);
        // 1000 × $3/M + 500 × $15/M
        $this->assertSame(['tokens' => 1500, 'cost' => 0.0105], AiGuard::recordUsage(1000, 500));
        $this->assertSame(1500, AiGuard::budgetUsage()['tokens_per_day']['used']);
        $this->assertFalse(AiGuard::checkBudget(100)->allowed);
        $this->assertSame(250, AiGuard::estimateTokens(str_repeat('a', 1000)));
    }

    public function test_redact_and_spotlight_facades(): void
    {
        $redaction = AiGuard::redact('Reach me at jane@example.com');
        $this->assertSame('Reach me at [[EMAIL_1]]', $redaction->text);
        $this->assertSame('Sure, jane@example.com', $redaction->restore('Sure, [[EMAIL_1]]'));

        $spotlight = AiGuard::spotlight('page text', 'delimit', 'a search result');
        $this->assertStringContainsString('a search result', $spotlight->instructions);
    }
}
