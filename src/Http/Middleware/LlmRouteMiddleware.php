<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Events\ThreatDetected;
use JayAnta\AiGuard\Services\ConversationGuard;
use JayAnta\AiGuard\Services\ModerationGuard;
use JayAnta\AiGuard\Services\TokenBudget;
use JayAnta\AiGuard\Services\TopicGuard;
use JayAnta\AiGuard\Support\ThreatLogger;

/**
 * Guards the routes that call a model: usage budgets, topic policy, harm moderation,
 * and multi-turn escalation.
 *
 *   Route::post('/chat', ChatController::class)->middleware('ai-guard.llm');        // 'default' tier
 *   Route::post('/assistant', ...)->middleware('ai-guard.llm:premium');              // named tier
 *
 * Budgets are quotas and are enforced in every mode. Topic, moderation, and conversation
 * checks are detections: they block only in 'block' mode above the confidence threshold.
 */
class LlmRouteMiddleware
{
    // How much of an unparsed request body is read for budgeting and scanning
    private const MAX_RAW_BODY = 262144;

    public function __construct(
        private TokenBudget $budget,
        private ThreatLogger $logger,
        private TopicGuard $topics,
        private ModerationGuard $moderation,
        private ConversationGuard $conversations,
    ) {}

    public function handle(Request $request, Closure $next, string $tier = 'default'): mixed
    {
        if (! (config('ai-guard.enabled') ?? true)) {
            return $next($request);
        }

        $texts = $this->inputTexts($request);

        if ($this->budget->isEnabled()) {
            $subject = $this->budget->subject($request->user(), $request->ip());
            $estimate = $this->budget->estimateTokens(implode("\n", $texts));
            $decision = $this->budget->consume($subject, $estimate, $tier);

            if (! $decision->allowed) {
                $this->report($request, [
                    'detected' => true,
                    'threat_type' => 'llm_budget_exceeded',
                    'threat_source' => $subject,
                    'confidence_score' => 100,
                    'matched_pattern' => "{$tier}: {$decision->limit} ({$decision->used} of {$decision->max})",
                ], 'blocked');

                $response = response()->json([
                    'error' => $decision->httpStatus() === 413 ? 'Payload too large' : 'Too many requests',
                    'message' => $decision->message(),
                    'limit' => $decision->limit,
                    'retry_after' => $decision->retryAfter,
                ], $decision->httpStatus());

                if ($decision->retryAfter > 0) {
                    $response->headers->set('Retry-After', (string) $decision->retryAfter);
                }

                return $response;
            }
        }

        if ($texts !== []) {
            $joined = implode("\n", $texts);
            $checks = [
                fn () => $this->topics->check($joined),
                fn () => $this->moderation->moderate($joined, 'input'),
                fn () => $this->observeConversation($request, $joined),
            ];

            foreach ($checks as $check) {
                $result = $check();
                if (! $result['detected']) {
                    continue;
                }

                $action = $this->action($result);
                $this->report($request, $result, $action);

                if ($action === 'blocked') {
                    return response()->json([
                        'error' => 'Access denied',
                        'message' => 'Request blocked by AI Guard',
                        'threat_type' => $result['threat_type'],
                    ], 403);
                }
            }
        }

        return $next($request);
    }

    private function observeConversation(Request $request, string $text): array
    {
        $conversationId = $request->header('X-Conversation-Id')
            ?? $request->input('conversation_id')
            ?? ($request->hasSession() ? $request->session()->getId() : null);

        return is_string($conversationId) && $conversationId !== ''
            ? $this->conversations->observe($conversationId, $text)
            : ['detected' => false];
    }

    private function action(array $result): string
    {
        $blocks = config('ai-guard.mode') === 'block'
            && $result['confidence_score'] >= (int) (config('ai-guard.confidence_threshold') ?? 70);

        return $blocks ? 'blocked' : 'logged';
    }

    /**
     * @return array<int, string>
     */
    private function inputTexts(Request $request): array
    {
        $inputs = $request->except(['_token', '_method', 'conversation_id']);

        if ($inputs === []) {
            // A body Laravel did not parse — any content type it does not model — still reaches
            // the model through the app, so it is still counted and checked here
            $raw = substr((string) $request->getContent(), 0, self::MAX_RAW_BODY);
            $decoded = json_decode($raw, true);
            $inputs = is_array($decoded) ? $decoded : array_filter([$raw]);
        }

        return $this->strings($inputs);
    }

    /**
     * Every string in the input, keys included: an instruction can be written as a key
     * ({"ignore previous instructions": 1}) and still be read back by the model.
     *
     * @return array<int, string>
     */
    private function strings(mixed $value, int $depth = 0): array
    {
        if ($depth > 12) {
            return [];
        }

        if (is_string($value)) {
            return $value === '' ? [] : [$value];
        }

        if (! is_array($value)) {
            return [];
        }

        $texts = [];

        foreach ($value as $key => $item) {
            if (is_string($key) && $key !== '') {
                $texts[] = $key;
            }

            array_push($texts, ...$this->strings($item, $depth + 1));
        }

        return $texts;
    }

    private function report(Request $request, array $result, string $action): void
    {
        $this->logger->log($request, $result, $action);

        try {
            ThreatDetected::dispatch($request, $result, $action);
        } catch (\Throwable $e) {
            Log::warning('AI Guard: ThreatDetected listener threw an exception.', ['error' => $e->getMessage()]);
        }
    }
}
