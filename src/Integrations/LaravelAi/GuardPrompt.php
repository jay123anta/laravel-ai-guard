<?php

namespace JayAnta\AiGuard\Integrations\LaravelAi;

use Closure;
use JayAnta\AiGuard\Exceptions\AiGuardBlockedException;
use JayAnta\AiGuard\Services\ConversationGuard;
use JayAnta\AiGuard\Services\LlmOutputGuard;
use JayAnta\AiGuard\Services\ModerationGuard;
use JayAnta\AiGuard\Services\PromptInjectionDetector;
use JayAnta\AiGuard\Services\Redactor;
use JayAnta\AiGuard\Services\TokenBudget;
use JayAnta\AiGuard\Services\TopicGuard;
use JayAnta\AiGuard\Support\Redaction;
use JayAnta\AiGuard\Support\ReportsThreats;
use Laravel\Ai\Prompts\AgentPrompt;
use Laravel\Ai\Responses\StreamedAgentResponse;

/**
 * laravel/ai agent middleware:
 *
 *   public function middleware(): array
 *   {
 *       return [new GuardPrompt];                      // or new GuardPrompt(tier: 'premium', redact: true)
 *   }
 *
 * Before the call: usage budget, prompt injection, topic policy, moderation, and multi-turn
 * escalation — a blocked prompt throws AiGuardBlockedException and never reaches the provider.
 * Optionally masks personal data and secrets, restoring them in the reply.
 * After the call: scans the reply for exfiltration, leaks of the agent's instructions, and
 * secrets, and records actual token usage. Streamed replies are scanned and logged once the
 * stream ends (their text has already been sent, so they are not rewritten).
 */
class GuardPrompt
{
    use ReportsThreats;

    public function __construct(
        private ?string $tier = null,
        private ?bool $redact = null,
        private ?bool $scanOutput = null,
        private ?string $conversationId = null,
    ) {}

    public function handle(AgentPrompt $prompt, Closure $next): mixed
    {
        if (! (config('ai-guard.enabled') ?? true)) {
            return $next($prompt);
        }

        $options = (array) (config('ai-guard.llm_guard.agents') ?? []);
        $tier = $this->tier ?? (string) ($options['tier'] ?? 'default');
        $budget = app(TokenBudget::class);
        $subject = $budget->subject(auth()->user(), app()->bound('request') ? request()->ip() : null);
        $instructions = (string) $prompt->agent->instructions();
        $reserved = 0;
        $redaction = null;

        // A resumed run (tool approval decisions) carries no new user text, so there is nothing
        // new to check or redact. Its round trip is still metered in afterResponse(): the provider
        // bills the whole prompt again, and the budget counts what the provider reports.
        if (! $prompt->hasApprovalDecisions()) {
            $reserved = $this->checkBudget($budget, $subject, $prompt->prompt."\n".$instructions, $tier);
            $this->checkInput($prompt->prompt);

            if ($this->redact ?? (bool) ($options['redact'] ?? false)) {
                $redaction = app(Redactor::class)->redact($prompt->prompt);
                if ($redaction->hasRedactions()) {
                    $prompt = $prompt->revise($redaction->text);
                }
            }
        }

        $scan = $this->scanOutput ?? (bool) ($options['scan_output'] ?? true);

        return $next($prompt)->then(function ($response) use ($prompt, $instructions, $redaction, $budget, $subject, $tier, $reserved, $scan): void {
            $this->afterResponse($response, $prompt, $instructions, $redaction, $budget, $subject, $tier, $reserved, $scan);
        });
    }

    private function checkBudget(TokenBudget $budget, string $subject, string $text, string $tier): int
    {
        if (! $budget->isEnabled()) {
            return 0;
        }

        $estimate = $budget->estimateTokens($text);
        $decision = $budget->consume($subject, $estimate, $tier);

        if (! $decision->allowed) {
            $result = [
                'detected' => true,
                'threat_type' => 'llm_budget_exceeded',
                'threat_source' => mb_substr($subject, 0, 100),
                'confidence_score' => 100,
                'matched_pattern' => "{$tier}: {$decision->limit} ({$decision->used} of {$decision->max})",
            ];
            $this->reportThreat($result, 'blocked');

            throw AiGuardBlockedException::budget($decision, $result);
        }

        return $estimate;
    }

    private function checkInput(string $text): void
    {
        if (trim($text) === '') {
            return;
        }

        $conversationId = $this->conversationId
            ?? (app()->bound('request') ? request()->header('X-Conversation-Id') : null);

        $checks = [
            fn () => app(PromptInjectionDetector::class)->scanValue($text),
            fn () => app(TopicGuard::class)->check($text),
            fn () => app(ModerationGuard::class)->moderate($text, 'input'),
            fn () => is_string($conversationId) && $conversationId !== ''
                ? app(ConversationGuard::class)->observe($conversationId, $text)
                : ['detected' => false],
        ];

        foreach ($checks as $check) {
            $result = $check();
            if (! $result['detected']) {
                continue;
            }

            $blocks = $this->blocks($result);
            $this->reportThreat($result, $blocks ? 'blocked' : 'logged');

            if ($blocks) {
                throw AiGuardBlockedException::threat($result);
            }
        }
    }

    private function afterResponse(object $response, AgentPrompt $prompt, string $instructions, ?Redaction $redaction, TokenBudget $budget, string $subject, string $tier, int $reserved, bool $scan): void
    {
        $text = is_string($response->text ?? null) ? $response->text : '';
        $streamed = $response instanceof StreamedAgentResponse;

        if ($scan && $text !== '') {
            // Scanned before placeholders are restored, so the user's own data is not reported as a leak
            $result = app(LlmOutputGuard::class)->scanOutput($text, ['system_prompt' => $instructions]);

            if ($result['detected']) {
                $blocks = ! $streamed && $this->blocks($result);
                $this->reportThreat($result, $blocks ? 'blocked' : 'logged');

                if ($blocks) {
                    $response->text = $text = (string) $result['sanitized'];
                }
            }
        }

        if ($redaction !== null && $redaction->hasRedactions() && ! $streamed) {
            $response->text = $redaction->restore($text);
        }

        if ($budget->isEnabled()) {
            $usage = $response->usage ?? null;
            $input = (int) ($usage->promptTokens ?? 0) ?: $reserved;
            $output = (int) ($usage->completionTokens ?? 0) ?: $budget->estimateTokens($text);

            $budget->record($subject, $input, $output, $prompt->model, $tier, $reserved);
        }
    }

    private function blocks(array $result): bool
    {
        return config('ai-guard.mode') === 'block'
            && $result['confidence_score'] >= (int) (config('ai-guard.confidence_threshold') ?? 70);
    }
}
