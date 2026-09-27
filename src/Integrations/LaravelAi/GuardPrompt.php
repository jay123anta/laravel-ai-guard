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
use Laravel\Ai\Gateway\StepResponse;
use Laravel\Ai\Messages\UserMessage;
use Laravel\Ai\PendingStep;
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

    /**
     * Per-run state for laravel/ai 1.x, keyed by invocation id: what step 0 found (the
     * reservation, the redaction) is needed again on every later step of the same run.
     *
     * @var array<string, array{redaction: Redaction|null, original: string|null, reserved: int}>
     */
    private array $runs = [];

    /**
     * laravel/ai 0.x calls agent middleware once per prompt with an AgentPrompt; 1.x calls it
     * once per generation step with a PendingStep. Both are supported.
     */
    public function handle(object $prompt, Closure $next): mixed
    {
        if (! (config('ai-guard.enabled') ?? true)) {
            return $next($prompt);
        }

        if ($prompt instanceof PendingStep) {
            return $this->handleStep($prompt, $next);
        }

        return $this->handlePrompt($prompt, $next);
    }

    /**
     * laravel/ai 1.x: one call per step. The input is checked once, on step 0; a masked prompt is
     * masked again on every step, because the loop rebuilds each step from its own history; the
     * reply is scanned and restored on the step that answers (no tool calls); every step's usage
     * is recorded, since every step is a separate round trip the provider bills.
     */
    private function handleStep(PendingStep $step, Closure $next): mixed
    {
        $options = (array) (config('ai-guard.llm_guard.agents') ?? []);
        $tier = $this->tier ?? (string) ($options['tier'] ?? 'default');
        $budget = app(TokenBudget::class);
        $subject = $budget->subject(auth()->user(), app()->bound('request') ? request()->ip() : null);
        $instructions = (string) $step->instructions;
        $key = $step->invocationId ?? 'run';

        if ($step->isFirstStep()) {
            $state = ['redaction' => null, 'original' => null, 'reserved' => 0];

            // A fresh prompt ends with the user's message. A run resumed after tool approvals
            // ends with tool results instead: there is no new user text to check or mask.
            $messages = $step->messages;
            $last = $messages === [] ? null : $messages[array_key_last($messages)];
            if ($last instanceof UserMessage) {
                $text = (string) $last->content;
                $state['reserved'] = $this->checkBudget($budget, $subject, $text."\n".$instructions, $tier);
                $this->checkInput($text);

                if ($this->redact ?? (bool) ($options['redact'] ?? false)) {
                    $redaction = app(Redactor::class)->redact($text);

                    if ($redaction->hasRedactions()) {
                        $state['redaction'] = $redaction;
                        $state['original'] = $text;
                    }
                }
            }

            $this->runs[$key] = $state;
        }

        $state = $this->runs[$key] ?? ['redaction' => null, 'original' => null, 'reserved' => 0];

        if ($state['redaction'] !== null) {
            $step = $step->withMessages($this->maskMessages($step->messages, (string) $state['original'], $state['redaction']->text));
        }

        $reserved = $step->isFirstStep() ? $state['reserved'] : 0;
        $scan = $this->scanOutput ?? (bool) ($options['scan_output'] ?? true);
        $result = $next($step);

        return $result->then(function (StepResponse $response) use ($result, $step, $instructions, $state, $budget, $subject, $tier, $reserved, $scan, $key): void {
            $final = $response->toolCalls === [];
            $text = $response->text;

            if ($final) {
                $text = $this->guardReply($response, $text, $result->streamed(), $instructions, $state['redaction'], $scan);
                unset($this->runs[$key]);
            }

            if ($budget->isEnabled()) {
                $input = (int) $response->usage->inputTokens ?: $reserved;
                $output = (int) $response->usage->outputTokens ?: $budget->estimateTokens($text);

                $budget->record($subject, $input, $output, $step->model, $tier, $reserved);
            }
        });
    }

    /**
     * Scan the reply and put redacted values back. A streamed reply has already been sent,
     * so it is scanned and logged but not rewritten.
     */
    private function guardReply(object $response, string $text, bool $streamed, string $instructions, ?Redaction $redaction, bool $scan): string
    {
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
            $response->text = $text = $redaction->restore($text);
        }

        return $text;
    }

    /**
     * The step's messages with the user's prompt replaced by its masked form. New message
     * objects: the loop's own history is left as it was.
     *
     * @param  array<int, mixed>  $messages
     * @return array<int, mixed>
     */
    private function maskMessages(array $messages, string $original, string $masked): array
    {
        return array_map(
            fn ($message) => $message instanceof UserMessage && $message->content === $original
                ? new UserMessage($masked, $message->attachments)
                : $message,
            $messages
        );
    }

    /**
     * laravel/ai 0.x: one call per prompt.
     */
    private function handlePrompt(AgentPrompt $prompt, Closure $next): mixed
    {
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
