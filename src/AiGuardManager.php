<?php

namespace JayAnta\AiGuard;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\HtmlString;
use JayAnta\AiGuard\Events\ThreatDetected;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AiDetector;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Services\BotVerifier;
use JayAnta\AiGuard\Services\ConversationGuard;
use JayAnta\AiGuard\Services\LlmOutputGuard;
use JayAnta\AiGuard\Services\McpGuard;
use JayAnta\AiGuard\Services\ModerationGuard;
use JayAnta\AiGuard\Services\PromptInjectionDetector;
use JayAnta\AiGuard\Services\Redactor;
use JayAnta\AiGuard\Services\SafeRenderer;
use JayAnta\AiGuard\Services\Spotlighter;
use JayAnta\AiGuard\Services\SqlGuard;
use JayAnta\AiGuard\Services\TaintTracker;
use JayAnta\AiGuard\Services\TokenBudget;
use JayAnta\AiGuard\Services\ToolCallScanner;
use JayAnta\AiGuard\Services\ToolFirewall;
use JayAnta\AiGuard\Services\TopicGuard;
use JayAnta\AiGuard\Support\BudgetDecision;
use JayAnta\AiGuard\Support\Redaction;
use JayAnta\AiGuard\Support\Spotlight;
use JayAnta\AiGuard\Support\ThreatLogger;
use JayAnta\AiGuard\Support\ToolDecision;

class AiGuardManager
{
    // Referenced by name: the laravel/ai integration only loads when laravel/ai is installed
    private const GUARDED_TOOL = 'JayAnta\AiGuard\Integrations\LaravelAi\GuardedTool';

    private array $config;

    private AiDetector $aiDetector;

    private PromptInjectionDetector $promptDetector;

    public function __construct()
    {
        $this->config = config('ai-guard') ?? [];
        $this->aiDetector = new AiDetector($this->config);
        $this->promptDetector = new PromptInjectionDetector($this->config);
    }

    public function detect(Request $request): array
    {
        if (! $this->isEnabled() || $this->aiDetector->isWhitelisted($request)) {
            return [
                'detected' => false,
                'threat_type' => null,
                'threat_source' => null,
                'confidence_score' => 0,
                'matched_pattern' => null,
            ];
        }

        $aiResult = $this->aiDetector->detect($request);
        $injectionResult = $this->promptDetector->detect($request);

        if ($aiResult['detected'] && $injectionResult['detected']) {
            return $injectionResult['confidence_score'] >= $aiResult['confidence_score']
                ? $injectionResult
                : $aiResult;
        }

        if ($aiResult['detected']) {
            return $aiResult;
        }

        if ($injectionResult['detected']) {
            return $injectionResult;
        }

        return $aiResult;
    }

    public function detectText(string $text): array
    {
        if (! $this->isEnabled()) {
            return [
                'detected' => false,
                'threat_type' => null,
                'threat_source' => null,
                'confidence_score' => 0,
                'matched_pattern' => null,
                'payload_snippet' => null,
            ];
        }

        return $this->promptDetector->scanValue($text);
    }

    /**
     * Scan text an LLM is about to return: image/link exfiltration, canary and
     * verbatim system-prompt leaks, secrets, and instructions for downstream agents.
     * The result's 'sanitized' key holds a safe-to-render copy.
     *
     * @param  array{system_prompt?: string|null, canary?: string|null, allowed_domains?: array<int, string>, scan_pii?: bool, moderate?: bool}  $options
     */
    public function scanOutput(string $text, array $options = []): array
    {
        return app(LlmOutputGuard::class)->scanOutput($text, $options);
    }

    /**
     * Scan an agent tool definition (tool poisoning), its arguments, or its result.
     *
     * @param  array<mixed>|string  $payload
     */
    public function scanToolCall(array|string $payload, string $kind = 'result'): array
    {
        return app(ToolCallScanner::class)->scan($payload, $kind);
    }

    public function canary(): string
    {
        return app(LlmOutputGuard::class)->canary();
    }

    /**
     * @return array{prompt: string, canary: string}
     */
    public function withCanary(string $systemPrompt): array
    {
        return app(LlmOutputGuard::class)->withCanary($systemPrompt);
    }

    public function isCanary(string $token): bool
    {
        return app(LlmOutputGuard::class)->isCanary($token);
    }

    /**
     * Record a detection result (from scanOutput, scanToolCall, detectText, ...) in
     * ai_threat_logs and dispatch ThreatDetected. Undetected results are ignored.
     */
    public function log(array $result, ?Request $request = null, string $actionTaken = 'logged'): ?AiThreatLog
    {
        if (! ($result['detected'] ?? false)) {
            return null;
        }

        $request ??= request();
        $log = app(ThreatLogger::class)->log($request, $result, $actionTaken);

        try {
            ThreatDetected::dispatch($request, $result, $actionTaken);
        } catch (\Throwable $e) {
            Log::warning('AI Guard: ThreatDetected listener threw an exception.', ['error' => $e->getMessage()]);
        }

        return $log;
    }

    /**
     * Mask personal data and secrets before sending text to a model; restore() the safe ones in the reply.
     *
     * @param  array<int, string>|null  $types
     */
    public function redact(string $text, ?array $types = null): Redaction
    {
        return app(Redactor::class)->redact($text, $types);
    }

    /**
     * Mark untrusted content (web pages, documents, tool results) so the model treats it as data.
     * Add the returned instructions to your system prompt.
     */
    public function spotlight(string $text, ?string $mode = null, string $source = 'an untrusted source'): Spotlight
    {
        return app(Spotlighter::class)->spotlight($text, $mode, $source);
    }

    public function estimateTokens(string $text): int
    {
        return app(TokenBudget::class)->estimateTokens($text);
    }

    /**
     * Would a call with this many input tokens fit the caller's budget? The subject defaults to
     * the signed-in user, or the client IP.
     */
    public function checkBudget(int $inputTokens, string $tier = 'default', ?string $subject = null): BudgetDecision
    {
        return app(TokenBudget::class)->check($subject ?? $this->budgetSubject(), $inputTokens, $tier);
    }

    /**
     * Check the budget and reserve the estimate in one step — what to call before making the
     * request, so simultaneous calls cannot each pass the same check.
     */
    public function consumeBudget(int $inputTokens, string $tier = 'default', ?string $subject = null): BudgetDecision
    {
        return app(TokenBudget::class)->consume($subject ?? $this->budgetSubject(), $inputTokens, $tier);
    }

    /**
     * Record a completed call's usage (from the provider's usage data) against the caller's budget.
     *
     * @param  int|null  $reservedInputTokens  What was already counted for this call. Null (the
     *                                         default) settles the estimate the ai-guard.llm
     *                                         middleware reserved for this request, once.
     * @return array{tokens: int, cost: float}
     */
    public function recordUsage(int $inputTokens, int $outputTokens, ?string $model = null, string $tier = 'default', ?string $subject = null, ?int $reservedInputTokens = null): array
    {
        $subject ??= $this->budgetSubject();

        if ($reservedInputTokens === null) {
            $reservedInputTokens = $this->takeReservation($subject, $tier);
        }

        return app(TokenBudget::class)->record($subject, $inputTokens, $outputTokens, $model, $tier, $reservedInputTokens);
    }

    /**
     * The middleware's reservation for this request, if it was for the same subject and tier.
     * Taken once, so a second record in the same request is not discounted again.
     */
    private function takeReservation(string $subject, string $tier): int
    {
        if (! app()->bound('request')) {
            return 0;
        }

        $attributes = request()->attributes;
        $reservation = $attributes->get(TokenBudget::RESERVATION_ATTRIBUTE);

        if (! is_array($reservation) || ($reservation['subject'] ?? null) !== $subject || ($reservation['tier'] ?? null) !== $tier) {
            return 0;
        }

        $attributes->remove(TokenBudget::RESERVATION_ATTRIBUTE);

        return (int) ($reservation['tokens'] ?? 0);
    }

    /**
     * @return array<string, array{used: int|float, limit: int|float|null}>
     */
    public function budgetUsage(string $tier = 'default', ?string $subject = null): array
    {
        return app(TokenBudget::class)->usage($subject ?? $this->budgetSubject(), $tier);
    }

    /**
     * Harm-category moderation through the configured provider (OpenAI, Llama Guard on Ollama, custom).
     */
    public function moderate(string $text, string $direction = 'input'): array
    {
        return app(ModerationGuard::class)->moderate($text, $direction);
    }

    /**
     * Check text against the denied / allowed topic policy.
     */
    public function checkTopic(string $text): array
    {
        return app(TopicGuard::class)->check($text);
    }

    /**
     * Add a message to a conversation's running risk (multi-turn escalation).
     */
    public function observeConversation(string $conversationId, string $message, ?string $subject = null): array
    {
        return app(ConversationGuard::class)->observe($conversationId, $message, $subject);
    }

    public function resetConversation(string $conversationId, ?string $subject = null): void
    {
        app(ConversationGuard::class)->reset($conversationId, $subject);
    }

    /**
     * Ask the tool firewall whether a tool call may run.
     */
    public function authorizeTool(string $tool, array $arguments = [], ?object $user = null, string $scope = TaintTracker::REQUEST_SCOPE, ?string $approvalToken = null): ToolDecision
    {
        return app(ToolFirewall::class)->evaluate($tool, $arguments, $user ?? auth()->user(), $scope, $approvalToken);
    }

    /**
     * Scan a tool result and return the text to give the model (spotlighted when untrusted).
     */
    public function inspectToolResult(string $tool, mixed $result, string $scope = TaintTracker::REQUEST_SCOPE): string
    {
        return app(ToolFirewall::class)->inspectResult($tool, $result, $scope);
    }

    /**
     * A signed, single-use token that approves exactly this tool call.
     */
    public function approveToolCall(string $tool, array $arguments = [], ?object $user = null, ?int $ttlSeconds = null): string
    {
        return app(ToolFirewall::class)->approvalToken($tool, $arguments, $user ?? auth()->user(), $ttlSeconds);
    }

    /**
     * Record that untrusted content (a web page, email, document) entered the conversation.
     */
    public function taint(string $source, string $scope = TaintTracker::REQUEST_SCOPE): void
    {
        app(TaintTracker::class)->taint($scope, $source);
    }

    /**
     * Keep only the MCP tools that are allowed, pinned and unchanged, and not poisoned.
     *
     * @param  iterable<mixed>  $tools
     * @return array<int, mixed>
     */
    public function guardMcpTools(string $server, iterable $tools): array
    {
        return app(McpGuard::class)->guard($server, $tools);
    }

    /**
     * Put laravel/ai tools (and MCP client tools) behind the tool firewall.
     *
     * @param  iterable<mixed>  $tools
     * @return array<int, mixed>
     */
    public function guardTools(iterable $tools, ?string $scope = null, ?object $user = null): array
    {
        if (! interface_exists('Laravel\Ai\Contracts\Tool')) {
            throw new \RuntimeException('AiGuard::guardTools() needs laravel/ai: composer require laravel/ai');
        }

        return call_user_func([self::GUARDED_TOOL, 'wrapAll'], $tools, $scope, $user);
    }

    /**
     * Render model output (Markdown or text) as sanitized HTML.
     */
    public function safeHtml(?string $text, array $options = []): HtmlString
    {
        return app(SafeRenderer::class)->render((string) $text, $options);
    }

    /**
     * Check model-written SQL: one read-only statement, allowed tables, no dangerous functions.
     */
    public function checkSql(string $sql, array $options = []): array
    {
        return app(SqlGuard::class)->check($sql, $options);
    }

    /**
     * Check and run model-written SQL with a row cap inside a rolled-back transaction.
     *
     * @return array<int, array<string, mixed>>
     */
    /**
     * @param  array<string, mixed>  $options  Same options as checkSql() — pass the allowed
     *                                         tables here too, or the query runs checked against
     *                                         the config alone
     */
    public function runReadOnlySql(string $sql, array $bindings = [], ?string $connection = null, array $options = []): array
    {
        return app(SqlGuard::class)->runReadOnly($sql, $bindings, $connection, $options);
    }

    /**
     * The Content-Security-Policy nonce for this request.
     */
    public function cspNonce(): string
    {
        $request = request();
        $nonce = $request->attributes->get('ai-guard.csp_nonce');

        if (! is_string($nonce)) {
            $nonce = base64_encode(random_bytes(18));
            $request->attributes->set('ai-guard.csp_nonce', $nonce);
        }

        return $nonce;
    }

    private function budgetSubject(): string
    {
        $request = request();

        return app(TokenBudget::class)->subject($request->user(), $request->ip());
    }

    /**
     * Is the bot behind this request who it claims to be?
     *
     * @return array{status: string|null, method: string|null, identity: string|null, token: string|null, category: string|null, detail: string|null}
     */
    public function verifyBot(Request $request): array
    {
        return app(BotVerifier::class)->verify($request);
    }

    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? true;
    }

    public function getMode(): string
    {
        return $this->config['mode'] ?? 'log_only';
    }

    public function getStats(int $hours = 24): array
    {
        return AiThreatLog::getThreatSummary($hours);
    }

    /**
     * @return Collection<int, AiThreatLog>
     */
    public function getTopThreats(int $limit = 10): Collection
    {
        return AiThreatLog::getTopSources($limit);
    }

    /**
     * @return \Illuminate\Database\Eloquent\Collection<int, AiThreatLog>
     */
    public function getRecentThreats(int $limit = 20): \Illuminate\Database\Eloquent\Collection
    {
        return AiThreatLog::recent(24)->notFalsePositive()
            ->orderByDesc('created_at')->limit($limit)->get();
    }

    public function getDetectorInfo(): array
    {
        return array_merge(
            $this->aiDetector->getDetectorInfo(),
            [
                'prompt_patterns' => $this->promptDetector->getPatternCount(),
                'honeypot_enabled' => $this->config['honeypot']['enabled'] ?? false,
                'response_scanning_enabled' => $this->config['response_scanning']['enabled'] ?? false,
                'robots_txt_enabled' => $this->config['robots_txt']['enabled'] ?? false,
                'fingerprinting_enabled' => $this->config['fingerprinting']['enabled'] ?? false,
                'ml_enabled' => $this->config['ml_detection']['enabled'] ?? false,
                'ml_driver' => $this->config['ml_detection']['driver'] ?? 'none',
            ]
        );
    }

    public function getFeatureStatus(): array
    {
        return [
            'enabled' => $this->isEnabled(),
            'mode' => $this->getMode(),
            'bot_signatures' => [
                'enabled' => $this->config['bot_signatures']['enabled'] ?? true,
                'total_bots' => BotSignatures::getTotalCount(),
                'categories' => BotSignatures::getCategoryCount(),
            ],
            'ai_crawlers' => $this->config['ai_crawlers']['enabled'] ?? false,
            'prompt_injection' => $this->config['prompt_injection']['enabled'] ?? false,
            'data_harvesters' => $this->config['data_harvesters']['enabled'] ?? false,
            'honeypot' => $this->config['honeypot']['enabled'] ?? false,
            'response_scanning' => $this->config['response_scanning']['enabled'] ?? false,
            'robots_txt' => $this->config['robots_txt']['enabled'] ?? false,
            'fingerprinting' => $this->config['fingerprinting']['enabled'] ?? false,
            'ml_detection' => [
                'enabled' => $this->config['ml_detection']['enabled'] ?? false,
                'driver' => $this->config['ml_detection']['driver'] ?? 'none',
            ],
        ];
    }
}
