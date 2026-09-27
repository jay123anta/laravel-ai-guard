<?php

namespace JayAnta\AiGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array detect(\Illuminate\Http\Request $request)
 * @method static array detectText(string $text)
 * @method static array verifyBot(\Illuminate\Http\Request $request)
 * @method static array scanOutput(string $text, array $options = [])
 * @method static array scanToolCall(array|string $payload, string $kind = 'result')
 * @method static string canary()
 * @method static array withCanary(string $systemPrompt)
 * @method static bool isCanary(string $token)
 * @method static \JayAnta\AiGuard\Models\AiThreatLog|null log(array $result, ?\Illuminate\Http\Request $request = null, string $actionTaken = 'logged')
 * @method static \JayAnta\AiGuard\Support\Redaction redact(string $text, ?array $types = null)
 * @method static \JayAnta\AiGuard\Support\Spotlight spotlight(string $text, ?string $mode = null, string $source = 'an untrusted source')
 * @method static int estimateTokens(string $text)
 * @method static \JayAnta\AiGuard\Support\BudgetDecision checkBudget(int $inputTokens, string $tier = 'default', ?string $subject = null)
 * @method static \JayAnta\AiGuard\Support\BudgetDecision consumeBudget(int $inputTokens, string $tier = 'default', ?string $subject = null)
 * @method static array recordUsage(int $inputTokens, int $outputTokens, ?string $model = null, string $tier = 'default', ?string $subject = null, ?int $reservedInputTokens = null)
 * @method static array budgetUsage(string $tier = 'default', ?string $subject = null)
 * @method static array moderate(string $text, string $direction = 'input')
 * @method static array checkTopic(string $text)
 * @method static array observeConversation(string $conversationId, string $message, string|null $subject = null)
 * @method static void resetConversation(string $conversationId, string|null $subject = null)
 * @method static \JayAnta\AiGuard\Support\ToolDecision authorizeTool(string $tool, array $arguments = [], ?object $user = null, string $scope = 'request', ?string $approvalToken = null)
 * @method static string inspectToolResult(string $tool, mixed $result, string $scope = 'request')
 * @method static string approveToolCall(string $tool, array $arguments = [], ?object $user = null, ?int $ttlSeconds = null)
 * @method static void taint(string $source, string $scope = 'request')
 * @method static array<int, mixed> guardMcpTools(string $server, iterable<mixed> $tools)
 * @method static array<int, mixed> guardTools(iterable<mixed> $tools, ?string $scope = null, ?object $user = null)
 * @method static \Illuminate\Support\HtmlString safeHtml(?string $text, array $options = [])
 * @method static array checkSql(string $sql, array $options = [])
 * @method static array<int, array<string, mixed>> runReadOnlySql(string $sql, array $bindings = [], ?string $connection = null, array $options = [])
 * @method static string cspNonce()
 * @method static bool isEnabled()
 * @method static string getMode()
 * @method static array getStats(int $hours = 24)
 * @method static \Illuminate\Support\Collection<int, \JayAnta\AiGuard\Models\AiThreatLog> getTopThreats(int $limit = 10)
 * @method static \Illuminate\Database\Eloquent\Collection<int, \JayAnta\AiGuard\Models\AiThreatLog> getRecentThreats(int $limit = 20)
 * @method static array getDetectorInfo()
 * @method static array getFeatureStatus()
 */
class AiGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'ai-guard';
    }
}
