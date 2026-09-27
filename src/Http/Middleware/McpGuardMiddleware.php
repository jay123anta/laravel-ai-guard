<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use JayAnta\AiGuard\Services\TaintTracker;
use JayAnta\AiGuard\Services\ToolCallScanner;
use JayAnta\AiGuard\Services\ToolFirewall;
use JayAnta\AiGuard\Support\ReportsThreats;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Tool firewall for an MCP server served from this app (laravel/mcp or any JSON-RPC endpoint):
 *
 *   Mcp::web('/mcp', AppServer::class)->middleware(['auth:sanctum', 'ai-guard.mcp']);
 *
 * Checks every tools/call against the tool policies, scans arguments and results,
 * and answers blocked calls with a JSON-RPC error. A call that needs approval
 * proceeds when the client sends a valid X-AI-Guard-Approval token.
 */
class McpGuardMiddleware
{
    use ReportsThreats;

    public const BLOCKED_CODE = -32001;

    public const APPROVAL_CODE = -32002;

    public function __construct(
        private ToolFirewall $firewall,
        private ToolCallScanner $scanner,
        private TaintTracker $taint,
    ) {}

    public function handle(Request $request, Closure $next): mixed
    {
        if (! (config('ai-guard.enabled') ?? true)) {
            return $next($request);
        }

        // Read from the body, not the Content-Type: a server that parses JSON-RPC sent as
        // text/plain would otherwise run the call while this guard waved it through.
        // A batch is a list, which the request's input bag does not model either.
        $payload = json_decode((string) $request->getContent(), true);
        if (! is_array($payload)) {
            return $next($request);
        }

        $messages = array_is_list($payload) ? $payload : [$payload];
        $scope = $this->scope($request);
        $calls = 0;

        foreach ($messages as $message) {
            if (! is_array($message) || ($message['method'] ?? null) !== 'tools/call') {
                continue;
            }

            $calls++;
            $id = $message['id'] ?? null;
            $tool = (string) ($message['params']['name'] ?? '');
            $arguments = is_array($message['params']['arguments'] ?? null) ? $message['params']['arguments'] : [];

            $scan = $this->scanner->scan($arguments, 'arguments');
            if ($scan['detected']) {
                $scan['threat_source'] = mb_substr('mcp:'.$tool, 0, 100);
                $blocks = $this->blocks($scan);
                $this->reportThreat($scan, $blocks ? 'blocked' : 'logged', $request);

                if ($blocks) {
                    return $this->rpcError($id, self::BLOCKED_CODE, 'Blocked by AI Guard: suspicious tool arguments');
                }
            }

            $decision = $this->firewall->evaluate($tool, $arguments, $request->user(), $scope, $request->header('X-AI-Guard-Approval'));

            if ($decision->denied()) {
                return $this->rpcError($id, self::BLOCKED_CODE, 'Blocked by AI Guard: '.$decision->reason);
            }

            if ($decision->requiresApproval()) {
                return $this->rpcError($id, self::APPROVAL_CODE, 'Approval required: '.$decision->reason, ['approval_required' => true]);
            }

            // A tool whose policy says its output is untrusted taints the conversation as soon
            // as it is called: the result may come back over a stream this middleware cannot
            // read, and waiting to see it would leave the next write or egress call unguarded
            if ($this->marksUntrusted($tool)) {
                $this->taint->taint($scope, 'tool:'.$tool);
            }
        }

        $response = $next($request);

        if ($calls > 0 && $response instanceof Response) {
            $this->inspectResults($this->readableBody($response), $scope, $request);
        }

        return $response;
    }

    /**
     * Does this tool's policy say its results are untrusted content?
     */
    private function marksUntrusted(string $tool): bool
    {
        $policy = $this->firewall->policyFor($tool) ?? [];

        return (bool) ($policy['untrusted_output'] ?? config('ai-guard.llm_guard.tools.taint_all_tool_results') ?? false);
    }

    /**
     * The response body, if this middleware can see it at all. A streamed response (MCP's
     * Streamable HTTP transport) is written straight to the client, so there is nothing here to
     * scan — which is why an untrusted tool taints when it is called rather than when it answers.
     */
    private function readableBody(Response $response): string
    {
        if ($response instanceof StreamedResponse || $response instanceof BinaryFileResponse) {
            return '';
        }

        return (string) $response->getContent();
    }

    /**
     * The taint scope for this conversation. MCP-Session-Id comes from the client, so it is
     * always prefixed with the authenticated subject: one client cannot clear — or read —
     * another's taint state by guessing or reusing a session id.
     */
    private function scope(Request $request): string
    {
        $user = $request->user();
        $subject = $user instanceof Authenticatable
            ? get_class($user).':'.$user->getAuthIdentifier()
            : 'ip:'.$request->ip();

        return 'mcp:'.sha1($subject.'|'.($request->header('MCP-Session-Id') ?: ''));
    }

    private function inspectResults(string $body, string $scope, Request $request): void
    {
        if (trim($body) === '') {
            return;
        }

        $decoded = json_decode($body, true);

        // Server-sent events carry the same JSON-RPC messages. An event's data may span several
        // "data:" lines, which the spec joins with a newline; a blank line ends the event.
        if (! is_array($decoded)) {
            $decoded = [];
            $data = [];

            foreach (array_merge(preg_split('/\R/', $body) ?: [], ['']) as $line) {
                if (str_starts_with($line, 'data:')) {
                    $data[] = ltrim(substr($line, 5), ' ');

                    continue;
                }

                if (trim($line) === '' && $data !== []) {
                    $message = json_decode(implode("\n", $data), true);
                    $data = [];

                    if (is_array($message)) {
                        $decoded[] = $message;
                    }
                }
            }
        }

        if ($decoded === []) {
            return;
        }

        foreach (array_is_list($decoded) ? $decoded : [$decoded] as $message) {
            // The whole result, not only result.content: structuredContent (MCP 2025-06) and any
            // other field the client hands to the model can carry the same instructions
            $content = is_array($message) ? ($message['result'] ?? null) : null;
            if (! is_array($content)) {
                continue;
            }

            $scan = $this->scanner->scan($content, 'result');
            if ($scan['detected']) {
                $this->reportThreat($scan, 'logged', $request);
                $this->taint->taint($scope, 'mcp tool result');
            }
        }
    }

    private function blocks(array $result): bool
    {
        return config('ai-guard.mode') === 'block'
            && $result['confidence_score'] >= (int) (config('ai-guard.confidence_threshold') ?? 70);
    }

    private function rpcError(mixed $id, int $code, string $message, array $data = []): JsonResponse
    {
        $error = ['code' => $code, 'message' => $message];
        if ($data !== []) {
            $error['data'] = $data;
        }

        return response()->json(['jsonrpc' => '2.0', 'id' => $id, 'error' => $error]);
    }
}
