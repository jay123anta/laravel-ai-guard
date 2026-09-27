<?php

namespace JayAnta\AiGuard\Integrations\LaravelAi;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use JayAnta\AiGuard\Services\TaintTracker;
use JayAnta\AiGuard\Services\ToolFirewall;
use JayAnta\AiGuard\Support\CanonicalJson;
use JayAnta\AiGuard\Support\ToolDecision;
use Laravel\Ai\Approvals\Approval;
use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\Approvable;
use Laravel\Ai\Contracts\Tool;
use Laravel\Ai\Providers\Tools\ToolSearch;
use Laravel\Ai\Tools\AgentTool;
use Laravel\Ai\Tools\McpServerTool;
use Laravel\Ai\Tools\McpTool;
use Laravel\Ai\Tools\Request;
use Laravel\Ai\Tools\ToolNameResolver;
use Stringable;

/**
 * Puts a laravel/ai tool behind the AI Guard tool firewall:
 *
 *   public function tools(): iterable
 *   {
 *       return AiGuard::guardTools([new SendEmail, new FetchPage], scope: $this->conversationId);
 *   }
 *
 * A call the firewall denies never runs — the model gets the reason as the tool result.
 * A call that needs a person's approval pauses the run through laravel/ai's approval flow.
 * Results are scanned for injection and, when untrusted, spotlighted and used to taint the scope.
 */
class GuardedTool implements Approvable, Tool
{
    /** @var array<string, ToolDecision> */
    private array $decisions = [];

    private Approval|false|null $approvalOverride = null;

    public function __construct(
        private Tool $tool,
        private string $scope = TaintTracker::REQUEST_SCOPE,
        private ?object $user = null,
    ) {}

    /**
     * Wrap every laravel/ai tool (and MCP client tool) in the list; anything else is returned unchanged.
     *
     * @param  iterable<mixed>  $tools
     * @return array<int, mixed>
     */
    public static function wrapAll(iterable $tools, ?string $scope = null, ?object $user = null): array
    {
        $wrapped = [];

        foreach ($tools as $tool) {
            $wrapped[] = self::wrap($tool, $scope ?? TaintTracker::REQUEST_SCOPE, $user);
        }

        return $wrapped;
    }

    /**
     * Mirrors laravel/ai's own tool resolution (Agent → Tool → ToolSearch → MCP client → MCP
     * server). laravel/ai turns sub-agents, searchable tools and MCP server tools into Tool objects
     * only after tools() has returned, so anything this method leaves unconverted would run with
     * no firewall, no result scan and no taint.
     */
    private static function wrap(mixed $tool, string $scope, ?object $user): mixed
    {
        if ($tool instanceof self) {
            return $tool;
        }

        if (interface_exists(Agent::class) && class_exists(AgentTool::class) && $tool instanceof Agent) {
            $tool = new AgentTool($tool);
        } elseif (! $tool instanceof Tool && class_exists(ToolSearch::class) && $tool instanceof ToolSearch) {
            return $tool->withTools(array_map(fn ($nested) => self::wrap($nested, $scope, $user), $tool->tools));
        } elseif (! $tool instanceof Tool && class_exists(McpTool::class) && McpTool::supports($tool)) {
            $tool = new McpTool($tool);
        } elseif (! $tool instanceof Tool && class_exists(McpServerTool::class) && McpServerTool::supports($tool)) {
            $tool = new McpServerTool($tool);
        }

        return $tool instanceof Tool ? new self($tool, $scope, $user) : $tool;
    }

    public function inner(): Tool
    {
        return $this->tool;
    }

    public function name(): string
    {
        return ToolNameResolver::resolve($this->tool);
    }

    public function description(): Stringable|string
    {
        return $this->tool->description();
    }

    public function schema(JsonSchema $schema): array
    {
        return $this->tool->schema($schema);
    }

    public function shouldRequestApproval(Request $request): ?Approval
    {
        $decision = $this->decide($request);

        if ($decision->requiresApproval()) {
            return Approval::required($decision->reason);
        }

        if ($this->approvalOverride !== null) {
            return $this->approvalOverride ?: null;
        }

        return $this->tool instanceof Approvable ? $this->tool->shouldRequestApproval($request) : null;
    }

    public function requireApproval(?string $reason = null): static
    {
        $this->approvalOverride = Approval::required($reason);

        return $this;
    }

    /**
     * Skip the wrapped tool's own approval rule. The firewall's approval requirements still apply.
     */
    public function withoutApproval(): static
    {
        $this->approvalOverride = false;

        return $this;
    }

    public function handle(Request $request): Stringable|string
    {
        // laravel/ai only runs a call that needed approval after a person approved it
        $decision = $this->decide($request);

        if ($decision->denied()) {
            return 'Tool call blocked by AI Guard: '.$decision->reason;
        }

        $result = $this->tool->handle($request);

        return app(ToolFirewall::class)->inspectResult($this->name(), (string) $result, $this->scope);
    }

    private function decide(Request $request): ToolDecision
    {
        // The arguments belong in the key: laravel/ai keeps the call id when a person edits
        // the arguments before approving, and the edited call must be decided on its own merits
        $key = ($request->toolCallId() ?? '').'|'.CanonicalJson::hash($request->all());

        return $this->decisions[$key] ??= app(ToolFirewall::class)->evaluate(
            $this->name(),
            $request->all(),
            $this->user ?? auth()->user(),
            $this->scope,
            null,
            $request->toolCallId(),
        );
    }
}
