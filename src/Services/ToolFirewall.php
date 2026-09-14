<?php

namespace JayAnta\AiGuard\Services;

use Closure;
use Illuminate\Support\Facades\Cache;
use JayAnta\AiGuard\Support\CanonicalJson;
use JayAnta\AiGuard\Support\JsonSchemaValidator;
use JayAnta\AiGuard\Support\ReportsThreats;
use JayAnta\AiGuard\Support\ToolDecision;
use JayAnta\AiGuard\Support\UrlHost;
use RuntimeException;

/**
 * Decides whether an agent may run a tool call — the control that matters most
 * once untrusted content is in play (OWASP LLM06 / ASI02, Meta's "Rule of Two").
 *
 * A tool policy may set:
 *   effect             read | write | egress   (default read)
 *   roles              user roles allowed to trigger it
 *   schema             JSON Schema for the arguments
 *   authorize          fn (array $arguments, ?object $user): bool  (code-defined policies only)
 *   requires_approval  always hold for a human
 *   untrusted_output   the result is untrusted content (web, email, files, ...)
 *   deny               switch the tool off
 */
class ToolFirewall
{
    use ReportsThreats;

    /** @var array<string, array> */
    private static array $definedPolicies = [];

    private static ?Closure $roleResolver = null;

    private array $config;

    private TaintTracker $taint;

    private ToolCallScanner $scanner;

    private Spotlighter $spotlighter;

    public function __construct(array $config, TaintTracker $taint, ToolCallScanner $scanner, Spotlighter $spotlighter)
    {
        $this->config = $config;
        $this->taint = $taint;
        $this->scanner = $scanner;
        $this->spotlighter = $spotlighter;
    }

    /**
     * Register a policy in code (e.g. in a service provider) — required for 'authorize' callbacks.
     */
    public static function define(string $tool, array $policy): void
    {
        self::$definedPolicies[$tool] = array_merge(self::$definedPolicies[$tool] ?? [], $policy);
    }

    public static function forgetDefinitions(): void
    {
        self::$definedPolicies = [];
        self::$roleResolver = null;
    }

    /**
     * How to read a user's roles, e.g. fn ($user) => $user->getRoleNames()->all().
     */
    public static function resolveRolesUsing(?Closure $resolver): void
    {
        self::$roleResolver = $resolver;
    }

    public function isEnabled(): bool
    {
        return (bool) ($this->option('enabled') ?? true);
    }

    public function policyFor(string $tool): ?array
    {
        $configured = $this->option('policies')[$tool] ?? null;
        $defined = self::$definedPolicies[$tool] ?? null;

        if ($configured === null && $defined === null) {
            return null;
        }

        return array_merge((array) $configured, (array) $defined);
    }

    /**
     * @param  string|null  $callId  The provider's tool-call ID: a call re-checked when a paused run resumes is logged once
     */
    public function evaluate(string $tool, array $arguments, ?object $user = null, string $scope = TaintTracker::REQUEST_SCOPE, ?string $approvalToken = null, ?string $callId = null): ToolDecision
    {
        if (! $this->isEnabled()) {
            return ToolDecision::allow($tool);
        }

        $decision = $this->decide($tool, $arguments, $user, $scope);

        if ($decision->requiresApproval() && $approvalToken !== null && $this->consumeApproval($approvalToken, $tool, $arguments, $user)) {
            $decision = ToolDecision::allow($tool);
        }

        $firstReport = $callId === null || Cache::add('ai-guard:tool-call:'.sha1($callId.'|'.$decision->status), true, 86400);

        if (! $decision->allowed() && $firstReport) {
            $this->reportThreat($decision->toThreat(), $decision->denied() ? 'blocked' : 'logged');
        }

        return $decision;
    }

    private function decide(string $tool, array $arguments, ?object $user, string $scope): ToolDecision
    {
        $policy = $this->policyFor($tool);

        if ($policy === null) {
            if (($this->option('default') ?? 'allow') === 'deny') {
                return ToolDecision::deny($tool, "{$tool} is not on the tool allow-list");
            }
            $policy = [];
        }

        if ($policy['deny'] ?? false) {
            return ToolDecision::deny($tool, "{$tool} is disabled");
        }

        $roles = (array) ($policy['roles'] ?? []);
        if ($roles !== [] && array_intersect($roles, $this->rolesOf($user)) === []) {
            return ToolDecision::deny($tool, "{$tool} requires one of these roles: ".implode(', ', $roles));
        }

        if (is_array($policy['schema'] ?? null)) {
            $errors = JsonSchemaValidator::validate($arguments, $policy['schema']);
            if ($errors !== []) {
                return ToolDecision::deny($tool, 'invalid arguments: '.implode('; ', array_slice($errors, 0, 3)));
            }
        }

        if (($policy['authorize'] ?? null) instanceof Closure && ! ($policy['authorize'])($arguments, $user)) {
            return ToolDecision::deny($tool, "not authorized to call {$tool} with these arguments");
        }

        $effect = (string) ($policy['effect'] ?? 'read');
        $blockedHost = $this->disallowedDestination($arguments, $effect);
        if ($blockedHost !== null) {
            return ToolDecision::deny($tool, "{$tool} would send data to {$blockedHost}, which is not an allowed domain");
        }

        $maxCalls = $this->option('max_calls');
        if (is_numeric($maxCalls) && $this->taint->countToolCall($scope) > (int) $maxCalls) {
            return ToolDecision::deny($tool, "more than {$maxCalls} tool calls in one conversation");
        }

        $restricted = (array) ($this->option('restricted_when_tainted') ?? ['write', 'egress']);
        if (in_array($effect, $restricted, true) && $this->taint->isTainted($scope)) {
            $why = "{$tool} can {$effect} after untrusted content entered the conversation (".implode(', ', array_slice($this->taint->sources($scope), 0, 3)).')';

            return ($this->option('tainted_action') ?? 'approve') === 'block'
                ? ToolDecision::deny($tool, $why)
                : ToolDecision::requireApproval($tool, $why);
        }

        if ($policy['requires_approval'] ?? false) {
            return ToolDecision::requireApproval($tool, "{$tool} always requires approval");
        }

        return ToolDecision::allow($tool);
    }

    /**
     * Scan a tool result, mark the conversation tainted when the result is untrusted,
     * and return the text to hand back to the model (spotlighted when untrusted).
     */
    public function inspectResult(string $tool, mixed $result, string $scope = TaintTracker::REQUEST_SCOPE): string
    {
        // A result that will not encode still has to be scanned, so it never becomes ''
        $text = is_string($result) ? $result : CanonicalJson::encode($result);

        if (! $this->isEnabled()) {
            return $text;
        }

        $policy = $this->policyFor($tool) ?? [];
        $untrusted = (bool) ($policy['untrusted_output'] ?? $this->option('taint_all_tool_results') ?? false);

        if ($this->option('scan_results') ?? true) {
            $scan = $this->scanner->scan($text, 'result');
            if ($scan['detected']) {
                $scan['threat_source'] = mb_substr('tool:'.$tool, 0, 100);
                $this->reportThreat($scan);
                $untrusted = true;
            }
        }

        if (! $untrusted) {
            return $text;
        }

        $this->taint->taint($scope, 'tool:'.$tool);

        if (! ($this->option('spotlight_results') ?? true)) {
            return $text;
        }

        $spotlight = $this->spotlighter->spotlight($text, 'delimit', "the {$tool} tool");

        return $spotlight->instructions."\n".$spotlight->text;
    }

    /**
     * A signed, single-use token a person can grant for exactly this call.
     */
    public function approvalToken(string $tool, array $arguments, ?object $user = null, ?int $ttlSeconds = null): string
    {
        $payload = [
            't' => $tool,
            'a' => $this->argumentsHash($arguments),
            'u' => $this->userKey($user),
            'e' => now()->getTimestamp() + ($ttlSeconds ?? (int) ($this->option('approval_ttl') ?? 600)),
            'n' => bin2hex(random_bytes(8)),
        ];

        $body = WebBotAuthVerifier::base64UrlEncode(CanonicalJson::encode($payload));

        return $body.'.'.WebBotAuthVerifier::base64UrlEncode(hash_hmac('sha256', $body, $this->secret(), true));
    }

    public function consumeApproval(string $token, string $tool, array $arguments, ?object $user = null): bool
    {
        [$body, $signature] = array_pad(explode('.', $token, 2), 2, '');
        $expected = WebBotAuthVerifier::base64UrlEncode(hash_hmac('sha256', $body, $this->secret(), true));

        if ($body === '' || ! hash_equals($expected, $signature)) {
            return false;
        }

        $payload = json_decode(WebBotAuthVerifier::base64UrlDecode($body), true);
        if (! is_array($payload)) {
            return false;
        }

        $valid = ($payload['t'] ?? null) === $tool
            && ($payload['a'] ?? null) === $this->argumentsHash($arguments)
            && ($payload['u'] ?? null) === $this->userKey($user)
            && (int) ($payload['e'] ?? 0) >= now()->getTimestamp();

        // Single use: the nonce can be spent once
        return $valid && Cache::add('ai-guard:tool-approval:'.($payload['n'] ?? ''), true, max(1, (int) $payload['e'] - now()->getTimestamp()));
    }

    /**
     * @return array<int, string>
     */
    private function rolesOf(?object $user): array
    {
        if ($user === null) {
            return [];
        }

        if (self::$roleResolver !== null) {
            return array_map('strval', (array) (self::$roleResolver)($user));
        }

        if (method_exists($user, 'getRoleNames')) {
            $names = $user->getRoleNames();

            return array_map('strval', is_object($names) && method_exists($names, 'all') ? $names->all() : (array) $names);
        }

        $role = $user->role ?? null;

        return is_string($role) ? [$role] : [];
    }

    private function disallowedDestination(array $arguments, string $effect): ?string
    {
        $allowed = array_map('strval', (array) ($this->option('egress_domains') ?? []));

        if ($allowed === [] || $effect !== 'egress') {
            return null;
        }

        // Every host reachable from the arguments: URLs and addresses in strings, keys, and nested values
        foreach (UrlHost::hostsIn($arguments) as $host) {
            if (! UrlHost::matches($host, $allowed)) {
                return $host === '' ? 'an address it could not parse' : $host;
            }
        }

        return null;
    }

    private function argumentsHash(array $arguments): string
    {
        return CanonicalJson::hash($arguments);
    }

    private function userKey(?object $user): ?string
    {
        return $user !== null && method_exists($user, 'getAuthIdentifier') ? (string) $user->getAuthIdentifier() : null;
    }

    /**
     * Approval tokens are only worth as much as the key that signs them, so there is no
     * built-in fallback: without an APP_KEY anyone could mint their own approval.
     */
    private function secret(): string
    {
        $key = (string) config('app.key');

        if (trim($key) === '') {
            throw new RuntimeException('AI Guard cannot sign tool approvals without an APP_KEY. Run "php artisan key:generate".');
        }

        return $key;
    }

    private function option(string $key): mixed
    {
        return $this->config['llm_guard']['tools'][$key] ?? null;
    }
}
