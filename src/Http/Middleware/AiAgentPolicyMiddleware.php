<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Services\BotVerifier;
use JayAnta\AiGuard\Support\ReportsThreats;

/**
 * Who may use a page on a person's behalf: AI agents (ChatGPT-User, Perplexity-User,
 * Operator, signed Web Bot Auth agents, ...) act for a user and often ignore robots.txt.
 *
 *   ->middleware('ai-guard.agents')           // verified agents only (the default)
 *   ->middleware('ai-guard.agents:deny')      // no AI agents
 *   ->middleware('ai-guard.agents:allow')     // any AI agent
 *
 * "Verified" means a valid Web Bot Auth signature or the operator's published IP ranges
 * (bot_verification must be enabled). This is an access rule, enforced in every mode.
 * Crawlers that are not agents (training, search) are left to the main middleware.
 */
class AiAgentPolicyMiddleware
{
    use ReportsThreats;

    public function __construct(private BotVerifier $verifier) {}

    public function handle(Request $request, Closure $next, string $policy = 'verified'): mixed
    {
        if (! (config('ai-guard.enabled') ?? true) || $policy === 'allow') {
            return $next($request);
        }

        $agent = $this->agent($request);
        if ($agent === null || ($policy === 'verified' && $agent['status'] === BotVerifier::VERIFIED)) {
            return $next($request);
        }

        $this->reportThreat([
            'detected' => true,
            'threat_type' => 'ai_agent_denied',
            'threat_source' => mb_substr($agent['name'], 0, 100),
            'confidence_score' => 100,
            'matched_pattern' => mb_substr("{$policy}: {$agent['name']} ({$agent['status']})", 0, 255),
            'bot_category' => 'ai_agents',
            'bot_verification' => $agent['status'] === BotVerifier::UNVERIFIED ? null : $agent['status'],
        ], 'blocked', $request);

        $message = $policy === 'deny'
            ? 'AI agents may not use this page.'
            : 'Only verified AI agents may use this page.';

        return $request->expectsJson()
            ? response()->json(['error' => 'Access denied', 'message' => $message], 403)
            : response($message, 403, ['Content-Type' => 'text/plain; charset=UTF-8']);
    }

    /**
     * @return array{name: string, status: string}|null
     */
    private function agent(Request $request): ?array
    {
        $verification = $this->verifier->isEnabled() ? $this->verifier->verify($request) : null;

        // A signed agent is an agent whatever user-agent it browses with
        if ($verification !== null && $verification['method'] === 'web_bot_auth' && $verification['status'] !== null) {
            return ['name' => (string) ($verification['identity'] ?? 'signed agent'), 'status' => $verification['status']];
        }

        foreach (BotSignatures::findAllBots((string) $request->userAgent()) as $match) {
            if ($match['category'] !== 'ai_agents') {
                continue;
            }

            $status = $verification !== null && $verification['token'] !== null && $verification['status'] !== null
                ? $verification['status']
                : BotVerifier::UNVERIFIED;

            return ['name' => $match['matched_bot'], 'status' => $status];
        }

        return null;
    }
}
