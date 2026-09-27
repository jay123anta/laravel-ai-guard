<?php

namespace JayAnta\AiGuard\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Events\AgentVerified;
use JayAnta\AiGuard\Events\BotClassified;
use JayAnta\AiGuard\Events\BotVerdictEvent;
use JayAnta\AiGuard\Events\SpoofedBotDetected;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Services\BotVerifier;

/**
 * Who the client is, worked out once per request: the ai-guard.verdict/1 array, kept on the
 * request under "ai_guard.verdict" and announced with the contract events the first time.
 *
 * Identity, not policy: the category is the best signature match across every category,
 * whether or not disabled_categories switches it off, and whatever the blocking mode — so a
 * verified Googlebot reads as a search engine, not as nothing.
 *
 * @internal
 */
final class RequestVerdict
{
    public const ATTRIBUTE = 'ai_guard.verdict';

    /**
     * @return array{schema: string, bot: array{category: string|null, token: string|null, identity: string|null}, verification: array{status: string|null, method: string|null}, evaluated_at: string}
     */
    public static function for(Request $request): array
    {
        $memo = $request->attributes->get(self::ATTRIBUTE);
        if (is_array($memo)) {
            return $memo;
        }

        $verdict = self::evaluate($request);
        $request->attributes->set(self::ATTRIBUTE, $verdict);
        self::announce($verdict, $request);

        return $verdict;
    }

    /**
     * @return array{schema: string, bot: array{category: string|null, token: string|null, identity: string|null}, verification: array{status: string|null, method: string|null}, evaluated_at: string}
     */
    private static function evaluate(Request $request): array
    {
        $verification = app(BotVerifier::class)->verify($request);
        $match = (config('ai-guard.bot_signatures.enabled') ?? true)
            ? BotSignatures::findBot((string) $request->userAgent())
            : null;

        // A signature says who the client is whatever user-agent it browses with
        $signed = $verification['method'] === 'web_bot_auth' && $verification['status'] !== null;

        return [
            'schema' => BotVerdictEvent::SCHEMA,
            'bot' => [
                'category' => $signed ? $verification['category'] : ($match['category'] ?? null),
                'token' => $match['matched_bot'] ?? null,
                'identity' => $verification['identity'],
            ],
            'verification' => [
                'status' => $verification['status'],
                'method' => $verification['status'] !== null ? $verification['method'] : null,
            ],
            'evaluated_at' => now()->toIso8601String(),
        ];
    }

    /**
     * @param  array{schema: string, bot: array{category: string|null, token: string|null, identity: string|null}, verification: array{status: string|null, method: string|null}, evaluated_at: string}  $verdict
     */
    private static function announce(array $verdict, Request $request): void
    {
        if (! (config('ai-guard.interop.enabled') ?? true)) {
            return;
        }

        $status = $verdict['verification']['status'];

        // Not a bot and no identity claim: announcing it would be one event per page view
        if ($verdict['bot']['category'] === null && ! in_array($status, [BotVerifier::VERIFIED, BotVerifier::SPOOFED], true)) {
            return;
        }

        $events = [BotClassified::class];
        if ($status === BotVerifier::VERIFIED) {
            $events[] = AgentVerified::class;
        } elseif ($status === BotVerifier::SPOOFED) {
            $events[] = SpoofedBotDetected::class;
        }

        foreach ($events as $event) {
            try {
                Event::dispatch(new $event($verdict, $request));
            } catch (\Throwable $e) {
                // A listener's bug must never become the visitor's error
                Log::warning('AI Guard: a '.class_basename($event).' listener threw an exception.', [
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }
}
