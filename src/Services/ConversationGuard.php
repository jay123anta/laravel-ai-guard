<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;

/**
 * Multi-turn attack detection. Crescendo-style jailbreaks escalate over several
 * harmless-looking messages; each message alone stays under the threshold, so the
 * risk is accumulated per conversation with exponential decay.
 */
class ConversationGuard
{
    private array $config;

    private PromptInjectionDetector $detector;

    public function __construct(array $config, ?PromptInjectionDetector $detector = null)
    {
        $this->config = $config;
        $this->detector = $detector ?? new PromptInjectionDetector($config);
    }

    public function isEnabled(): bool
    {
        return (bool) ($this->option('enabled') ?? true);
    }

    /**
     * Add a message to the conversation's running risk and report if it crossed the line.
     *
     * @param  string|null  $subject  Whose conversation this is; the authenticated user by default.
     *                                Pass it explicitly from queued work, where there is no request.
     */
    public function observe(string $conversationId, string $message, ?string $subject = null): array
    {
        if (! $this->isEnabled() || $conversationId === '') {
            return $this->emptyResult();
        }

        $score = $this->detector->analyzeText($message)['confidence_score'];
        $window = max(1, (int) ($this->option('window_minutes') ?? 60)) * 60;
        $decay = (float) ($this->option('decay') ?? 0.6);
        $now = now()->getTimestamp();
        $key = $this->key($conversationId, $subject);

        $state = Cache::get($key);
        if (! is_array($state) || $now - (int) ($state['updated'] ?? 0) > $window) {
            $state = ['risk' => 0.0, 'messages' => 0, 'elevated' => 0];
        }

        // Suspicious messages fade with time, so a long-running conversation is not condemned
        // by something said hours ago; risk fades per message, which is what escalation looks like
        $gap = max(0, $now - (int) ($state['updated'] ?? $now));
        $state['risk'] = round((float) $state['risk'] * $decay + $score, 2);
        $state['elevated'] = round((float) $state['elevated'] * $decay ** ($gap / $window), 2);
        $state['messages']++;
        if ($score >= (int) ($this->option('elevated_score') ?? 40)) {
            $state['elevated']++;
        }
        $state['updated'] = $now;

        Cache::put($key, $state, $window);

        $threshold = (float) ($this->option('threshold') ?? 120);
        $elevatedLimit = (int) ($this->option('elevated_messages') ?? 3);

        if ($state['risk'] < $threshold && $state['elevated'] < $elevatedLimit) {
            return $this->emptyResult() + ['risk' => $state['risk'], 'messages' => $state['messages']];
        }

        return [
            'detected' => true,
            'threat_type' => 'multi_turn_attack',
            'threat_source' => 'conversation',
            'confidence_score' => (int) min(95, max(60, round($state['risk'] / $threshold * 80))),
            'matched_pattern' => sprintf('risk %.0f over %d messages (%d suspicious)', $state['risk'], $state['messages'], $state['elevated']),
            'risk' => $state['risk'],
            'messages' => $state['messages'],
        ];
    }

    public function reset(string $conversationId, ?string $subject = null): void
    {
        Cache::forget($this->key($conversationId, $subject));
    }

    /**
     * Conversation ids usually come from the client, so the accumulated risk is stored under
     * the authenticated subject as well: naming someone else's conversation reaches nothing.
     */
    private function key(string $conversationId, ?string $subject = null): string
    {
        $subject ??= $this->currentSubject();

        return 'ai-guard:conversation:'.sha1($subject.'|'.$conversationId);
    }

    private function currentSubject(): string
    {
        try {
            $user = auth()->user();
        } catch (\Throwable) {
            $user = null;
        }

        if ($user instanceof Authenticatable) {
            return get_class($user).':'.$user->getAuthIdentifier();
        }

        // Guests are separated too: with one namespace for everyone, a public chat widget whose
        // client picks the conversation id lets one visitor inherit — or inflate — another's risk
        if (app()->bound('request')) {
            $request = request();

            return $request->hasSession() && $request->session()->isStarted()
                ? 'session:'.$request->session()->getId()
                : 'ip:'.$request->ip();
        }

        return '';
    }

    private function emptyResult(): array
    {
        return [
            'detected' => false,
            'threat_type' => null,
            'threat_source' => null,
            'confidence_score' => 0,
            'matched_pattern' => null,
        ];
    }

    private function option(string $key): mixed
    {
        return $this->config['llm_guard']['conversations'][$key] ?? null;
    }
}
