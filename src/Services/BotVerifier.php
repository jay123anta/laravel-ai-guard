<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use JayAnta\AiGuard\Support\DnsResolver;

/**
 * Is the bot really who it says it is? Checks, in order: a Web Bot Auth
 * signature, the operator's published IP ranges, and forward-confirmed
 * reverse DNS. A claimed crawler that fails every check it could run is spoofed.
 */
class BotVerifier
{
    public const VERIFIED = 'verified';

    public const SPOOFED = 'spoofed';

    public const UNVERIFIED = 'unverified';

    // Re-check a verdict that could not be reached (e.g. range list offline) after 5 minutes
    private const RETRY_SECONDS = 300;

    private array $config;

    private DnsResolver $dns;

    private WebBotAuthVerifier $webBotAuth;

    private IpRangeRepository $ranges;

    public function __construct(array $config, ?DnsResolver $dns = null, ?WebBotAuthVerifier $webBotAuth = null, ?IpRangeRepository $ranges = null)
    {
        $this->config = $config;
        $this->dns = $dns ?? new DnsResolver;
        $this->webBotAuth = $webBotAuth ?? new WebBotAuthVerifier($config, $this->dns);
        $this->ranges = $ranges ?? new IpRangeRepository(
            (int) ($config['bot_verification']['timeout'] ?? 3),
            (int) ($config['bot_verification']['cache_minutes'] ?? 1440),
        );
    }

    public function isEnabled(): bool
    {
        return $this->config['bot_verification']['enabled'] ?? false;
    }

    /**
     * @return array{status: string|null, method: string|null, identity: string|null, token: string|null, category: string|null, detail: string|null}
     */
    public function verify(Request $request): array
    {
        if (! $this->isEnabled()) {
            return $this->result(null);
        }

        $methods = $this->config['bot_verification']['methods'] ?? ['web_bot_auth', 'ip_ranges', 'reverse_dns'];
        $signatureDetail = null;

        if (in_array('web_bot_auth', $methods, true)) {
            $signature = $this->webBotAuth->verify($request);
            $agentHost = $signature['agent'] !== null ? (string) parse_url($signature['agent'], PHP_URL_HOST) : null;
            $category = (string) ($this->config['bot_verification']['web_bot_auth']['category'] ?? 'ai_agents');

            if ($signature['status'] === WebBotAuthVerifier::VERIFIED) {
                return $this->result(self::VERIFIED, 'web_bot_auth', $agentHost, null, $category, 'keyid '.$signature['keyid']);
            }

            if ($signature['status'] === WebBotAuthVerifier::INVALID) {
                return $this->result(self::SPOOFED, 'web_bot_auth', $agentHost, null, $category, $signature['detail']);
            }

            if ($signature['status'] !== WebBotAuthVerifier::ABSENT) {
                $signatureDetail = 'web-bot-auth '.$signature['status'];
            }
        }

        $token = $this->claimedToken($request->userAgent() ?? '');
        if ($token === null) {
            return $this->result(null, detail: $signatureDetail);
        }

        $ip = (string) $request->ip();
        $cacheKey = 'ai-guard:bot-verify:'.sha1($token.'|'.$ip);
        $minutes = (int) ($this->config['bot_verification']['cache_minutes'] ?? 1440);

        $verdict = $minutes > 0 ? Cache::get($cacheKey) : null;
        if (! is_array($verdict)) {
            $verdict = $this->verifyClaim($token, $ip, $methods);

            if ($minutes > 0) {
                // A verdict that rests on DNS is only kept briefly: a resolver that was down for
                // a moment would otherwise leave a real crawler marked as an impostor all day.
                // Published ranges are deterministic, so those verdicts keep the full lifetime.
                $shortLived = $verdict['status'] === self::UNVERIFIED
                    || ($verdict['status'] === self::SPOOFED && $verdict['method'] === 'reverse_dns');

                Cache::put($cacheKey, $verdict, $shortLived ? self::RETRY_SECONDS : $minutes * 60);
            }
        }

        return $this->result($verdict['status'], $verdict['method'], $token, $token, $this->categoryOf($token), $verdict['detail']);
    }

    /**
     * Threat result for a request whose claimed identity failed verification.
     */
    public function spoofedResult(array $verification, array $userAgentResult): array
    {
        $claimed = $verification['token'] ?? $verification['identity'] ?? 'unknown';
        $confidence = max(
            (int) ($this->config['bot_verification']['spoofed_confidence'] ?? 90),
            ($userAgentResult['detected'] ?? false) ? (int) $userAgentResult['confidence_score'] : 0
        );

        return [
            'detected' => true,
            'threat_type' => 'spoofed_bot',
            'threat_source' => $claimed,
            'confidence_score' => min($confidence, 100),
            'matched_pattern' => 'spoofed '.$claimed.' ('.$verification['method'].': '.$verification['detail'].')',
            'bot_category' => $verification['category'],
            'bot_verification' => self::SPOOFED,
        ];
    }

    /**
     * Threat result for a signed agent that browses with an ordinary user-agent.
     */
    public function signedAgentResult(array $verification): array
    {
        $category = $verification['category'] ?? 'ai_agents';
        $overrides = BotSignatures::confidenceOverrides($this->config);

        return [
            'detected' => true,
            'threat_type' => 'ai_crawler',
            'threat_source' => $verification['identity'],
            'confidence_score' => $overrides[$category] ?? (BotSignatures::getCategories()[$category]['confidence'] ?? 60),
            'matched_pattern' => 'web-bot-auth: '.$verification['identity'],
            'bot_category' => $category,
            'bot_verification' => self::VERIFIED,
        ];
    }

    /**
     * @param  array<int, string>  $methods
     * @return array{status: string, method: string|null, detail: string|null}
     */
    private function verifyClaim(string $token, string $ip, array $methods): array
    {
        $rule = $this->ruleFor($token);
        $evaluated = false;
        $reasons = [];

        $ranges = $rule['ip_ranges'] ?? [];
        if (in_array('ip_ranges', $methods, true) && $ranges !== []) {
            $inRange = $this->ipInPublishedRanges($ip, $ranges);

            if ($inRange === true) {
                return ['status' => self::VERIFIED, 'method' => 'ip_ranges', 'detail' => null];
            }

            if ($inRange === false) {
                $evaluated = true;
                $reasons[] = 'IP not in published ranges';
            } else {
                $reasons[] = 'published ranges unavailable';
            }
        }

        $suffixes = $rule['reverse_dns'] ?? [];
        if (in_array('reverse_dns', $methods, true) && $suffixes !== []) {
            $confirms = $this->reverseDnsConfirms($ip, $suffixes);

            if ($confirms === true) {
                return ['status' => self::VERIFIED, 'method' => 'reverse_dns', 'detail' => null];
            }

            // null = the lookup could not be completed, which is not evidence of anything
            if ($confirms === false) {
                $evaluated = true;
                $reasons[] = 'reverse DNS does not confirm';
            } else {
                $reasons[] = 'reverse DNS unavailable';
            }
        }

        $method = $suffixes !== [] ? 'reverse_dns' : 'ip_ranges';

        return [
            'status' => $evaluated ? self::SPOOFED : self::UNVERIFIED,
            'method' => $method,
            'detail' => implode('; ', $reasons) ?: null,
        ];
    }

    /**
     * true = in range, false = not in range, null = no range list could be loaded.
     *
     * @param  array<int, string>  $urls
     */
    private function ipInPublishedRanges(string $ip, array $urls): ?bool
    {
        return $this->ranges->contains($ip, $urls);
    }

    /**
     * Forward-confirmed reverse DNS: PTR must end in an allowed suffix AND resolve back to the IP.
     *
     * true = confirmed, false = contradicted, null = the lookup could not be completed.
     *
     * @param  array<int, string>  $suffixes
     */
    private function reverseDnsConfirms(string $ip, array $suffixes): ?bool
    {
        $host = $this->dns->reverse($ip);
        if ($host === null) {
            return false;
        }

        $host = strtolower(rtrim($host, '.'));
        $suffixMatches = false;

        foreach ($suffixes as $suffix) {
            $suffix = strtolower(trim($suffix, '.'));
            if ($host === $suffix || str_ends_with($host, '.'.$suffix)) {
                $suffixMatches = true;
                break;
            }
        }

        if (! $suffixMatches) {
            return false;
        }

        $packed = @inet_pton($ip);
        $addresses = $this->dns->forward($host);

        foreach ($addresses as $resolved) {
            if ($packed !== false && @inet_pton($resolved) === $packed) {
                return true;
            }
        }

        // The PTR named an operator's own host but nothing resolved: that is a resolver that
        // could not answer, not a crawler caught impersonating one
        return $addresses === [] ? null : false;
    }

    private function claimedToken(string $userAgent): ?string
    {
        if ($userAgent === '') {
            return null;
        }

        foreach (array_keys($this->config['bot_verification']['crawlers'] ?? []) as $token) {
            if (preg_match('/(?<![a-z0-9])'.preg_quote((string) $token, '/').'(?![a-z])/i', $userAgent)) {
                return (string) $token;
            }
        }

        return null;
    }

    /**
     * @return array{ip_ranges?: array<int, string>, reverse_dns?: array<int, string>}
     */
    private function ruleFor(string $token): array
    {
        foreach ($this->config['bot_verification']['crawlers'] ?? [] as $name => $rule) {
            if (strcasecmp((string) $name, $token) === 0 && is_array($rule)) {
                return $rule;
            }
        }

        return [];
    }

    private function categoryOf(string $token): ?string
    {
        foreach (BotSignatures::getCategories() as $key => $category) {
            foreach ($category['bots'] as $bot) {
                if (strcasecmp($bot, $token) === 0) {
                    return $key;
                }
            }
        }

        return null;
    }

    /**
     * @return array{status: string|null, method: string|null, identity: string|null, token: string|null, category: string|null, detail: string|null}
     */
    private function result(?string $status, ?string $method = null, ?string $identity = null, ?string $token = null, ?string $category = null, ?string $detail = null): array
    {
        return [
            'status' => $status,
            'method' => $method,
            'identity' => $identity,
            'token' => $token,
            'category' => $category,
            'detail' => $detail,
        ];
    }
}
