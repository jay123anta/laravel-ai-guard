<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Support\DnsResolver;

/**
 * Web Bot Auth: HTTP Message Signatures (RFC 9421) plus a Signature-Agent key
 * directory. Proves which operator sent a request — including AI agents that
 * browse with an ordinary Chrome user-agent — instead of trusting the UA string.
 */
class WebBotAuthVerifier
{
    public const ABSENT = 'absent';

    public const VERIFIED = 'verified';

    // A signature that does not verify: forged, tampered, or replayed
    public const INVALID = 'invalid';

    public const EXPIRED = 'expired';

    public const UNTRUSTED_AGENT = 'untrusted_agent';

    public const UNKNOWN_KEY = 'unknown_key';

    public const UNSUPPORTED = 'unsupported';

    // No Ed25519 implementation, or the key directory could not be fetched
    public const UNAVAILABLE = 'unavailable';

    private const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';

    private const ED25519_SIGNATURE_BYTES = 64;

    private const ED25519_KEY_BYTES = 32;

    private array $config;

    private DnsResolver $dns;

    public function __construct(array $config, ?DnsResolver $dns = null)
    {
        $this->config = $config;
        $this->dns = $dns ?? new DnsResolver;
    }

    /**
     * @return array{status: string, agent: string|null, keyid: string|null, detail: string|null}
     */
    public function verify(Request $request): array
    {
        $signatureInput = $request->headers->get('Signature-Input');
        $signatureHeader = $request->headers->get('Signature');

        if (! is_string($signatureInput) || $signatureInput === '' || ! is_string($signatureHeader) || $signatureHeader === '') {
            return $this->result(self::ABSENT);
        }

        // Prefer the member tagged for Web Bot Auth; otherwise the first parseable one
        $label = null;
        $parsed = null;
        foreach ($this->parseDictionary($signatureInput) as $name => $value) {
            $candidate = $this->parseInnerList($value);
            if ($candidate === null) {
                continue;
            }

            if ($label === null || ($candidate['params']['tag'] ?? null) === 'web-bot-auth') {
                $label = $name;
                $parsed = $candidate;
            }

            if (($candidate['params']['tag'] ?? null) === 'web-bot-auth') {
                break;
            }
        }

        $signatures = $this->parseDictionary($signatureHeader);

        if ($label === null || $parsed === null || ! isset($signatures[$label])) {
            return $this->result(self::UNSUPPORTED, detail: 'malformed Signature-Input');
        }

        $params = $parsed['params'];
        $agentHeader = trim((string) $request->headers->get('Signature-Agent', ''));
        $agent = $this->agentUrl($agentHeader, $label);

        if (isset($params['alg']) && strtolower((string) $params['alg']) !== 'ed25519') {
            return $this->result(self::UNSUPPORTED, $agent, detail: 'unsupported alg');
        }

        if ($parsed['unsupported'] || ! is_int($params['created'] ?? null) || ! is_string($params['keyid'] ?? null)) {
            return $this->result(self::UNSUPPORTED, $agent, detail: 'unsupported signature parameters');
        }

        // draft-ietf-webbotauth-httpsig-protocol §5.2: the signature must bind the target — a
        // signature over neither @authority nor @target-uri verifies on every host, so one
        // captured at another site could be replayed here
        if (! in_array('@authority', $parsed['components'], true) && ! in_array('@target-uri', $parsed['components'], true)) {
            return $this->result(self::UNSUPPORTED, $agent, $params['keyid'], 'signature covers neither @authority nor @target-uri');
        }

        // §5.2.1: the Signature-Agent header must be covered, or it could be rewritten to point
        // the verifier at a different key directory
        if ($agentHeader !== '' && ! in_array('signature-agent', $parsed['components'], true)) {
            return $this->result(self::UNSUPPORTED, $agent, $params['keyid'], 'Signature-Agent is not covered by the signature');
        }

        // Freshness
        $now = time();
        $skew = (int) ($this->option('clock_skew') ?? 30);
        if ($params['created'] > $now + $skew) {
            return $this->result(self::INVALID, $agent, $params['keyid'], 'created in the future');
        }

        $expires = is_int($params['expires'] ?? null)
            ? $params['expires']
            : $params['created'] + (int) ($this->option('max_age') ?? 300);
        if ($expires < $now - $skew) {
            return $this->result(self::EXPIRED, $agent, $params['keyid'], 'signature expired');
        }

        if ($agent === null) {
            return $this->result(self::UNSUPPORTED, detail: 'missing or malformed Signature-Agent');
        }

        $directoryUrl = $this->directoryUrl($agent);
        if ($directoryUrl === null) {
            return $this->result(self::UNTRUSTED_AGENT, $agent, $params['keyid'], 'agent is not trusted');
        }

        $key = $this->findKey($directoryUrl, $params['keyid']);
        if ($key === false) {
            return $this->result(self::UNAVAILABLE, $agent, $params['keyid'], 'key directory unreachable');
        }
        if ($key === null) {
            return $this->result(self::UNKNOWN_KEY, $agent, $params['keyid'], 'keyid not in the agent key directory');
        }

        if (! function_exists('sodium_crypto_sign_verify_detached')) {
            return $this->result(self::UNAVAILABLE, $agent, $params['keyid'], 'Ed25519 requires ext-sodium or paragonie/sodium_compat');
        }

        $base = $this->signatureBase($request, $parsed, $agentHeader);
        if ($base === null) {
            return $this->result(self::UNSUPPORTED, $agent, $params['keyid'], 'unsupported covered component');
        }

        $signature = $this->decodeSignature($signatures[$label]);
        if ($signature === null || strlen($signature) !== self::ED25519_SIGNATURE_BYTES) {
            return $this->result(self::INVALID, $agent, $params['keyid'], 'malformed signature');
        }

        try {
            $valid = sodium_crypto_sign_verify_detached($signature, $base, $key);
        } catch (\Throwable) {
            $valid = false;
        }

        if (! $valid) {
            return $this->result(self::INVALID, $agent, $params['keyid'], 'signature does not verify');
        }

        // Replay protection: a nonce may be used once within the signature's lifetime
        if (is_string($params['nonce'] ?? null) && $params['nonce'] !== '') {
            $ttl = max(1, $expires - $now + $skew);
            if (! Cache::add('ai-guard:wba-nonce:'.sha1($agent.'|'.$params['nonce']), true, $ttl)) {
                return $this->result(self::INVALID, $agent, $params['keyid'], 'replayed nonce');
            }
        }

        return $this->result(self::VERIFIED, $agent, $params['keyid']);
    }

    /**
     * RFC 7638 JWK thumbprint of an Ed25519 public key (base64url "x"), as used for keyid.
     */
    public static function thumbprint(string $x): string
    {
        return self::base64UrlEncode(hash('sha256', '{"crv":"Ed25519","kty":"OKP","x":"'.$x.'"}', true));
    }

    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/').str_repeat('=', (4 - strlen($value) % 4) % 4), true);

        return $decoded === false ? '' : $decoded;
    }

    private function option(string $key): mixed
    {
        return $this->config['bot_verification']['web_bot_auth'][$key] ?? null;
    }

    private function agentUrl(string $header, string $label): ?string
    {
        if ($header === '') {
            return null;
        }

        if ($header[0] === '"') {
            $value = $this->unquote($header);
        } else {
            // Newer drafts send a dictionary: sig1="https://agent.example"
            $dictionary = $this->parseDictionary($header);
            $member = $dictionary[$label] ?? reset($dictionary);
            if (! is_string($member) || ! str_starts_with($member, '"')) {
                return null;
            }
            $value = $this->unquote($member);
        }

        return filter_var($value, FILTER_VALIDATE_URL) ? rtrim($value, '/') : null;
    }

    /**
     * The key directory URL for an agent, or null when the agent is not allowed.
     */
    private function directoryUrl(string $agent): ?string
    {
        // Admin-pinned directories are trusted as configured
        foreach ((array) ($this->option('directory_overrides') ?? []) as $pinnedAgent => $url) {
            if (rtrim((string) $pinnedAgent, '/') === $agent && is_string($url)) {
                return $url;
            }
        }

        $trusted = array_map(fn ($a) => rtrim((string) $a, '/'), (array) ($this->option('trusted_agents') ?? []));
        $isTrusted = in_array($agent, $trusted, true);

        if (! $isTrusted && ! ($this->option('allow_any_agent') ?? false)) {
            return null;
        }

        if (! str_starts_with($agent, 'https://')) {
            return null;
        }

        // The Signature-Agent header is attacker-controlled: never fetch internal hosts (SSRF)
        if (! $isTrusted && ! $this->isPublicHost($agent)) {
            return null;
        }

        return $agent.self::DIRECTORY_PATH;
    }

    private function isPublicHost(string $url): bool
    {
        $host = parse_url($url, PHP_URL_HOST);
        if (! is_string($host) || $host === '' || filter_var(trim($host, '[]'), FILTER_VALIDATE_IP)) {
            return false;
        }

        $ips = $this->dns->forward($host);
        if ($ips === []) {
            return false;
        }

        foreach ($ips as $ip) {
            if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Raw 32-byte public key for the keyid; null if absent; false if the directory is unreachable.
     */
    private function findKey(string $directoryUrl, string $keyid): string|false|null
    {
        $keys = $this->fetchKeys($directoryUrl);
        if ($keys === null) {
            return false;
        }

        foreach ($keys as $jwk) {
            if (! is_array($jwk) || ($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519' || ! is_string($jwk['x'] ?? null)) {
                continue;
            }

            if (($jwk['kid'] ?? null) === $keyid || self::thumbprint($jwk['x']) === $keyid) {
                $raw = self::base64UrlDecode($jwk['x']);

                return strlen($raw) === self::ED25519_KEY_BYTES ? $raw : null;
            }
        }

        return null;
    }

    /**
     * @return array<int, mixed>|null
     */
    private function fetchKeys(string $url): ?array
    {
        $cacheKey = 'ai-guard:wba-directory:'.sha1($url);
        $minutes = (int) ($this->config['bot_verification']['cache_minutes'] ?? 1440);

        if ($minutes > 0) {
            $cached = Cache::get($cacheKey);
            if (is_array($cached)) {
                return $cached['ok'] ? $cached['keys'] : null;
            }
        }

        $keys = null;
        try {
            $response = Http::timeout((int) ($this->option('timeout') ?? 3))
                ->withOptions(['allow_redirects' => false])
                ->accept('application/http-message-signatures-directory+json, application/json')
                ->get($url);

            if ($response->successful() && is_array($response->json('keys'))) {
                $keys = array_values($response->json('keys'));
            }
        } catch (\Throwable $e) {
            Log::warning('AI Guard: Web Bot Auth key directory fetch failed.', ['url' => $url, 'error' => $e->getMessage()]);
        }

        if ($minutes > 0) {
            // Failures are retried after 5 minutes rather than pinned for the full cache window
            Cache::put($cacheKey, ['ok' => $keys !== null, 'keys' => $keys ?? []], $keys !== null ? $minutes * 60 : 300);
        }

        return $keys;
    }

    /**
     * RFC 9421 §2.5 signature base for the covered components.
     */
    private function signatureBase(Request $request, array $parsed, string $agentHeader): ?string
    {
        $lines = [];
        $uri = $request->getRequestUri();

        foreach ($parsed['components'] as $component) {
            $value = match ($component) {
                '@authority' => strtolower($request->getHttpHost()),
                '@method' => strtoupper($request->getRealMethod()),
                '@path' => (string) (parse_url($uri, PHP_URL_PATH) ?: '/'),
                '@query' => '?'.(string) (parse_url($uri, PHP_URL_QUERY) ?? ''),
                '@target-uri' => $request->getSchemeAndHttpHost().$uri,
                '@scheme' => strtolower($request->getScheme()),
                '@request-target' => $uri,
                'signature-agent' => $agentHeader,
                default => str_starts_with($component, '@') ? null : $this->headerValue($request, $component),
            };

            if ($value === null) {
                return null;
            }

            $lines[] = '"'.$component.'": '.$value;
        }

        $lines[] = '"@signature-params": '.$this->serializeInnerList($parsed);

        return implode("\n", $lines);
    }

    private function headerValue(Request $request, string $name): ?string
    {
        $values = $request->headers->all(strtolower($name));

        return $values === [] ? null : implode(', ', array_map(fn ($v) => trim((string) $v), $values));
    }

    private function serializeInnerList(array $parsed): string
    {
        $items = implode(' ', array_map(fn (string $c) => '"'.$c.'"', $parsed['components']));
        $params = '';

        foreach ($parsed['params'] as $name => $value) {
            $params .= match (true) {
                is_int($value) => ";{$name}={$value}",
                $value === true => ";{$name}",
                default => ';'.$name.'="'.addcslashes((string) $value, '"\\').'"',
            };
        }

        return '('.$items.')'.$params;
    }

    /**
     * RFC 8941 dictionary → member name => raw member value.
     *
     * @return array<string, string>
     */
    private function parseDictionary(string $header): array
    {
        $members = [];
        $buffer = '';
        $inQuotes = false;
        $depth = 0;
        $length = strlen($header);

        for ($i = 0; $i < $length; $i++) {
            $char = $header[$i];

            if ($char === '"' && ($i === 0 || $header[$i - 1] !== '\\')) {
                $inQuotes = ! $inQuotes;
            } elseif (! $inQuotes && $char === '(') {
                $depth++;
            } elseif (! $inQuotes && $char === ')') {
                $depth--;
            }

            if ($char === ',' && ! $inQuotes && $depth === 0) {
                $members[] = $buffer;
                $buffer = '';

                continue;
            }

            $buffer .= $char;
        }
        $members[] = $buffer;

        $dictionary = [];
        foreach ($members as $member) {
            $member = trim($member);
            $eq = strpos($member, '=');
            if ($eq !== false) {
                $dictionary[trim(substr($member, 0, $eq))] = trim(substr($member, $eq + 1));
            }
        }

        return $dictionary;
    }

    /**
     * Inner list with parameters: ("@authority" "signature-agent");created=1;keyid="k"
     *
     * @return array{components: array<int, string>, params: array<string, int|string|bool>, unsupported: bool}|null
     */
    private function parseInnerList(string $value): ?array
    {
        if (! preg_match('/^\(([^)]*)\)(.*)$/s', trim($value), $match)) {
            return null;
        }

        preg_match_all('/"([^"\\\\]*)"((?:;[^\s;"]+(?:="[^"]*")?)*)/', $match[1], $items, PREG_SET_ORDER);

        $components = [];
        $unsupported = false;
        foreach ($items as $item) {
            $components[] = strtolower($item[1]);
            // Component parameters (;sf ;key ;bs ;req ;name) are not supported
            if ($item[2] !== '') {
                $unsupported = true;
            }
        }

        preg_match_all('/;\s*([a-z0-9_.*-]+)(?:=("(?:[^"\\\\]|\\\\.)*"|[^;\s]+))?/i', $match[2], $pairs, PREG_SET_ORDER);

        $params = [];
        foreach ($pairs as $pair) {
            $name = strtolower($pair[1]);
            $raw = $pair[2] ?? '';

            if ($raw === '') {
                $params[$name] = true;
            } elseif ($raw[0] === '"') {
                $params[$name] = (string) preg_replace('/\\\\(.)/', '$1', substr($raw, 1, -1));
            } else {
                $params[$name] = preg_match('/^-?\d+$/', $raw) ? (int) $raw : $raw;
            }
        }

        return ['components' => $components, 'params' => $params, 'unsupported' => $unsupported];
    }

    private function decodeSignature(string $member): ?string
    {
        if (! preg_match('/^:([A-Za-z0-9+\/=]+):/', trim($member), $match)) {
            return null;
        }

        $decoded = base64_decode($match[1], true);

        return $decoded === false ? null : $decoded;
    }

    private function unquote(string $value): string
    {
        $value = trim($value);

        return (string) preg_replace('/\\\\(.)/', '$1', substr($value, 1, -1));
    }

    /**
     * @return array{status: string, agent: string|null, keyid: string|null, detail: string|null}
     */
    private function result(string $status, ?string $agent = null, ?string $keyid = null, ?string $detail = null): array
    {
        return ['status' => $status, 'agent' => $agent, 'keyid' => $keyid, 'detail' => $detail];
    }
}
