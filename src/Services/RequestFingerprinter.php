<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;

class RequestFingerprinter
{
    private array $config;

    private ?IpRangeRepository $ranges;

    /**
     * Headers every current browser sends, whatever its engine. Sec-CH-UA* are Chromium-only,
     * DNT is off by default, and Connection is forbidden in HTTP/2 — counting those as missing
     * would score ordinary Firefox and Safari traffic as suspicious.
     */
    private const BROWSER_HEADERS = [
        'Accept', 'Accept-Language', 'Accept-Encoding',
        'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site',
        'Upgrade-Insecure-Requests',
    ];

    // Headers a CDN sets with the client's JA4 TLS fingerprint (Cloudflare, CloudFront, your own)
    public const JA4_HEADERS = ['cf-ja4', 'cloudfront-viewer-ja4-fingerprint', 'x-ja4'];

    public function __construct(array $config, ?IpRangeRepository $ranges = null)
    {
        $this->config = $config;
        $this->ranges = $ranges;
    }

    public function analyze(Request $request): array
    {
        if (! ($this->config['fingerprinting']['enabled'] ?? false)) {
            return $this->buildEmptyResult();
        }

        $signals = [];
        $suspicionScore = 0;

        // Signal 1: Missing standard browser headers
        $missingHeaders = $this->checkMissingBrowserHeaders($request);
        if ($missingHeaders > 3) {
            $suspicionScore += min($missingHeaders * 5, 30);
            $signals[] = "missing_{$missingHeaders}_browser_headers";
        }

        // Signal 2: Header order anomaly — bots often have alphabetical headers
        if ($this->hasAlphabeticalHeaders($request)) {
            $suspicionScore += 15;
            $signals[] = 'alphabetical_header_order';
        }

        // Signal 3: Accept header anomaly — bots use generic or missing Accept
        if ($this->hasAnomalousAccept($request)) {
            $suspicionScore += 15;
            $signals[] = 'anomalous_accept_header';
        }

        // Signal 4: Connection: close — bots often ask for it. Its absence says nothing:
        // HTTP/2 forbids the header, so most real browser traffic has none.
        if (strtolower((string) $request->header('Connection')) === 'close') {
            $suspicionScore += 10;
            $signals[] = 'no_keep_alive';
        }

        // Signal 5: Empty or missing Referer on internal navigation
        if ($request->header('Sec-Fetch-Site') === null && $request->header('Referer') === null) {
            $suspicionScore += 5;
            $signals[] = 'no_navigation_context';
        }

        // Signal 6: What your CDN saw at the edge — JA4 TLS fingerprint and bot score
        foreach ($this->edgeSignals($request) as $signal => $score) {
            $suspicionScore += $score;
            $signals[] = $signal;
        }

        // Signal 7: A browser user-agent from a cloud / datacenter network
        $network = $this->datacenterNetwork($request);
        if ($network !== null) {
            $suspicionScore += (int) ($this->config['fingerprinting']['datacenter']['score'] ?? 25);
            $signals[] = "datacenter_ip:{$network}";
        }

        if ($suspicionScore < ($this->config['fingerprinting']['min_score'] ?? 30)) {
            return $this->buildEmptyResult();
        }

        return [
            'detected' => true,
            'threat_type' => 'suspicious_fingerprint',
            'threat_source' => 'fingerprint_analysis',
            'confidence_score' => min($suspicionScore, 100),
            'matched_pattern' => implode(', ', $signals),
        ];
    }

    public function generateFingerprint(Request $request): string
    {
        $components = [
            $request->userAgent() ?? '',
            $request->header('Accept-Language') ?? '',
            $request->header('Accept-Encoding') ?? '',
            $request->header('Accept') ?? '',
            implode(',', array_keys($request->headers->all())),
        ];

        return substr(md5(implode('|', $components)), 0, 16);
    }

    public function isEnabled(): bool
    {
        return $this->config['fingerprinting']['enabled'] ?? false;
    }

    /**
     * The client's JA4 fingerprint as reported by a trusted CDN, or null.
     */
    public function ja4(Request $request): ?string
    {
        $edge = (array) ($this->config['fingerprinting']['edge'] ?? []);

        if (($edge['require_trusted_proxy'] ?? true) && ! $request->isFromTrustedProxy()) {
            return null;
        }

        foreach ((array) ($edge['ja4_headers'] ?? self::JA4_HEADERS) as $header) {
            $value = strtolower(trim((string) $request->header((string) $header)));

            if (preg_match('/^[tqd][0-9a-z]{2}[di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/', $value)) {
                return $value;
            }
        }

        return null;
    }

    /**
     * @return array<string, int>
     */
    private function edgeSignals(Request $request): array
    {
        $edge = (array) ($this->config['fingerprinting']['edge'] ?? []);

        // Anyone can send "cf-ja4": edge headers count only when your CDN set them
        if (! ($edge['enabled'] ?? true) || (($edge['require_trusted_proxy'] ?? true) && ! $request->isFromTrustedProxy())) {
            return [];
        }

        $signals = [];
        $ja4 = $this->ja4($request);

        if ($ja4 !== null) {
            if ($this->isListedClient($ja4, (array) ($edge['client_ja4'] ?? []))) {
                $signals['ja4_http_client'] = 40;
            } elseif ($this->claimsBrowser((string) $request->userAgent()) && ! $this->ja4LooksLikeBrowser($ja4)) {
                $signals['ja4_user_agent_mismatch'] = 35;
            }
        }

        $header = $edge['bot_score_header'] ?? 'cf-bot-score';
        $botScore = is_string($header) && $header !== '' ? trim((string) $request->header($header)) : '';

        if (ctype_digit($botScore)) {
            $value = (int) $botScore;
            $threshold = (int) ($edge['bot_score_threshold'] ?? 29);

            if ($value === 1) {
                $signals['edge_bot_score:1'] = 40;
            } elseif ($value >= 2 && $value <= $threshold) {
                $signals["edge_bot_score:{$value}"] = 25;
            }
        }

        return $signals;
    }

    /**
     * @param  array<int, string>  $clients  Full JA4 fingerprints or prefixes (e.g. a JA4_a like 't13d1812h1')
     */
    private function isListedClient(string $ja4, array $clients): bool
    {
        foreach ($clients as $client) {
            $client = strtolower(rtrim(trim((string) $client), '*'));

            if ($client !== '' && str_starts_with($ja4, $client)) {
                return true;
            }
        }

        return false;
    }

    /**
     * JA4_a is protocol, TLS version, SNI (d = domain, i = IP), cipher count, extension
     * count, and the first ALPN value. Current browsers offer TLS 1.3, send SNI, and offer h2 first.
     */
    private function ja4LooksLikeBrowser(string $ja4): bool
    {
        return substr($ja4, 1, 2) === '13'
            && $ja4[3] === 'd'
            && ! in_array(substr($ja4, 8, 2), ['00', 'h1'], true);
    }

    private function claimsBrowser(string $userAgent): bool
    {
        return (bool) preg_match('#^Mozilla/5\.0 .*(Chrome|Firefox|Safari|Edg|OPR)/\d#', $userAgent)
            && ! preg_match('/bot|crawl|spider|slurp|headless|python|curl|wget/i', $userAgent);
    }

    private function datacenterNetwork(Request $request): ?string
    {
        $options = (array) ($this->config['fingerprinting']['datacenter'] ?? []);

        if (! ($options['enabled'] ?? false) || ! $this->claimsBrowser((string) $request->userAgent())) {
            return null;
        }

        $ip = (string) $request->ip();
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return null;
        }

        $this->ranges ??= new IpRangeRepository((int) ($options['timeout'] ?? 5), (int) ($options['cache_minutes'] ?? 1440));
        $fetch = (bool) ($options['fetch_on_request'] ?? true);

        foreach ((array) ($options['ranges'] ?? []) as $network => $sources) {
            if ($this->ranges->contains($ip, array_map('strval', (array) $sources), $fetch) === true) {
                return (string) $network;
            }
        }

        return null;
    }

    private function checkMissingBrowserHeaders(Request $request): int
    {
        $missing = 0;
        foreach (self::BROWSER_HEADERS as $header) {
            if ($request->header($header) === null) {
                $missing++;
            }
        }

        return $missing;
    }

    private function hasAlphabeticalHeaders(Request $request): bool
    {
        $headers = array_keys($request->headers->all());
        if (count($headers) < 3) {
            return false;
        }

        $sorted = $headers;
        sort($sorted);

        return $headers === $sorted;
    }

    private function hasAnomalousAccept(Request $request): bool
    {
        $accept = $request->header('Accept');

        if ($accept === null) {
            return true;
        }

        if ($accept === '*/*' && $request->method() === 'GET') {
            return true;
        }

        return false;
    }

    private function buildEmptyResult(): array
    {
        return [
            'detected' => false,
            'threat_type' => null,
            'threat_source' => null,
            'confidence_score' => 0,
            'matched_pattern' => null,
        ];
    }
}
