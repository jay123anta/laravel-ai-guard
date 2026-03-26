<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;

class RequestFingerprinter
{
    private array $config;

    private const BROWSER_HEADERS = [
        'Accept', 'Accept-Language', 'Accept-Encoding',
        'Sec-CH-UA', 'Sec-CH-UA-Mobile', 'Sec-CH-UA-Platform',
        'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site',
        'Upgrade-Insecure-Requests', 'DNT', 'Connection',
    ];

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function analyze(Request $request): array
    {
        if (!($this->config['fingerprinting']['enabled'] ?? false)) {
            return $this->buildEmptyResult();
        }

        $signals = [];
        $suspicionScore = 0;

        // Signal 1: Missing standard browser headers
        $missingHeaders = $this->checkMissingBrowserHeaders($request);
        if ($missingHeaders > 4) {
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

        // Signal 4: Connection header — bots often omit or use 'close'
        $connection = $request->header('Connection');
        if ($connection === null || strtolower($connection) === 'close') {
            $suspicionScore += 10;
            $signals[] = 'no_keep_alive';
        }

        // Signal 5: Empty or missing Referer on internal navigation
        if ($request->header('Sec-Fetch-Site') === null && $request->header('Referer') === null) {
            $suspicionScore += 5;
            $signals[] = 'no_navigation_context';
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
