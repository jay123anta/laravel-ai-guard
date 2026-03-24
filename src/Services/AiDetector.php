<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;

class AiDetector
{
    private array $config;
    private array $crawlerPatterns;
    private array $harvesterPatterns;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->crawlerPatterns = $config['ai_crawlers']['user_agents'] ?? [];
        $this->harvesterPatterns = $config['data_harvesters']['generic_user_agents'] ?? [];
    }

    public function detect(Request $request): array
    {
        $results = [];

        if ($this->config['ai_crawlers']['enabled'] ?? false) {
            $results[] = $this->detectAiCrawler($request);
        }

        if ($this->config['data_harvesters']['enabled'] ?? false) {
            $results[] = $this->detectDataHarvester($request);
        }

        if (empty($results)) {
            return $this->buildEmptyResult();
        }

        $best = $this->buildEmptyResult();
        foreach ($results as $result) {
            if ($result['confidence_score'] > $best['confidence_score']) {
                $best = $result;
            }
        }

        return $best;
    }

    public function detectAiCrawler(Request $request): array
    {
        $userAgent = $request->userAgent() ?? '';

        foreach ($this->crawlerPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                return [
                    'detected' => true,
                    'threat_type' => 'ai_crawler',
                    'threat_source' => $pattern,
                    'confidence_score' => 95,
                    'matched_pattern' => $pattern,
                ];
            }
        }

        return $this->buildEmptyResult();
    }

    public function detectDataHarvester(Request $request): array
    {
        $userAgent = $request->userAgent() ?? '';
        $result = $this->buildEmptyResult();

        // Check 1: Generic user agent
        foreach ($this->harvesterPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                $result = [
                    'detected' => true,
                    'threat_type' => 'data_harvester',
                    'threat_source' => $pattern,
                    'confidence_score' => 80,
                    'matched_pattern' => $pattern,
                ];
                break;
            }
        }

        // Check 2: Missing Accept-Language header
        if ($this->config['data_harvesters']['check_accept_language'] ?? false) {
            $acceptLanguage = $request->header('Accept-Language');

            if (empty($acceptLanguage)) {
                $result['confidence_score'] = min($result['confidence_score'] + 20, 100);
                $result['detected'] = true;
                $result['threat_type'] = $result['threat_type'] ?? 'data_harvester';
                $result['matched_pattern'] = $result['matched_pattern'] ?? 'missing_accept_language';
            }
        }

        return $result;
    }

    public function isWhitelisted(Request $request): bool
    {
        $ip = $request->ip();
        $userAgent = $request->userAgent() ?? '';

        $whitelistIps = $this->config['false_positives']['whitelist_ips'] ?? [];
        if (in_array($ip, $whitelistIps, true)) {
            return true;
        }

        $whitelistAgents = $this->config['false_positives']['whitelist_user_agents'] ?? [];
        foreach ($whitelistAgents as $agent) {
            if (stripos($userAgent, $agent) !== false) {
                return true;
            }
        }

        return false;
    }

    public function getDetectorInfo(): array
    {
        return [
            'crawler_patterns_count' => count($this->crawlerPatterns),
            'harvester_patterns_count' => count($this->harvesterPatterns),
            'ai_crawlers_enabled' => $this->config['ai_crawlers']['enabled'] ?? false,
            'data_harvesters_enabled' => $this->config['data_harvesters']['enabled'] ?? false,
        ];
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
