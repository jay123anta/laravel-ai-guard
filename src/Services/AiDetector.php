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

        // Categorized bot signature detection
        $botResult = $this->detectCategorizedBot($request);
        if ($botResult['detected']) {
            $results[] = $botResult;
        }

        // Legacy AI crawler detection (config-defined user_agents)
        if ($this->config['ai_crawlers']['enabled'] ?? false) {
            $crawlerResult = $this->detectAiCrawler($request);
            if ($crawlerResult['detected']) {
                $results[] = $crawlerResult;
            }
        }

        // Data harvester detection
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

    public function detectCategorizedBot(Request $request): array
    {
        if (! ($this->config['bot_signatures']['enabled'] ?? true)) {
            return $this->buildEmptyResult();
        }

        $userAgent = $request->userAgent() ?? '';
        if ($userAgent === '') {
            return $this->buildEmptyResult();
        }

        $botInfo = BotSignatures::findBot($userAgent, $this->excludedCategories(), $this->confidenceOverrides());

        if ($botInfo === null) {
            return $this->buildEmptyResult();
        }

        // Map category to threat type — all three AI categories stay 'ai_crawler';
        // the purpose is recorded separately as bot_category
        $threatType = match ($botInfo['category']) {
            'ai_training', 'ai_search', 'ai_agents' => 'ai_crawler',
            'seo_tools' => 'seo_bot',
            'scrapers' => 'scraper',
            'bad_bots' => 'bad_bot',
            'data_harvesters' => 'data_harvester',
            'search_engines' => 'search_engine',
            default => 'bot',
        };

        return [
            'detected' => true,
            'threat_type' => $threatType,
            'threat_source' => $botInfo['matched_bot'],
            'confidence_score' => $botInfo['confidence'],
            'matched_pattern' => $botInfo['matched_bot'],
            'bot_category' => $botInfo['category'],
            'bot_label' => $botInfo['label'],
        ];
    }

    public function detectAiCrawler(Request $request): array
    {
        $userAgent = $request->userAgent() ?? '';
        $signaturesEnabled = $this->config['bot_signatures']['enabled'] ?? true;

        foreach ($this->crawlerPatterns as $pattern) {
            // Tokens the signature database knows are scored by their category —
            // a flat 95 here would override seo_tools/scrapers scoring and ignore
            // disabled_categories
            if ($signaturesEnabled && BotSignatures::isKnownToken($pattern)) {
                continue;
            }

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

        if ($this->config['data_harvesters']['check_accept_language'] ?? false) {
            $acceptLanguage = $request->header('Accept-Language');

            // A missing Accept-Language adds weight to something already suspicious, but on its
            // own it is not a finding: health checks, uptime monitors, sendBeacon and most
            // server-to-server calls send no Accept-Language, and logging every one of them as a
            // threat with no source fills the log with noise.
            if (empty($acceptLanguage) && $result['detected']) {
                $result['confidence_score'] = min($result['confidence_score'] + 20, 100);
                $result['matched_pattern'] = ($result['matched_pattern'] ?? 'data_harvester').', missing_accept_language';
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

    public function getBotInfo(Request $request): ?array
    {
        $userAgent = $request->userAgent() ?? '';

        return BotSignatures::findBot($userAgent, $this->excludedCategories());
    }

    /**
     * Categories switched off by bot_signatures.disabled_categories or by a feature toggle.
     *
     * @return array<int, string>
     */
    private function excludedCategories(): array
    {
        $excluded = $this->config['bot_signatures']['disabled_categories'] ?? ['search_engines'];

        if (! ($this->config['ai_crawlers']['enabled'] ?? true)) {
            array_push($excluded, ...BotSignatures::AI_CATEGORIES);
        }

        if (! ($this->config['data_harvesters']['enabled'] ?? true)) {
            $excluded[] = 'data_harvesters';
        }

        return BotSignatures::expandCategories($excluded);
    }

    /**
     * bot_signatures.confidence: per-category score overrides (the per-purpose policy).
     *
     * @return array<string, int>
     */
    private function confidenceOverrides(): array
    {
        return BotSignatures::confidenceOverrides($this->config);
    }

    public function getDetectorInfo(): array
    {
        return [
            'crawler_patterns_count' => count($this->crawlerPatterns),
            'harvester_patterns_count' => count($this->harvesterPatterns),
            'bot_signatures_count' => BotSignatures::getTotalCount(),
            'bot_categories_count' => BotSignatures::getCategoryCount(),
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
