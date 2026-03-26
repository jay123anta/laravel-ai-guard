<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class RobotsTxtEnforcer
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function check(Request $request, ?array $botInfo): array
    {
        if (!($this->config['robots_txt']['enabled'] ?? false)) {
            return $this->buildEmptyResult();
        }

        if ($botInfo === null) {
            return $this->buildEmptyResult();
        }

        $disallowedPaths = $this->getDisallowedPaths($botInfo['matched_bot']);

        if (empty($disallowedPaths)) {
            return $this->buildEmptyResult();
        }

        $requestPath = '/' . ltrim($request->path(), '/');

        foreach ($disallowedPaths as $disallowed) {
            if ($this->pathMatches($requestPath, $disallowed)) {
                $boostAmount = $this->config['robots_txt']['confidence_boost'] ?? 30;

                return [
                    'detected' => true,
                    'threat_type' => 'robots_txt_violation',
                    'threat_source' => $botInfo['matched_bot'],
                    'confidence_score' => $boostAmount,
                    'matched_pattern' => "robots.txt disallow: {$disallowed}",
                ];
            }
        }

        return $this->buildEmptyResult();
    }

    public function isEnabled(): bool
    {
        return $this->config['robots_txt']['enabled'] ?? false;
    }

    public function getDisallowedPaths(?string $botName = null): array
    {
        $robotsContent = $this->getRobotsContent();

        if ($robotsContent === null) {
            return [];
        }

        return $this->parseDisallowRules($robotsContent, $botName);
    }

    private function getRobotsContent(): ?string
    {
        $cacheMinutes = $this->config['robots_txt']['cache_minutes'] ?? 60;

        return Cache::remember('ai-guard:robots-txt', $cacheMinutes * 60, function () {
            $robotsPath = public_path('robots.txt');

            if (!file_exists($robotsPath)) {
                return null;
            }

            $content = file_get_contents($robotsPath);
            return $content !== false ? $content : null;
        });
    }

    private function parseDisallowRules(string $content, ?string $botName): array
    {
        $lines = explode("\n", $content);
        $disallowed = [];
        $currentAgent = null;
        $isRelevantAgent = false;

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (stripos($line, 'User-agent:') === 0) {
                $agent = trim(substr($line, 11));
                $currentAgent = $agent;
                $isRelevantAgent = ($agent === '*');

                if ($botName !== null && stripos($agent, $botName) !== false) {
                    $isRelevantAgent = true;
                }
                continue;
            }

            if ($isRelevantAgent && stripos($line, 'Disallow:') === 0) {
                $path = trim(substr($line, 9));
                if ($path !== '') {
                    $disallowed[] = $path;
                }
            }
        }

        return array_unique($disallowed);
    }

    private function pathMatches(string $requestPath, string $disallowedPath): bool
    {
        if ($disallowedPath === '/') {
            return true;
        }

        if (str_ends_with($disallowedPath, '*')) {
            $prefix = rtrim($disallowedPath, '*');
            return str_starts_with($requestPath, $prefix);
        }

        return str_starts_with($requestPath, $disallowedPath);
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
