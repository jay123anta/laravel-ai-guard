<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class RobotsTxtEnforcer
{
    private array $config;

    private ?RobotsTxtParser $parser = null;

    private ?string $parsedContent = null;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function check(Request $request, ?array $botInfo): array
    {
        if (! ($this->config['robots_txt']['enabled'] ?? false)) {
            return $this->buildEmptyResult();
        }

        if ($botInfo === null) {
            return $this->buildEmptyResult();
        }

        $parser = $this->getParser();
        if ($parser === null) {
            return $this->buildEmptyResult();
        }

        $requestPath = '/'.ltrim($request->path(), '/');
        $query = $request->getQueryString();
        if ($query !== null && $query !== '') {
            $requestPath .= '?'.$query;
        }

        $result = $parser->check($botInfo['matched_bot'], $requestPath);

        if ($result['allowed'] || $result['rule'] === null) {
            return $this->buildEmptyResult();
        }

        return [
            'detected' => true,
            'threat_type' => 'robots_txt_violation',
            'threat_source' => $botInfo['matched_bot'],
            'confidence_score' => $this->config['robots_txt']['confidence_boost'] ?? 30,
            'matched_pattern' => 'robots.txt disallow: '.$result['rule']['path'],
        ];
    }

    public function isEnabled(): bool
    {
        return $this->config['robots_txt']['enabled'] ?? false;
    }

    /**
     * Disallow rules that apply to the bot (its own group, or "*" when it has none).
     */
    public function getDisallowedPaths(?string $botName = null): array
    {
        $parser = $this->getParser();

        if ($parser === null) {
            return [];
        }

        return $parser->disallowedPaths($botName ?? '*');
    }

    private function getParser(): ?RobotsTxtParser
    {
        $content = $this->getRobotsContent();

        if ($content === '') {
            return null;
        }

        if ($this->parser === null || $this->parsedContent !== $content) {
            $this->parser = new RobotsTxtParser($content);
            $this->parsedContent = $content;
        }

        return $this->parser;
    }

    private function getRobotsContent(): string
    {
        $cacheMinutes = $this->config['robots_txt']['cache_minutes'] ?? 60;
        $robotsPath = $this->config['robots_txt']['path'] ?? null;

        // A missing file is cached as '' — Cache::remember does not store null,
        // which would re-read the filesystem on every request
        return Cache::remember('ai-guard:robots-txt', $cacheMinutes * 60, function () use ($robotsPath) {
            $robotsPath ??= public_path('robots.txt');

            if (! file_exists($robotsPath)) {
                return '';
            }

            $content = file_get_contents($robotsPath);

            return $content !== false ? $content : '';
        });
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
