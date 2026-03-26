<?php

namespace JayAnta\AiGuard;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AiDetector;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Services\PromptInjectionDetector;

class AiGuardManager
{
    private Application $app;
    private array $config;
    private AiDetector $aiDetector;
    private PromptInjectionDetector $promptDetector;

    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->config = config('ai-guard') ?? [];
        $this->aiDetector = new AiDetector($this->config);
        $this->promptDetector = new PromptInjectionDetector($this->config);
    }

    public function detect(Request $request): array
    {
        $aiResult = $this->aiDetector->detect($request);
        $injectionResult = $this->promptDetector->detect($request);

        if ($aiResult['detected'] && $injectionResult['detected']) {
            return $injectionResult['confidence_score'] >= $aiResult['confidence_score']
                ? $injectionResult
                : $aiResult;
        }

        if ($aiResult['detected']) {
            return $aiResult;
        }

        if ($injectionResult['detected']) {
            return $injectionResult;
        }

        return $aiResult;
    }

    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? true;
    }

    public function getMode(): string
    {
        return $this->config['mode'] ?? 'log_only';
    }

    public function getStats(int $hours = 24): array
    {
        return AiThreatLog::getThreatSummary($hours);
    }

    public function getTopThreats(int $limit = 10): \Illuminate\Support\Collection
    {
        return AiThreatLog::getTopSources($limit);
    }

    public function getRecentThreats(int $limit = 20): \Illuminate\Database\Eloquent\Collection
    {
        return AiThreatLog::recent(24)->notFalsePositive()
            ->orderByDesc('created_at')->limit($limit)->get();
    }

    public function getDetectorInfo(): array
    {
        return array_merge(
            $this->aiDetector->getDetectorInfo(),
            [
                'prompt_patterns' => $this->promptDetector->getPatternCount(),
                'honeypot_enabled' => $this->config['honeypot']['enabled'] ?? false,
                'response_scanning_enabled' => $this->config['response_scanning']['enabled'] ?? false,
                'robots_txt_enabled' => $this->config['robots_txt']['enabled'] ?? false,
                'fingerprinting_enabled' => $this->config['fingerprinting']['enabled'] ?? false,
                'ml_enabled' => $this->config['ml_detection']['enabled'] ?? false,
                'ml_driver' => $this->config['ml_detection']['driver'] ?? 'none',
            ]
        );
    }

    public function getFeatureStatus(): array
    {
        return [
            'enabled' => $this->isEnabled(),
            'mode' => $this->getMode(),
            'bot_signatures' => [
                'enabled' => $this->config['bot_signatures']['enabled'] ?? true,
                'total_bots' => BotSignatures::getTotalCount(),
                'categories' => BotSignatures::getCategoryCount(),
            ],
            'ai_crawlers' => $this->config['ai_crawlers']['enabled'] ?? false,
            'prompt_injection' => $this->config['prompt_injection']['enabled'] ?? false,
            'data_harvesters' => $this->config['data_harvesters']['enabled'] ?? false,
            'honeypot' => $this->config['honeypot']['enabled'] ?? false,
            'response_scanning' => $this->config['response_scanning']['enabled'] ?? false,
            'robots_txt' => $this->config['robots_txt']['enabled'] ?? false,
            'fingerprinting' => $this->config['fingerprinting']['enabled'] ?? false,
            'ml_detection' => [
                'enabled' => $this->config['ml_detection']['enabled'] ?? false,
                'driver' => $this->config['ml_detection']['driver'] ?? 'none',
            ],
        ];
    }
}
