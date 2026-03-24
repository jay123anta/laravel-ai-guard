<?php

namespace JayAnta\AiGuard;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AiDetector;
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
            ['prompt_patterns' => $this->promptDetector->getPatternCount()]
        );
    }
}
