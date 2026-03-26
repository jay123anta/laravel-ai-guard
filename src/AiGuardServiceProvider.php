<?php

namespace JayAnta\AiGuard;

use Illuminate\Support\ServiceProvider;
use JayAnta\AiGuard\AiGuardManager;
use JayAnta\AiGuard\Console\Commands\AiGuardStats;
use JayAnta\AiGuard\Services\AiDetector;
use JayAnta\AiGuard\Services\HoneypotService;
use JayAnta\AiGuard\Services\MlDetector;
use JayAnta\AiGuard\Services\PromptInjectionDetector;
use JayAnta\AiGuard\Services\RequestFingerprinter;
use JayAnta\AiGuard\Services\ResponseScanner;
use JayAnta\AiGuard\Services\RobotsTxtEnforcer;

class AiGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ai-guard.php', 'ai-guard');

        $this->app->singleton('ai-guard', fn ($app) => new AiGuardManager($app));

        $this->app->singleton(AiDetector::class, fn ($app) => new AiDetector(config('ai-guard') ?? []));

        $this->app->singleton(PromptInjectionDetector::class, fn ($app) => new PromptInjectionDetector(config('ai-guard') ?? []));

        $this->app->singleton(HoneypotService::class, fn ($app) => new HoneypotService(config('ai-guard') ?? []));

        $this->app->singleton(ResponseScanner::class, fn ($app) => new ResponseScanner(config('ai-guard') ?? []));

        $this->app->singleton(RobotsTxtEnforcer::class, fn ($app) => new RobotsTxtEnforcer(config('ai-guard') ?? []));

        $this->app->singleton(RequestFingerprinter::class, fn ($app) => new RequestFingerprinter(config('ai-guard') ?? []));

        $this->app->singleton(MlDetector::class, fn ($app) => new MlDetector(config('ai-guard') ?? []));
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/ai-guard.php' => config_path('ai-guard.php'),
        ], 'ai-guard-config');

        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'ai-guard-migrations');

        $this->loadRoutesFrom(__DIR__.'/../routes/api.php');
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'ai-guard');

        if ($this->app->runningInConsole()) {
            $this->commands([
                AiGuardStats::class,
            ]);
        }
    }

    public function provides(): array
    {
        return ['ai-guard'];
    }
}
