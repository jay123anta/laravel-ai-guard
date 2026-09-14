<?php

namespace JayAnta\AiGuard;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use JayAnta\AiGuard\Console\Commands\AiGuardAuditVerify;
use JayAnta\AiGuard\Console\Commands\AiGuardMcpPins;
use JayAnta\AiGuard\Console\Commands\AiGuardPrune;
use JayAnta\AiGuard\Console\Commands\AiGuardRedTeam;
use JayAnta\AiGuard\Console\Commands\AiGuardRefreshRanges;
use JayAnta\AiGuard\Console\Commands\AiGuardRobotsTxt;
use JayAnta\AiGuard\Console\Commands\AiGuardStats;
use JayAnta\AiGuard\Console\Commands\AiGuardUpdateSignatures;
use JayAnta\AiGuard\Http\Middleware\AiAgentPolicyMiddleware;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Http\Middleware\AiPreferencesMiddleware;
use JayAnta\AiGuard\Http\Middleware\ContentSecurityPolicyMiddleware;
use JayAnta\AiGuard\Http\Middleware\LlmRouteMiddleware;
use JayAnta\AiGuard\Http\Middleware\McpGuardMiddleware;
use JayAnta\AiGuard\Services\AiDetector;
use JayAnta\AiGuard\Services\AuditChain;
use JayAnta\AiGuard\Services\AuditExporter;
use JayAnta\AiGuard\Services\BotSignatures;
use JayAnta\AiGuard\Services\BotVerifier;
use JayAnta\AiGuard\Services\ConversationGuard;
use JayAnta\AiGuard\Services\HoneypotService;
use JayAnta\AiGuard\Services\LlmOutputGuard;
use JayAnta\AiGuard\Services\McpGuard;
use JayAnta\AiGuard\Services\MlDetector;
use JayAnta\AiGuard\Services\ModerationGuard;
use JayAnta\AiGuard\Services\PromptInjectionDetector;
use JayAnta\AiGuard\Services\Redactor;
use JayAnta\AiGuard\Services\RequestFingerprinter;
use JayAnta\AiGuard\Services\ResponseScanner;
use JayAnta\AiGuard\Services\RobotsTxtEnforcer;
use JayAnta\AiGuard\Services\SafeRenderer;
use JayAnta\AiGuard\Services\Spotlighter;
use JayAnta\AiGuard\Services\SqlGuard;
use JayAnta\AiGuard\Services\TaintTracker;
use JayAnta\AiGuard\Services\TokenBudget;
use JayAnta\AiGuard\Services\ToolCallScanner;
use JayAnta\AiGuard\Services\ToolFirewall;
use JayAnta\AiGuard\Services\TopicGuard;
use JayAnta\AiGuard\Services\WebBotAuthVerifier;
use JayAnta\AiGuard\Support\DnsResolver;
use JayAnta\AiGuard\Support\SignatureFeed;
use JayAnta\AiGuard\Support\ThreatLogger;

class AiGuardServiceProvider extends ServiceProvider
{
    /**
     * Container singletons that read config('ai-guard') when first resolved.
     */
    public const SINGLETONS = [
        'ai-guard',
        AiDetector::class,
        PromptInjectionDetector::class,
        HoneypotService::class,
        ResponseScanner::class,
        RobotsTxtEnforcer::class,
        RequestFingerprinter::class,
        MlDetector::class,
        WebBotAuthVerifier::class,
        BotVerifier::class,
        LlmOutputGuard::class,
        ToolCallScanner::class,
        ThreatLogger::class,
        Redactor::class,
        Spotlighter::class,
        TokenBudget::class,
        ModerationGuard::class,
        TopicGuard::class,
        ConversationGuard::class,
        TaintTracker::class,
        ToolFirewall::class,
        McpGuard::class,
        SafeRenderer::class,
        SqlGuard::class,
        AuditChain::class,
        AuditExporter::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ai-guard.php', 'ai-guard');

        $this->app->singleton('ai-guard', fn () => new AiGuardManager);

        $this->app->singleton(AiDetector::class, fn ($app) => new AiDetector(config('ai-guard') ?? []));

        $this->app->singleton(PromptInjectionDetector::class, fn ($app) => new PromptInjectionDetector(config('ai-guard') ?? []));

        $this->app->singleton(HoneypotService::class, fn ($app) => new HoneypotService(config('ai-guard') ?? []));

        $this->app->singleton(ResponseScanner::class, fn ($app) => new ResponseScanner(
            config('ai-guard') ?? [],
            $app->make(PromptInjectionDetector::class)
        ));

        $this->app->singleton(RobotsTxtEnforcer::class, fn ($app) => new RobotsTxtEnforcer(config('ai-guard') ?? []));

        $this->app->singleton(RequestFingerprinter::class, fn ($app) => new RequestFingerprinter(config('ai-guard') ?? []));

        $this->app->singleton(MlDetector::class, fn ($app) => new MlDetector(config('ai-guard') ?? []));

        $this->app->singleton(DnsResolver::class, fn () => new DnsResolver);

        $this->app->singleton(WebBotAuthVerifier::class, fn ($app) => new WebBotAuthVerifier(
            config('ai-guard') ?? [],
            $app->make(DnsResolver::class)
        ));

        $this->app->singleton(BotVerifier::class, fn ($app) => new BotVerifier(
            config('ai-guard') ?? [],
            $app->make(DnsResolver::class),
            $app->make(WebBotAuthVerifier::class)
        ));

        $this->app->singleton(LlmOutputGuard::class, fn ($app) => new LlmOutputGuard(
            config('ai-guard') ?? [],
            $app->make(PromptInjectionDetector::class),
            null,
            $app->make(ModerationGuard::class)
        ));

        $this->app->singleton(ToolCallScanner::class, fn ($app) => new ToolCallScanner(
            config('ai-guard') ?? [],
            $app->make(PromptInjectionDetector::class)
        ));

        $this->app->singleton(ThreatLogger::class, fn () => new ThreatLogger(config('ai-guard') ?? []));

        $this->app->singleton(Redactor::class, fn () => new Redactor(config('ai-guard') ?? []));

        $this->app->singleton(Spotlighter::class, fn () => new Spotlighter(config('ai-guard') ?? []));

        $this->app->singleton(TokenBudget::class, fn () => new TokenBudget(config('ai-guard') ?? []));

        $this->app->singleton(ModerationGuard::class, fn () => new ModerationGuard(config('ai-guard') ?? []));

        $this->app->singleton(TopicGuard::class, fn () => new TopicGuard(config('ai-guard') ?? []));

        $this->app->singleton(ConversationGuard::class, fn ($app) => new ConversationGuard(
            config('ai-guard') ?? [],
            $app->make(PromptInjectionDetector::class)
        ));

        // Scoped: taint and per-turn call counts must not leak between requests (Octane) or jobs
        $this->app->scoped(TaintTracker::class, fn () => new TaintTracker);

        $this->app->scoped(ToolFirewall::class, fn ($app) => new ToolFirewall(
            config('ai-guard') ?? [],
            $app->make(TaintTracker::class),
            $app->make(ToolCallScanner::class),
            $app->make(Spotlighter::class)
        ));

        $this->app->singleton(McpGuard::class, fn ($app) => new McpGuard(
            config('ai-guard') ?? [],
            $app->make(ToolCallScanner::class)
        ));

        $this->app->singleton(SafeRenderer::class, fn () => new SafeRenderer(config('ai-guard') ?? []));

        $this->app->singleton(SqlGuard::class, fn () => new SqlGuard(config('ai-guard') ?? []));

        $this->app->singleton(AuditChain::class, fn () => new AuditChain(config('ai-guard') ?? []));

        // Scoped: the export buffer belongs to one request or job
        $this->app->scoped(AuditExporter::class, fn () => new AuditExporter(config('ai-guard') ?? []));
    }

    public function boot(): void
    {
        $this->app->make(Router::class)->aliasMiddleware('ai-guard', AiGuardMiddleware::class);
        $this->app->make(Router::class)->aliasMiddleware('ai-guard.preferences', AiPreferencesMiddleware::class);
        $this->app->make(Router::class)->aliasMiddleware('ai-guard.llm', LlmRouteMiddleware::class);
        $this->app->make(Router::class)->aliasMiddleware('ai-guard.mcp', McpGuardMiddleware::class);
        $this->app->make(Router::class)->aliasMiddleware('ai-guard.csp', ContentSecurityPolicyMiddleware::class);
        $this->app->make(Router::class)->aliasMiddleware('ai-guard.agents', AiAgentPolicyMiddleware::class);

        // Audit exports are buffered and sent when the request, command, or queued job ends
        $flush = function () {
            if ($this->app->resolved(AuditExporter::class)) {
                $this->app->make(AuditExporter::class)->flush();
            }
        };
        $this->app->terminating($flush);
        $this->app->make('events')->listen(['Illuminate\Queue\Events\JobProcessed', 'Illuminate\Queue\Events\JobFailed'], $flush);

        // Tokens saved by ai-guard:update-signatures (nothing is fetched here)
        if (config('ai-guard.bot_signatures.feed.enabled') ?? true) {
            BotSignatures::loadFeed(SignatureFeed::path());
        }

        // @aiSafe($reply) renders model output safely; @aiNonce prints the CSP nonce
        $this->callAfterResolving('blade.compiler', function ($blade) {
            $blade->directive('aiSafe', fn ($expression) => "<?php echo app('ai-guard')->safeHtml({$expression})->toHtml(); ?>");
            $blade->directive('aiNonce', fn () => "<?php echo e(app('ai-guard')->cspNonce()); ?>");
        });

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
                AiGuardRobotsTxt::class,
                AiGuardMcpPins::class,
                AiGuardRefreshRanges::class,
                AiGuardUpdateSignatures::class,
                AiGuardAuditVerify::class,
                AiGuardPrune::class,
                AiGuardRedTeam::class,
            ]);
        }
    }

    public function provides(): array
    {
        return ['ai-guard'];
    }
}
