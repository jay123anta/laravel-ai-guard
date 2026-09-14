<?php

namespace JayAnta\AiGuard\Tests;

use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Http;
use JayAnta\AiGuard\AiGuardServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [AiGuardServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Web routes (dashboard) encrypt cookies; canary tokens are HMAC'd with the app key
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));

        // Counters, taint, and verification verdicts live in the cache: give every test its own,
        // instead of a file store shared by the whole suite (and by previous runs)
        $app['config']->set('cache.default', 'array');

        $app['config']->set('ai-guard.enabled', true);
        $app['config']->set('ai-guard.mode', 'log_only');
    }

    protected function defineDatabaseMigrations(): void
    {
        // Run the package's own migrations so tests always match the shipped schema.
        // Plain migrate (no rollback on teardown) — the in-memory database is discarded anyway.
        $this->artisan('migrate', [
            '--path' => realpath(__DIR__.'/../database/migrations'),
            '--realpath' => true,
        ])->run();
    }

    protected function setUp(): void
    {
        parent::setUp();

        // No test may reach a real ML provider, key directory, or webhook
        Http::preventStrayRequests();
    }

    /**
     * Drop resolved AI Guard singletons so the next resolution reads the current config.
     */
    protected function refreshAiGuard(): void
    {
        foreach (AiGuardServiceProvider::SINGLETONS as $abstract) {
            $this->app->forgetInstance($abstract);
        }

        Facade::clearResolvedInstance('ai-guard');
    }
}
