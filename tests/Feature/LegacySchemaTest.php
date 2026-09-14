<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Tests\TestCase;

/**
 * An app that upgraded the package but hasn't run the v3 upgrade migration yet.
 */
class LegacySchemaTest extends TestCase
{
    protected function defineDatabaseMigrations(): void
    {
        // Only the v2 create migration — no bot_category / bot_verification columns
        $this->artisan('migrate', [
            '--path' => realpath(__DIR__.'/../../database/migrations/create_ai_threat_logs_table.php'),
            '--realpath' => true,
        ])->run();
    }

    public function test_threats_are_still_logged_on_a_v2_schema(): void
    {
        $this->assertFalse(Schema::hasColumn('ai_threat_logs', 'bot_category'));

        Log::spy();
        Route::middleware(AiGuardMiddleware::class)->get('/page', fn () => response('ok'));

        $this->withHeaders(['User-Agent' => 'GPTBot/1.1', 'Accept-Language' => 'en'])->get('/page')->assertOk();
        $this->withHeaders(['User-Agent' => 'ClaudeBot/1.0', 'Accept-Language' => 'en'])->get('/page')->assertOk();

        $this->assertSame(2, AiThreatLog::count());
        $this->assertSame('ai_crawler', AiThreatLog::first()->threat_type);

        // Warned once, not once per request
        Log::shouldHaveReceived('warning')
            ->withArgs(fn (string $message) => str_contains($message, 'missing the v3 columns'))
            ->atMost()->once();
    }
}
