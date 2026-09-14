<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Services\RobotsTxtParser;
use JayAnta\AiGuard\Support\AiPreferences;
use JayAnta\AiGuard\Tests\TestCase;

class AiPreferencesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware('ai-guard.preferences')->get('/from-config', fn () => response('ok'));
        Route::middleware('ai-guard.preferences:train-ai=n,search=y')->get('/per-route', fn () => response('ok'));
        Route::middleware('ai-guard.preferences:train-ai=n')->get('/preset', fn () => response('ok')->header('Content-Usage', 'train-ai=y'));
        Route::middleware('ai-guard.preferences:train-ai=maybe')->get('/invalid', fn () => response('ok'));
    }

    // -------------------------------------------------------------------------
    // Content-Usage response header
    // -------------------------------------------------------------------------

    public function test_header_comes_from_config(): void
    {
        $this->get('/from-config')->assertHeaderMissing('Content-Usage');

        config()->set('ai-guard.ai_preferences.content_usage', 'Train-AI = N');
        $this->get('/from-config')->assertHeader('Content-Usage', 'train-ai=n');
    }

    public function test_route_parameters_override_config(): void
    {
        config()->set('ai-guard.ai_preferences.content_usage', 'train-ai=y');

        $this->get('/per-route')->assertHeader('Content-Usage', 'train-ai=n, search=y');
    }

    public function test_existing_header_is_not_overwritten(): void
    {
        $this->get('/preset')->assertHeader('Content-Usage', 'train-ai=y');
    }

    public function test_invalid_values_are_not_sent(): void
    {
        $this->get('/invalid')->assertHeaderMissing('Content-Usage');
    }

    public function test_value_validation(): void
    {
        $this->assertTrue(AiPreferences::isValidContentUsage('train-ai=n'));
        $this->assertTrue(AiPreferences::isValidContentUsage('train-ai=n, search=y'));
        $this->assertFalse(AiPreferences::isValidContentUsage('train-ai=no'));
        $this->assertFalse(AiPreferences::isValidContentUsage('train-ai'));

        $this->assertTrue(AiPreferences::isValidContentSignal('search=yes, ai-input=yes, ai-train=no'));
        $this->assertFalse(AiPreferences::isValidContentSignal('ai-train=n'));
    }

    // -------------------------------------------------------------------------
    // robots.txt generator
    // -------------------------------------------------------------------------

    public function test_robots_txt_includes_preferences_from_options(): void
    {
        $this->withoutMockingConsoleOutput();

        $exit = Artisan::call('ai-guard:robots-txt', [
            '--categories' => 'ai_training',
            '--content-usage' => 'train-ai=n',
            '--content-signal' => 'search=yes, ai-input=yes, ai-train=no',
        ]);
        $output = Artisan::output();

        $this->assertSame(0, $exit);
        $this->assertStringContainsString("User-agent: *\nAllow: /\n", $output);
        $this->assertStringContainsString("\nContent-Usage: train-ai=n\n", $output);
        $this->assertStringContainsString("\nContent-Signal: search=yes, ai-input=yes, ai-train=no\n", $output);

        // The extra directives don't disturb Allow/Disallow semantics
        $robots = substr($output, (int) strpos($output, '# ===='));
        $parser = new RobotsTxtParser($robots);
        $this->assertFalse($parser->isAllowed('GPTBot', '/articles'));
        $this->assertTrue($parser->isAllowed('SomeBrowserBot', '/articles'));
    }

    public function test_robots_txt_uses_config_defaults(): void
    {
        config()->set('ai-guard.ai_preferences.content_usage', 'train-ai=n');
        $this->withoutMockingConsoleOutput();

        Artisan::call('ai-guard:robots-txt', ['--categories' => 'ai_training']);

        $this->assertStringContainsString('Content-Usage: train-ai=n', Artisan::output());
    }

    public function test_robots_txt_omits_preferences_by_default(): void
    {
        $this->withoutMockingConsoleOutput();

        Artisan::call('ai-guard:robots-txt');
        $output = Artisan::output();

        $this->assertStringNotContainsString('Content-Usage:', $output);
        $this->assertStringNotContainsString('Content-Signal:', $output);
    }

    public function test_robots_txt_rejects_invalid_preferences(): void
    {
        $this->artisan('ai-guard:robots-txt', ['--content-usage' => 'train-ai=maybe'])
            ->expectsOutputToContain('Invalid Content-Usage value')
            ->assertExitCode(1);

        $this->artisan('ai-guard:robots-txt', ['--content-signal' => 'ai-train=n'])
            ->expectsOutputToContain('Invalid Content-Signal value')
            ->assertExitCode(1);
    }
}
