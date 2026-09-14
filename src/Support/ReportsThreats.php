<?php

namespace JayAnta\AiGuard\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Events\ThreatDetected;

/**
 * Log a detection and dispatch ThreatDetected from code that runs outside the
 * main middleware (tool calls, MCP, agents). Listener failures never propagate.
 */
trait ReportsThreats
{
    protected function reportThreat(array $result, string $actionTaken = 'logged', ?Request $request = null): void
    {
        $request ??= request();

        app(ThreatLogger::class)->log($request, $result, $actionTaken);

        try {
            ThreatDetected::dispatch($request, $result, $actionTaken);
        } catch (\Throwable $e) {
            Log::warning('AI Guard: ThreatDetected listener threw an exception.', ['error' => $e->getMessage()]);
        }
    }
}
