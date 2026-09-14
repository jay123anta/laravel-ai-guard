<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JayAnta\AiGuard\Support\AiPreferences;
use Symfony\Component\HttpFoundation\Response;

/**
 * Adds an IETF AIPREF Content-Usage header (e.g. "train-ai=n") to responses,
 * telling AI crawlers how the content may be used.
 *
 *   Route::middleware('ai-guard.preferences')                         // config value
 *   Route::middleware('ai-guard.preferences:train-ai=n,search=y')     // per route
 */
class AiPreferencesMiddleware
{
    public function handle(Request $request, Closure $next, string ...$preferences): mixed
    {
        $response = $next($request);

        $value = $preferences !== []
            ? implode(', ', array_map('trim', $preferences))
            : config('ai-guard.ai_preferences.content_usage');

        if ($response instanceof Response
            && is_string($value)
            && AiPreferences::isValidContentUsage($value)
            && ! $response->headers->has('Content-Usage')) {
            $response->headers->set('Content-Usage', AiPreferences::normalize($value));
        }

        return $response;
    }
}
