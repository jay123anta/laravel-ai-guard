<?php

namespace JayAnta\AiGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Content-Security-Policy for pages that show model output, so an injection that slips
 * past rendering still cannot run script or load images from arbitrary hosts:
 *
 *   Route::get('/chat', ...)->middleware('ai-guard.csp');              // enforce
 *   Route::get('/chat', ...)->middleware('ai-guard.csp:report-only');  // try it first
 *
 * Use @aiNonce (or AiGuard::cspNonce()) on your own <script nonce="..."> tags.
 */
class ContentSecurityPolicyMiddleware
{
    public const DEFAULT_DIRECTIVES = [
        'default-src' => ["'self'"],
        'script-src' => ["'self'", "'nonce-{nonce}'"],
        'style-src' => ["'self'", "'unsafe-inline'"],
        'img-src' => ["'self'", 'data:', '{allowed_domains}'],
        'connect-src' => ["'self'"],
        'object-src' => ["'none'"],
        'base-uri' => ["'none'"],
        'form-action' => ["'self'"],
        'frame-ancestors' => ["'self'"],
    ];

    public function handle(Request $request, Closure $next, ?string $mode = null): mixed
    {
        $nonce = app('ai-guard')->cspNonce();

        // Vite-rendered script tags get the same nonce
        if (class_exists(\Illuminate\Foundation\Vite::class) && app()->bound(\Illuminate\Foundation\Vite::class)) {
            app(\Illuminate\Foundation\Vite::class)->useCspNonce($nonce);
        }

        $response = $next($request);

        if (! $response instanceof Response) {
            return $response;
        }

        $reportOnly = $mode === 'report-only' || ($mode === null && (bool) config('ai-guard.llm_guard.csp.report_only', false));
        $header = $reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

        if (! $response->headers->has($header)) {
            $response->headers->set($header, $this->policy($nonce));
        }

        return $response;
    }

    public function policy(string $nonce): string
    {
        // Configured directives are merged onto the defaults, so adding one (say connect-src for
        // a streaming endpoint) does not quietly drop object-src 'none' and base-uri 'none'.
        // Set a directive to null to leave it out of the policy.
        $configured = config('ai-guard.llm_guard.csp.directives');
        $directives = array_filter(
            is_array($configured) ? array_merge(self::DEFAULT_DIRECTIVES, $configured) : self::DEFAULT_DIRECTIVES,
            fn ($sources) => $sources !== null && $sources !== false && $sources !== [],
        );

        $hosts = [];
        foreach ((array) config('ai-guard.llm_guard.allowed_domains', []) as $domain) {
            $domain = trim((string) $domain, '. ');
            if ($domain !== '') {
                array_push($hosts, 'https://'.$domain, 'https://*.'.$domain);
            }
        }

        $parts = [];
        foreach ($directives as $name => $sources) {
            $list = [];
            foreach ((array) $sources as $source) {
                if ($source === '{allowed_domains}') {
                    array_push($list, ...$hosts);

                    continue;
                }
                $list[] = str_replace('{nonce}', $nonce, (string) $source);
            }
            $parts[] = trim($name.' '.implode(' ', array_unique($list)));
        }

        $reportUri = config('ai-guard.llm_guard.csp.report_uri');
        if (is_string($reportUri) && $reportUri !== '') {
            $parts[] = 'report-uri '.$reportUri;
        }

        return implode('; ', $parts);
    }
}
