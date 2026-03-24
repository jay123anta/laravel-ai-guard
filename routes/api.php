<?php

use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Http\Controllers\AiGuardApiController;

if (config('ai-guard.api.enabled', true)) {
    Route::group([
        'prefix' => config('ai-guard.api.prefix', 'ai-guard'),
        'middleware' => config('ai-guard.api.middleware', ['api']),
        'controller' => AiGuardApiController::class,
    ], function () {
        Route::get('/api/threats', 'index');
        Route::get('/api/stats', 'stats');
        Route::get('/api/top-sources', 'topSources');
        Route::get('/api/top-ips', 'topIps');
        Route::get('/api/timeline', 'timeline');
        Route::get('/api/confidence-breakdown', 'confidenceBreakdown');
        Route::get('/api/detector-info', 'detectorInfo');
        Route::get('/api/threats/{id}', 'show');
        Route::post('/api/threats/{id}/false-positive', 'markFalsePositive');
        Route::delete('/api/flush', 'flush');
    });
}
