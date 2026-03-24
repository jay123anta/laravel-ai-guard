<?php

use Illuminate\Support\Facades\Route;
use JayAnta\AiGuard\Http\Controllers\AiGuardDashboardController;

if (config('ai-guard.dashboard.enabled', true)) {
    Route::group([
        'prefix' => config('ai-guard.dashboard.path', 'ai-guard'),
        'middleware' => config('ai-guard.dashboard.middleware', ['web']),
    ], function () {
        Route::get('/', [AiGuardDashboardController::class, 'index'])
            ->name('ai-guard.dashboard');
    });
}
