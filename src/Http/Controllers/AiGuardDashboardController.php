<?php

namespace JayAnta\AiGuard\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\View\View;
use JayAnta\AiGuard\Models\AiThreatLog;

class AiGuardDashboardController extends Controller
{
    public function index(): View
    {
        $hours = 24;

        $stats = AiThreatLog::getThreatSummary($hours);

        $recentThreats = AiThreatLog::recent($hours)
            ->notFalsePositive()
            ->orderByDesc('created_at')
            ->limit(20)
            ->get();

        $topSources = AiThreatLog::getTopSources(10, $hours);
        $topIps = AiThreatLog::getTopIps(10, $hours);
        $timeline = AiThreatLog::getTimeline($hours);
        $confidenceBreakdown = AiThreatLog::getConfidenceBreakdown($hours);
        $detectorInfo = app('ai-guard')->getDetectorInfo();

        return view('ai-guard::dashboard', compact(
            'stats',
            'recentThreats',
            'topSources',
            'topIps',
            'timeline',
            'confidenceBreakdown',
            'detectorInfo'
        ));
    }
}
