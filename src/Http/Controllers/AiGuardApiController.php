<?php

namespace JayAnta\AiGuard\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use JayAnta\AiGuard\Models\AiThreatLog;

class AiGuardApiController extends Controller
{
    private const MAX_LIMIT = 200;
    private const MAX_HOURS = 8760; // 1 year
    private const ALLOWED_THREAT_TYPES = ['ai_crawler', 'prompt_injection', 'data_harvester', 'api_abuser'];
    private const ALLOWED_ACTIONS = ['logged', 'blocked', 'rate_limited'];

    public function index(Request $request): JsonResponse
    {
        $hours = $this->validHours($request);
        $limit = $this->validLimit($request);

        $query = AiThreatLog::recent($hours)->notFalsePositive();

        $threatType = $request->query('threat_type');
        if ($threatType && in_array($threatType, self::ALLOWED_THREAT_TYPES, true)) {
            $query->where('threat_type', $threatType);
        }

        $actionTaken = $request->query('action_taken');
        if ($actionTaken && in_array($actionTaken, self::ALLOWED_ACTIONS, true)) {
            $query->where('action_taken', $actionTaken);
        }

        $threats = $query->orderByDesc('created_at')->paginate($limit);

        return response()->json(['data' => $threats, 'status' => 'success']);
    }

    public function stats(Request $request): JsonResponse
    {
        $hours = $this->validHours($request);

        return response()->json([
            'data' => AiThreatLog::getThreatSummary($hours),
            'hours' => $hours,
            'status' => 'success',
        ]);
    }

    public function topSources(Request $request): JsonResponse
    {
        $hours = $this->validHours($request);
        $limit = $this->validLimit($request, 10);

        return response()->json([
            'data' => AiThreatLog::getTopSources($limit, $hours),
            'status' => 'success',
        ]);
    }

    public function topIps(Request $request): JsonResponse
    {
        $hours = $this->validHours($request);
        $limit = $this->validLimit($request, 10);

        return response()->json([
            'data' => AiThreatLog::getTopIps($limit, $hours),
            'status' => 'success',
        ]);
    }

    public function timeline(Request $request): JsonResponse
    {
        $hours = $this->validHours($request);

        return response()->json([
            'data' => AiThreatLog::getTimeline($hours),
            'status' => 'success',
        ]);
    }

    public function show(int $id): JsonResponse
    {
        $threat = AiThreatLog::findOrFail($id);

        return response()->json(['data' => $threat, 'status' => 'success']);
    }

    public function markFalsePositive(int $id): JsonResponse
    {
        $threat = AiThreatLog::findOrFail($id);
        $threat->markAsFalsePositive();

        return response()->json([
            'message' => 'Marked as false positive',
            'status' => 'success',
        ]);
    }

    public function confidenceBreakdown(Request $request): JsonResponse
    {
        $hours = $this->validHours($request);

        return response()->json([
            'data' => AiThreatLog::getConfidenceBreakdown($hours),
            'status' => 'success',
        ]);
    }

    public function detectorInfo(): JsonResponse
    {
        $manager = app('ai-guard');

        return response()->json([
            'data' => $manager->getDetectorInfo(),
            'mode' => $manager->getMode(),
            'enabled' => $manager->isEnabled(),
            'status' => 'success',
        ]);
    }

    public function flush(Request $request): JsonResponse
    {
        // Require explicit confirmation to prevent accidental deletion
        if ($request->query('confirm') !== 'yes') {
            return response()->json([
                'error' => 'Confirmation required',
                'message' => 'Add ?confirm=yes to confirm deletion.',
                'status' => 'error',
            ], 422);
        }

        $hours = $request->query('hours');

        if ($hours !== null) {
            $hours = max(1, min((int) $hours, self::MAX_HOURS));
            $deleted = AiThreatLog::where('created_at', '<', now()->subHours($hours))->delete();
        } else {
            $deleted = AiThreatLog::query()->delete();
        }

        return response()->json([
            'message' => "{$deleted} records deleted",
            'status' => 'success',
        ]);
    }

    private function validHours(Request $request, int $default = 24): int
    {
        return max(1, min((int) $request->query('hours', $default), self::MAX_HOURS));
    }

    private function validLimit(Request $request, int $default = 50): int
    {
        return max(1, min((int) $request->query('limit', $default), self::MAX_LIMIT));
    }
}
