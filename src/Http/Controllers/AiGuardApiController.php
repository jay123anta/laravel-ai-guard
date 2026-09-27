<?php

namespace JayAnta\AiGuard\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AuditChain;
use JayAnta\AiGuard\Services\BotSignatures;

class AiGuardApiController extends Controller
{
    private const MAX_LIMIT = 200;

    private const MAX_HOURS = 8760; // 1 year

    private const ALLOWED_THREAT_TYPES = [
        'ai_crawler', 'prompt_injection', 'data_harvester', 'api_abuser',
        'honeypot_trap', 'pii_leak', 'robots_txt_violation', 'suspicious_fingerprint',
        'seo_bot', 'scraper', 'bad_bot', 'search_engine',
        'spoofed_bot', 'indirect_prompt_injection', 'llm_output_threat', 'tool_injection', 'system_prompt_leak',
        'llm_budget_exceeded', 'content_moderation', 'denied_topic', 'multi_turn_attack',
        'tool_call_blocked', 'tool_call_held', 'mcp_tool_changed', 'mcp_server_blocked', 'unsafe_sql',
        'ai_agent_denied',
    ];

    private const ALLOWED_ACTIONS = ['logged', 'blocked', 'rate_limited'];

    private const ALLOWED_VERIFICATIONS = ['verified', 'spoofed', 'unverified'];

    public function index(Request $request): JsonResponse
    {
        $hours = $this->validHours($request);
        $limit = $this->validLimit($request);

        $query = AiThreatLog::recent($hours)->notFalsePositive();

        $threatType = $request->query('threat_type');
        if (is_string($threatType) && in_array($threatType, self::ALLOWED_THREAT_TYPES, true)) {
            $query->where('threat_type', $threatType);
        }

        $botCategory = $request->query('bot_category');
        if (is_string($botCategory) && array_key_exists($botCategory, BotSignatures::getCategories())) {
            $query->where('bot_category', $botCategory);
        }

        $verification = $request->query('bot_verification');
        if (is_string($verification) && in_array($verification, self::ALLOWED_VERIFICATIONS, true)) {
            $query->where('bot_verification', $verification);
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

    public function flush(Request $request, AuditChain $chain): JsonResponse
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
            $rows = AiThreatLog::query()->where('created_at', '<', now()->subHours($hours));
        } else {
            $rows = AiThreatLog::query();
        }

        // A flush is a deliberate deletion: record it like a prune, so the audit chain still
        // verifies afterwards while a deletion made directly in the database does not
        $chain->anchorDeletion($rows);
        $deleted = $rows->delete();

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
