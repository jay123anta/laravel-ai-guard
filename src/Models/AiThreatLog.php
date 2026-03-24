<?php

namespace JayAnta\AiGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

class AiThreatLog extends Model
{
    protected $table = 'ai_threat_logs';

    protected $fillable = [
        'ip_address',
        'user_agent',
        'threat_type',
        'threat_source',
        'confidence_score',
        'request_url',
        'request_method',
        'matched_pattern',
        'payload_snippet',
        'headers_snapshot',
        'action_taken',
        'is_false_positive',
        'country_code',
    ];

    protected $casts = [
        'headers_snapshot' => 'array',
        'is_false_positive' => 'boolean',
        'confidence_score' => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    // -------------------------------------------------------------------------
    // Query Scopes
    // -------------------------------------------------------------------------

    public function scopeAiCrawlers(Builder $query): Builder
    {
        return $query->where('threat_type', 'ai_crawler');
    }

    public function scopePromptInjections(Builder $query): Builder
    {
        return $query->where('threat_type', 'prompt_injection');
    }

    public function scopeDataHarvesters(Builder $query): Builder
    {
        return $query->where('threat_type', 'data_harvester');
    }

    public function scopeBlocked(Builder $query): Builder
    {
        return $query->where('action_taken', 'blocked');
    }

    public function scopeRateLimited(Builder $query): Builder
    {
        return $query->where('action_taken', 'rate_limited');
    }

    public function scopeHighConfidence(Builder $query, int $threshold = 70): Builder
    {
        return $query->where('confidence_score', '>=', $threshold);
    }

    public function scopeRecent(Builder $query, int $hours = 24): Builder
    {
        return $query->where('created_at', '>=', now()->subHours($hours));
    }

    public function scopeByIp(Builder $query, string $ip): Builder
    {
        return $query->where('ip_address', $ip);
    }

    public function scopeNotFalsePositive(Builder $query): Builder
    {
        return $query->where('is_false_positive', false);
    }

    // -------------------------------------------------------------------------
    // Static Stats Methods
    // -------------------------------------------------------------------------

    public static function getThreatSummary(int $hours = 24): array
    {
        $query = static::where('created_at', '>=', now()->subHours($hours));

        return [
            'total' => (clone $query)->count(),
            'ai_crawlers' => (clone $query)->where('threat_type', 'ai_crawler')->count(),
            'prompt_injections' => (clone $query)->where('threat_type', 'prompt_injection')->count(),
            'data_harvesters' => (clone $query)->where('threat_type', 'data_harvester')->count(),
            'blocked' => (clone $query)->where('action_taken', 'blocked')->count(),
            'rate_limited' => (clone $query)->where('action_taken', 'rate_limited')->count(),
        ];
    }

    public static function getTopIps(int $limit = 10, int $hours = 24): Collection
    {
        return static::where('created_at', '>=', now()->subHours($hours))
            ->select('ip_address', DB::raw('COUNT(*) as total'), DB::raw('MAX(confidence_score) as confidence_score'))
            ->groupBy('ip_address')
            ->orderByDesc('total')
            ->limit($limit)
            ->get();
    }

    public static function getTopSources(int $limit = 10, int $hours = 24): Collection
    {
        return static::where('created_at', '>=', now()->subHours($hours))
            ->select('threat_source', DB::raw('COUNT(*) as total'))
            ->groupBy('threat_source')
            ->orderByDesc('total')
            ->limit($limit)
            ->get();
    }

    public static function getTimeline(int $hours = 24): Collection
    {
        $driver = DB::getDriverName();

        $hourExpression = match ($driver) {
            'sqlite' => "strftime('%Y-%m-%d %H:00:00', created_at)",
            'pgsql' => "to_char(created_at, 'YYYY-MM-DD HH24:00:00')",
            default => "DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00')",
        };

        return static::where('created_at', '>=', now()->subHours($hours))
            ->select(DB::raw("{$hourExpression} as hour"), DB::raw('COUNT(*) as total'))
            ->groupBy('hour')
            ->orderBy('hour')
            ->get();
    }

    public static function getConfidenceBreakdown(int $hours = 24): array
    {
        $query = static::where('created_at', '>=', now()->subHours($hours));

        return [
            'high' => (clone $query)->where('confidence_score', '>=', 90)->count(),
            'medium' => (clone $query)->whereBetween('confidence_score', [70, 89])->count(),
            'low' => (clone $query)->where('confidence_score', '<', 70)->count(),
        ];
    }

    // -------------------------------------------------------------------------
    // Instance Methods
    // -------------------------------------------------------------------------

    public function markAsFalsePositive(): bool
    {
        $this->is_false_positive = true;

        return $this->save();
    }

    public function isHighConfidence(int $threshold = 70): bool
    {
        return $this->confidence_score >= $threshold;
    }

    public function getActionLabel(): string
    {
        return match ($this->action_taken) {
            'blocked' => 'Blocked',
            'rate_limited' => 'Rate Limited',
            'logged' => 'Logged Only',
            default => ucfirst($this->action_taken),
        };
    }

    public function getThreatTypeLabel(): string
    {
        return match ($this->threat_type) {
            'ai_crawler' => 'AI Crawler',
            'prompt_injection' => 'Prompt Injection',
            'data_harvester' => 'Data Harvester',
            'api_abuser' => 'API Abuser',
            default => ucfirst($this->threat_type ?? 'Unknown'),
        };
    }
}
