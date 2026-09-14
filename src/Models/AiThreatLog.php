<?php

namespace JayAnta\AiGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use JayAnta\AiGuard\Services\BotSignatures;

/**
 * @property int $id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string|null $threat_type
 * @property string|null $threat_source
 * @property string|null $bot_category
 * @property string|null $bot_verification
 * @property int $confidence_score
 * @property string|null $request_url
 * @property string|null $request_method
 * @property string|null $matched_pattern
 * @property string|null $payload_snippet
 * @property array|null $headers_snapshot
 * @property string|null $action_taken
 * @property bool $is_false_positive
 * @property string|null $country_code
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 * @property-read int|null $total Aggregate alias from getTopIps()/getTopSources()/getTimeline()
 */
class AiThreatLog extends Model
{
    protected $table = 'ai_threat_logs';

    protected $fillable = [
        'ip_address',
        'user_agent',
        'threat_type',
        'threat_source',
        'bot_category',
        'bot_verification',
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

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeAiCrawlers(Builder $query): Builder
    {
        return $query->where('threat_type', 'ai_crawler');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopePromptInjections(Builder $query): Builder
    {
        return $query->where('threat_type', 'prompt_injection');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeDataHarvesters(Builder $query): Builder
    {
        return $query->where('threat_type', 'data_harvester');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeBlocked(Builder $query): Builder
    {
        return $query->where('action_taken', 'blocked');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeRateLimited(Builder $query): Builder
    {
        return $query->where('action_taken', 'rate_limited');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeHighConfidence(Builder $query, int $threshold = 70): Builder
    {
        return $query->where('confidence_score', '>=', $threshold);
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeRecent(Builder $query, int $hours = 24): Builder
    {
        return $query->where('created_at', '>=', now()->subHours($hours));
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeByIp(Builder $query, string $ip): Builder
    {
        return $query->where('ip_address', $ip);
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
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
            'honeypot_traps' => (clone $query)->where('threat_type', 'honeypot_trap')->count(),
            'pii_leaks' => (clone $query)->where('threat_type', 'pii_leak')->count(),
            'bad_bots' => (clone $query)->where('threat_type', 'bad_bot')->count(),
            'scrapers' => (clone $query)->where('threat_type', 'scraper')->count(),
            'ai_training_crawlers' => (clone $query)->where('bot_category', 'ai_training')->count(),
            'ai_search_crawlers' => (clone $query)->where('bot_category', 'ai_search')->count(),
            'ai_agents' => (clone $query)->where('bot_category', 'ai_agents')->count(),
            'spoofed_bots' => (clone $query)->where('bot_verification', 'spoofed')->count(),
            'blocked' => (clone $query)->where('action_taken', 'blocked')->count(),
            'rate_limited' => (clone $query)->where('action_taken', 'rate_limited')->count(),
        ];
    }

    /**
     * @return Collection<int, AiThreatLog>
     */
    public static function getTopIps(int $limit = 10, int $hours = 24): Collection
    {
        return static::where('created_at', '>=', now()->subHours($hours))
            ->select('ip_address', DB::raw('COUNT(*) as total'), DB::raw('MAX(confidence_score) as confidence_score'))
            ->groupBy('ip_address')
            ->orderByDesc('total')
            ->limit($limit)
            ->get();
    }

    /**
     * @return Collection<int, AiThreatLog>
     */
    public static function getTopSources(int $limit = 10, int $hours = 24): Collection
    {
        return static::where('created_at', '>=', now()->subHours($hours))
            ->select('threat_source', DB::raw('COUNT(*) as total'))
            ->groupBy('threat_source')
            ->orderByDesc('total')
            ->limit($limit)
            ->get();
    }

    /**
     * @return Collection<int, AiThreatLog>
     */
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
            'honeypot_trap' => 'Honeypot Trap',
            'pii_leak' => 'PII Leak',
            'robots_txt_violation' => 'Robots.txt Violation',
            'suspicious_fingerprint' => 'Suspicious Fingerprint',
            'seo_bot' => 'SEO Bot',
            'scraper' => 'Web Scraper',
            'bad_bot' => 'Malicious Bot',
            'search_engine' => 'Search Engine',
            'spoofed_bot' => 'Spoofed Bot',
            'indirect_prompt_injection' => 'Indirect Prompt Injection',
            'llm_output_threat' => 'LLM Output Threat',
            'tool_injection' => 'Tool Injection',
            'system_prompt_leak' => 'System Prompt Leak',
            'llm_budget_exceeded' => 'AI Budget Exceeded',
            'content_moderation' => 'Harmful Content',
            'denied_topic' => 'Denied Topic',
            'multi_turn_attack' => 'Multi-Turn Attack',
            'tool_call_blocked' => 'Tool Call Blocked',
            'tool_call_held' => 'Tool Call Held for Approval',
            'mcp_tool_changed' => 'MCP Tool Changed',
            'mcp_server_blocked' => 'MCP Server Blocked',
            'unsafe_sql' => 'Unsafe SQL',
            'ai_agent_denied' => 'AI Agent Denied',
            default => ucfirst(str_replace('_', ' ', $this->threat_type ?? 'Unknown')),
        };
    }

    public function getBotCategoryLabel(): ?string
    {
        if ($this->bot_category === null) {
            return null;
        }

        return BotSignatures::getCategories()[$this->bot_category]['label']
            ?? ucfirst(str_replace('_', ' ', $this->bot_category));
    }

    public function getVerificationLabel(): ?string
    {
        return match ($this->bot_verification) {
            'verified' => 'Verified',
            'spoofed' => 'Spoofed',
            'unverified' => 'Unverified',
            null => null,
            default => ucfirst($this->bot_verification),
        };
    }

    // -------------------------------------------------------------------------
    // v2 Scopes
    // -------------------------------------------------------------------------

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeHoneypotTraps(Builder $query): Builder
    {
        return $query->where('threat_type', 'honeypot_trap');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopePiiLeaks(Builder $query): Builder
    {
        return $query->where('threat_type', 'pii_leak');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeBadBots(Builder $query): Builder
    {
        return $query->where('threat_type', 'bad_bot');
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeScrapers(Builder $query): Builder
    {
        return $query->where('threat_type', 'scraper');
    }

    // -------------------------------------------------------------------------
    // v3 Scopes
    // -------------------------------------------------------------------------

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeBotCategory(Builder $query, string $category): Builder
    {
        return $query->where('bot_category', $category);
    }

    /**
     * @param  Builder<AiThreatLog>  $query
     * @return Builder<AiThreatLog>
     */
    public function scopeSpoofedBots(Builder $query): Builder
    {
        return $query->where('bot_verification', 'spoofed');
    }
}
