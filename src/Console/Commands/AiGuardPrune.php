<?php

namespace JayAnta\AiGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Services\AuditChain;

class AiGuardPrune extends Command
{
    protected $signature = 'ai-guard:prune
        {--days= : Delete logs older than this many days (default: ai-guard.audit.retention_days)}
        {--dry-run : Count the logs without deleting them}';

    protected $description = 'Delete old threat logs';

    public function handle(AuditChain $chain): int
    {
        $days = $this->option('days') ?? config('ai-guard.audit.retention_days');

        if (! is_numeric($days) || (int) $days < 1) {
            $this->error('Set --days=N or ai-guard.audit.retention_days.');

            return self::FAILURE;
        }

        $days = (int) $days;
        $cutoff = now()->subDays($days);
        $old = fn () => AiThreatLog::query()->where('created_at', '<', $cutoff);
        $count = $old()->count();

        if ($this->option('dry-run')) {
            $this->info("{$count} log(s) older than {$days} days would be deleted.");

            return self::SUCCESS;
        }

        if ($count === 0) {
            $this->info("No logs older than {$days} days.");

            return self::SUCCESS;
        }

        // ai-guard:audit-verify checks the first remaining row against the last deleted one
        if (Schema::hasColumn('ai_threat_logs', 'chain_hash')) {
            $last = $old()->whereNotNull('chain_hash')->orderByDesc('id')->first();
            if ($last !== null) {
                $chain->saveAnchor((int) $last->getKey(), (string) $last->getAttribute('chain_hash'));
            }
        }

        $deleted = 0;
        do {
            $ids = $old()->orderBy('id')->limit(1000)->pluck('id')->all();
            if ($ids !== []) {
                $deleted += AiThreatLog::query()->whereIn('id', $ids)->delete();
            }
        } while ($ids !== []);

        $this->info("Deleted {$deleted} log(s) older than {$days} days.");

        return self::SUCCESS;
    }
}
