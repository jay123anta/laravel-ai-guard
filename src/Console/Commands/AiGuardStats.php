<?php

namespace JayAnta\AiGuard\Console\Commands;

use Illuminate\Console\Command;
use JayAnta\AiGuard\Models\AiThreatLog;

class AiGuardStats extends Command
{
    protected $signature = 'ai-guard:stats {--hours=24 : Number of hours to look back}';

    protected $description = 'Display AI Guard threat detection statistics';

    public function handle(): int
    {
        $hours = (int) $this->option('hours');

        $stats = AiThreatLog::getThreatSummary($hours);

        $this->info("AI Guard — Threat Statistics (last {$hours} hours)");
        $this->line(str_repeat('─', 50));

        $this->table(['Metric', 'Count'], [
            ['Total Threats Detected', $stats['total']],
            ['AI Crawlers', $stats['ai_crawlers']],
            ['Prompt Injections', $stats['prompt_injections']],
            ['Data Harvesters', $stats['data_harvesters']],
            ['Requests Blocked', $stats['blocked']],
            ['Requests Rate Limited', $stats['rate_limited']],
        ]);

        $this->line('');
        $this->info('Top Threat IPs:');
        $topIps = AiThreatLog::getTopIps(5, $hours);
        if ($topIps->isEmpty()) {
            $this->line('  No threats detected.');
        } else {
            $this->table(
                ['IP Address', 'Hits', 'Max Confidence'],
                $topIps->map(fn ($r) => [$r->ip_address, $r->total, $r->confidence_score])
            );
        }

        $this->line('');
        $this->info('Top Threat Sources:');
        $topSources = AiThreatLog::getTopSources(5, $hours);
        if ($topSources->isEmpty()) {
            $this->line('  No threats detected.');
        } else {
            $this->table(
                ['Source', 'Hits'],
                $topSources->map(fn ($r) => [$r->threat_source ?? 'Unknown', $r->total])
            );
        }

        $this->line('');
        $this->info('Confidence Breakdown:');
        $breakdown = AiThreatLog::getConfidenceBreakdown($hours);
        $this->table(['Level', 'Count'], [
            ['High (90+)', $breakdown['high']],
            ['Medium (70-89)', $breakdown['medium']],
            ['Low (<70)', $breakdown['low']],
        ]);

        return Command::SUCCESS;
    }
}
