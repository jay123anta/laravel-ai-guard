<?php

namespace JayAnta\AiGuard\Console\Commands;

use Illuminate\Console\Command;
use JayAnta\AiGuard\Services\AuditChain;

class AiGuardAuditVerify extends Command
{
    protected $signature = 'ai-guard:audit-verify
        {--from= : Start at this log ID}';

    protected $description = 'Check the tamper-evident hash chain of the threat log';

    public function handle(AuditChain $chain): int
    {
        $from = $this->option('from');
        $result = $chain->verify(is_numeric($from) ? (int) $from : null);

        if ($result['broken_at'] !== null) {
            $reason = $result['reason'] ?? "log #{$result['broken_at']} was changed or moved, or a row before it was removed";
            $this->error("The chain is broken at log #{$result['broken_at']}: {$reason}.");
            $this->line("{$result['checked']} row(s) before it verified.");

            return self::FAILURE;
        }

        if ($result['checked'] === 0) {
            $this->warn('No chained log rows found. Set ai-guard.audit.hash_chain to true to start the chain.');

            return self::SUCCESS;
        }

        $this->info("Verified {$result['checked']} log row(s), #{$result['first']} to #{$result['last']}.");

        return self::SUCCESS;
    }
}
