<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

// Named to sort after create_ai_threat_logs_table when both are published without timestamps
return new class extends Migration
{
    public function up(): void
    {
        $missing = array_filter(
            ['bot_category', 'bot_verification', 'chain_hash'],
            fn (string $column) => ! Schema::hasColumn('ai_threat_logs', $column)
        );

        if ($missing === []) {
            return;
        }

        Schema::table('ai_threat_logs', function (Blueprint $table) use ($missing) {
            if (in_array('bot_category', $missing, true)) {
                // ai_training, ai_search, ai_agents, scrapers, ...
                $table->string('bot_category', 30)->nullable()->after('threat_source');
                $table->index('bot_category');
            }

            if (in_array('bot_verification', $missing, true)) {
                // verified, spoofed, unverified
                $table->string('bot_verification', 20)->nullable()->after('bot_category');
                $table->index('bot_verification');
            }

            if (in_array('chain_hash', $missing, true)) {
                // Tamper-evident audit chain (ai-guard.audit.hash_chain)
                $table->string('chain_hash', 64)->nullable()->after('action_taken');
            }
        });
    }

    public function down(): void
    {
        // Only what up() could have added: dropping all three unconditionally would delete
        // columns this migration never created, and fail on indexes that were never there
        $present = array_filter(
            ['bot_category', 'bot_verification', 'chain_hash'],
            fn (string $column) => Schema::hasColumn('ai_threat_logs', $column)
        );

        if ($present === []) {
            return;
        }

        Schema::table('ai_threat_logs', function (Blueprint $table) use ($present) {
            foreach (['bot_category', 'bot_verification'] as $column) {
                if (in_array($column, $present, true)) {
                    $table->dropIndex([$column]);
                }
            }

            $table->dropColumn(array_values($present));
        });
    }
};
