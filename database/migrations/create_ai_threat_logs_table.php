<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ai_threat_logs', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->string('threat_type', 50);
            $table->string('threat_source', 100)->nullable();
            $table->unsignedTinyInteger('confidence_score')->default(0);
            $table->text('request_url')->nullable();
            $table->string('request_method', 10)->nullable();
            $table->string('matched_pattern', 255)->nullable();
            $table->text('payload_snippet')->nullable();
            $table->json('headers_snapshot')->nullable();
            $table->string('action_taken', 20)->default('logged');
            $table->boolean('is_false_positive')->default(false);
            $table->string('country_code', 2)->nullable();
            $table->timestamp('created_at')->nullable();
            $table->timestamp('updated_at')->nullable();

            $table->index('ip_address');
            $table->index('threat_type');
            $table->index('action_taken');
            $table->index('created_at');
            $table->index('confidence_score');

            // Composite indexes for dashboard and API query patterns
            $table->index(['created_at', 'threat_type']);
            $table->index(['created_at', 'is_false_positive']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ai_threat_logs');
    }
};
