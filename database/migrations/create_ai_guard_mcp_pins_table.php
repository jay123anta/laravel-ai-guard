<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

// Approved MCP tool definitions, for rug-pull detection
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('ai_guard_mcp_pins')) {
            return;
        }

        Schema::create('ai_guard_mcp_pins', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->string('server', 255);
            $table->string('tool', 255);
            $table->string('status', 20)->default('approved');
            $table->string('approved_hash', 64)->nullable();
            $table->json('approved_definition')->nullable();
            $table->string('pending_hash', 64)->nullable();
            $table->json('pending_definition')->nullable();
            $table->timestamp('approved_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamps();

            $table->unique(['server', 'tool']);
            $table->index('status');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ai_guard_mcp_pins');
    }
};
