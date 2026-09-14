<?php

namespace JayAnta\AiGuard\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property string $server
 * @property string $tool
 * @property string $status approved | pending
 * @property string|null $approved_hash
 * @property array|null $approved_definition
 * @property string|null $pending_hash
 * @property array|null $pending_definition
 * @property \Illuminate\Support\Carbon|null $approved_at
 * @property \Illuminate\Support\Carbon|null $last_seen_at
 */
class McpToolPin extends Model
{
    protected $table = 'ai_guard_mcp_pins';

    protected $fillable = [
        'server',
        'tool',
        'status',
        'approved_hash',
        'approved_definition',
        'pending_hash',
        'pending_definition',
        'approved_at',
        'last_seen_at',
    ];

    protected $casts = [
        'approved_definition' => 'array',
        'pending_definition' => 'array',
        'approved_at' => 'datetime',
        'last_seen_at' => 'datetime',
    ];
}
