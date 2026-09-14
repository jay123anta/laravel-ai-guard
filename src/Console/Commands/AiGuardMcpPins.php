<?php

namespace JayAnta\AiGuard\Console\Commands;

use Illuminate\Console\Command;
use JayAnta\AiGuard\Models\McpToolPin;
use JayAnta\AiGuard\Services\McpGuard;

class AiGuardMcpPins extends Command
{
    protected $signature = 'ai-guard:mcp-pins
        {action=list : list | approve | forget}
        {server? : MCP server URL or name}
        {tool? : A single tool (default: every tool of the server)}';

    protected $description = 'List, approve, or forget pinned MCP tool definitions';

    public function handle(McpGuard $guard): int
    {
        $action = (string) $this->argument('action');
        $server = $this->argument('server');
        $tool = $this->argument('tool');

        if ($action === 'list') {
            $pins = McpToolPin::query()
                ->when(is_string($server), fn ($query) => $query->where('server', $server))
                ->orderBy('server')->orderBy('tool')->get();

            if ($pins->isEmpty()) {
                $this->line('No pinned MCP tools.');

                return Command::SUCCESS;
            }

            $this->table(['Server', 'Tool', 'Status', 'Approved hash', 'Last seen'], $pins->map(fn (McpToolPin $pin) => [
                $pin->server,
                $pin->tool,
                $pin->status === 'pending' ? ($pin->approved_hash === null ? 'pending (new)' : 'pending (changed)') : 'approved',
                $pin->approved_hash !== null ? substr($pin->approved_hash, 0, 12) : '—',
                $pin->last_seen_at?->toDateTimeString() ?? '—',
            ]));

            return Command::SUCCESS;
        }

        if (! is_string($server) || $server === '') {
            $this->error("Name the server: php artisan ai-guard:mcp-pins {$action} <server> [tool]");

            return Command::FAILURE;
        }

        $tool = is_string($tool) ? $tool : null;

        if ($action === 'approve') {
            $count = $guard->approve($server, $tool);
            $this->info("Approved {$count} tool definition(s) for {$server}.");

            return Command::SUCCESS;
        }

        if ($action === 'forget') {
            $count = $guard->forget($server, $tool);
            $this->info("Forgot {$count} pinned tool(s) for {$server}.");

            return Command::SUCCESS;
        }

        $this->error("Unknown action \"{$action}\" — use list, approve, or forget.");

        return Command::FAILURE;
    }
}
