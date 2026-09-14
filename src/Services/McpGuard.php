<?php

namespace JayAnta\AiGuard\Services;

use JayAnta\AiGuard\Models\McpToolPin;
use JayAnta\AiGuard\Support\CanonicalJson;
use JayAnta\AiGuard\Support\ReportsThreats;
use JayAnta\AiGuard\Support\UrlHost;

/**
 * Guards the MCP servers an app consumes: a server allow-list, pinning of every
 * tool definition (so a definition that changes after approval — a "rug pull" —
 * is caught), and scanning of definitions for tool poisoning.
 *
 * Tools may be laravel/mcp client tools (objects with name/description/inputSchema)
 * or plain arrays with the same keys.
 */
class McpGuard
{
    use ReportsThreats;

    public const PINNED = 'pinned';

    public const UNCHANGED = 'unchanged';

    public const CHANGED = 'changed';

    public const NEW = 'new';

    private array $config;

    private ToolCallScanner $scanner;

    public function __construct(array $config, ToolCallScanner $scanner)
    {
        $this->config = $config;
        $this->scanner = $scanner;
    }

    public function isServerAllowed(string $server): bool
    {
        $allowed = (array) ($this->option('allowed_servers') ?? []);
        if ($allowed === []) {
            return true;
        }

        $host = UrlHost::host($server);

        foreach ($allowed as $entry) {
            $entry = (string) $entry;

            if ($entry === $server || ($host !== null && $host !== '' && strtolower($entry) === $host)) {
                return true;
            }

            // A prefix must end at a host or path boundary: "https://mcp.example.com*" is the
            // natural way to write "that server and its paths", and it must not also admit
            // https://mcp.example.com.evil.test/mcp
            if (str_ends_with($entry, '*')) {
                $prefix = rtrim($entry, '*');
                $next = substr($server, strlen($prefix), 1);

                if (str_starts_with($server, $prefix) && ($next === '' || $next === '/' || $next === ':' || $next === '?' || str_ends_with($prefix, '/'))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The tools that are safe to hand to an agent: server allowed, definition pinned
     * and unchanged, and not poisoned. Everything dropped is logged.
     *
     * @param  iterable<mixed>  $tools
     * @return array<int, mixed>
     */
    public function guard(string $server, iterable $tools): array
    {
        if (! $this->isServerAllowed($server)) {
            $this->reportThreat([
                'detected' => true,
                'threat_type' => 'mcp_server_blocked',
                'threat_source' => mb_substr($server, 0, 100),
                'confidence_score' => 90,
                'matched_pattern' => 'MCP server is not on the allow-list',
            ], 'blocked');

            return [];
        }

        $tools = is_array($tools) ? array_values($tools) : iterator_to_array($tools, false);
        $usable = [];
        $seen = [];

        foreach ($tools as $tool) {
            $definition = $this->definition($tool);
            $name = $definition['name'];

            // A tool the pins cannot address, or a second tool answering to a name already
            // taken, is dropped: either would let an unpinned definition reach the agent
            if (! self::isUsableName($name) || isset($seen[$name])) {
                $this->reportThreat([
                    'detected' => true,
                    'threat_type' => 'mcp_tool_rejected',
                    'threat_source' => mb_substr($server, 0, 100),
                    'confidence_score' => 80,
                    'matched_pattern' => isset($seen[$name])
                        ? mb_substr("two tools named {$name}", 0, 255)
                        : 'a tool without a usable name',
                    'payload_snippet' => mb_substr($name, 0, 500),
                ], 'blocked');

                continue;
            }

            $seen[$name] = true;
            $usable[] = [$tool, $definition];
        }

        $statuses = ($this->option('pinning') ?? true) ? $this->pin($server, array_column($usable, 0)) : [];
        $blockChanges = ($this->option('on_change') ?? 'block') === 'block';
        $safe = [];

        foreach ($usable as [$tool, $definition]) {
            $status = $statuses[$definition['name']] ?? self::UNCHANGED;

            if ($status === self::CHANGED || $status === self::NEW) {
                $this->reportThreat([
                    'detected' => true,
                    'threat_type' => 'mcp_tool_changed',
                    'threat_source' => mb_substr($server, 0, 100),
                    'confidence_score' => $status === self::CHANGED ? 90 : 60,
                    'matched_pattern' => mb_substr("{$definition['name']}: definition {$status} since approval", 0, 255),
                ], $blockChanges ? 'blocked' : 'logged');

                if ($blockChanges) {
                    continue;
                }
            }

            if ($this->option('scan_definitions') ?? true) {
                $scan = $this->scanner->scan($definition, 'definition');
                if ($scan['detected']) {
                    $scan['threat_source'] = mb_substr($server.' '.$definition['name'], 0, 100);
                    $this->reportThreat($scan, 'blocked');

                    continue;
                }
            }

            $safe[] = $tool;
        }

        return $safe;
    }

    /**
     * Compare each tool with its pinned definition.
     *
     * @param  iterable<mixed>  $tools
     * @return array<string, string> tool name => pinned | unchanged | changed | new
     */
    public function pin(string $server, iterable $tools): array
    {
        $existing = McpToolPin::where('server', $server)->get()->keyBy('tool');
        $firstSight = $existing->isEmpty();
        $trustFirstUse = (bool) ($this->option('trust_on_first_use') ?? true);
        $statuses = [];
        $now = now();

        foreach ($tools as $tool) {
            $definition = $this->definition($tool);
            $hash = self::fingerprint($definition);
            $pin = $existing->get($definition['name']);

            if ($pin === null) {
                $approve = $firstSight && $trustFirstUse;
                McpToolPin::create([
                    'server' => $server,
                    'tool' => $definition['name'],
                    'status' => $approve ? 'approved' : 'pending',
                    'approved_hash' => $approve ? $hash : null,
                    'approved_definition' => $approve ? $definition : null,
                    'pending_hash' => $approve ? null : $hash,
                    'pending_definition' => $approve ? null : $definition,
                    'approved_at' => $approve ? $now : null,
                    'last_seen_at' => $now,
                ]);
                $statuses[$definition['name']] = $approve ? self::PINNED : self::NEW;

                continue;
            }

            if ($pin->status === 'approved' && $pin->approved_hash === $hash) {
                $pin->forceFill(['last_seen_at' => $now, 'pending_hash' => null, 'pending_definition' => null])->save();
                $statuses[$definition['name']] = self::UNCHANGED;

                continue;
            }

            $pin->forceFill([
                'status' => 'pending',
                'pending_hash' => $hash,
                'pending_definition' => $definition,
                'last_seen_at' => $now,
            ])->save();
            $statuses[$definition['name']] = $pin->approved_hash === null ? self::NEW : self::CHANGED;
        }

        return $statuses;
    }

    /**
     * Accept the latest seen definitions for a server (optionally one tool).
     */
    public function approve(string $server, ?string $tool = null): int
    {
        $pins = McpToolPin::where('server', $server)->where('status', 'pending')
            ->when($tool !== null, fn ($query) => $query->where('tool', $tool))
            ->get();

        foreach ($pins as $pin) {
            $pin->forceFill([
                'status' => 'approved',
                'approved_hash' => $pin->pending_hash,
                'approved_definition' => $pin->pending_definition,
                'pending_hash' => null,
                'pending_definition' => null,
                'approved_at' => now(),
            ])->save();
        }

        return $pins->count();
    }

    public function forget(string $server, ?string $tool = null): int
    {
        return (int) McpToolPin::where('server', $server)
            ->when($tool !== null, fn ($query) => $query->where('tool', $tool))
            ->delete();
    }

    /**
     * SHA-256 of the canonical JSON of everything in the definition.
     */
    public static function fingerprint(array $definition): string
    {
        return CanonicalJson::hash($definition);
    }

    /**
     * Pins address a tool by name, so the name has to be one a pin can hold.
     */
    public static function isUsableName(string $name): bool
    {
        return preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._:\/-]{0,127}$/', $name) === 1;
    }

    /**
     * Everything in a tool definition that a model reads or that changes what a call does —
     * a rug pull can hide in an annotation or a title just as well as in the description.
     *
     * @return array<string, mixed>
     */
    public function definition(mixed $tool): array
    {
        $read = function (string ...$keys) use ($tool) {
            foreach ($keys as $key) {
                $value = $this->property($tool, $key);

                if ($value !== null) {
                    return $value;
                }
            }

            return null;
        };

        return [
            'name' => (string) ($read('name') ?? ''),
            'title' => (string) ($read('title') ?? ''),
            'description' => (string) ($read('description') ?? ''),
            'inputSchema' => self::plain($read('inputSchema', 'input_schema')),
            'outputSchema' => self::plain($read('outputSchema', 'output_schema')),
            'annotations' => self::plain($read('annotations')),
            'meta' => self::plain($read('_meta', 'meta')),
        ];
    }

    /**
     * A key of an array tool, a property of an object tool, or — for tools that expose their
     * definition through methods — the value that a no-argument accessor of that name returns.
     */
    private function property(mixed $tool, string $key): mixed
    {
        if (is_array($tool)) {
            return $tool[$key] ?? null;
        }

        if (! is_object($tool)) {
            return null;
        }

        if (isset($tool->{$key})) {
            return $tool->{$key};
        }

        if (! method_exists($tool, $key)) {
            return null;
        }

        try {
            $method = new \ReflectionMethod($tool, $key);

            return $method->isPublic() && ! $method->isStatic() && $method->getNumberOfRequiredParameters() === 0
                ? $method->invoke($tool)
                : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Arrays and scalars only, so a definition can be stored, compared, and scanned.
     */
    private static function plain(mixed $value): mixed
    {
        if ($value === null) {
            return [];
        }

        $decoded = json_decode(CanonicalJson::encode($value), true);

        return $decoded ?? [];
    }

    private function option(string $key): mixed
    {
        return $this->config['llm_guard']['mcp'][$key] ?? null;
    }
}
