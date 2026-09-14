<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Support\CanonicalJson;
use RuntimeException;

/**
 * Tamper-evident threat log: each row stores HMAC(previous row's hash, its own contents).
 * Editing, reordering, or deleting a row breaks the chain from that point on. The key is
 * your APP_KEY (or audit.chain_key), so database access alone cannot re-seal the chain.
 */
class AuditChain
{
    public const FIELDS = [
        'ip_address', 'user_agent', 'threat_type', 'threat_source', 'bot_category', 'bot_verification',
        'confidence_score', 'request_url', 'request_method', 'matched_pattern', 'payload_snippet',
        'headers_snapshot', 'action_taken', 'created_at',
    ];

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function isEnabled(): bool
    {
        return (bool) ($this->config['audit']['hash_chain'] ?? false);
    }

    /**
     * Insert a row linked to the last chained row.
     */
    public function append(array $attributes): AiThreatLog
    {
        $write = function () use ($attributes): AiThreatLog {
            $previous = (string) AiThreatLog::query()->whereNotNull('chain_hash')->orderByDesc('id')->value('chain_hash');

            // With the table empty, the last pruned row is what the next one links to — the same
            // predecessor verify() looks for. Sealing against genesis instead would leave a chain
            // that can never verify again after a prune deleted every row.
            if ($previous === '') {
                $anchor = $this->anchor();
                $previous = $anchor !== null ? $anchor['hash'] : '';
            }

            $attributes['created_at'] = $attributes['updated_at'] = now()->startOfSecond();
            $attributes['chain_hash'] = $this->hash($previous, $attributes);

            $log = new AiThreatLog;
            $log->forceFill($attributes)->save();

            // Remember the head outside the database: deleting the newest rows, or emptying the
            // table, leaves what is left internally consistent and would otherwise verify clean
            $this->saveHead((int) $log->getKey(), (string) $attributes['chain_hash']);

            return $log;
        };

        try {
            // One writer at a time, or two requests could link to the same previous row
            return Cache::lock('ai-guard:audit-chain', 10)->block(5, $write);
        } catch (LockTimeoutException) {
            // Writing anyway could link two rows to the same predecessor and break the chain for
            // good. The row is kept, outside the chain, and says so.
            Log::warning('AI Guard: audit chain lock timed out; the row is logged without a chain hash.');

            $log = new AiThreatLog;
            $log->forceFill($attributes + ['created_at' => now()->startOfSecond(), 'updated_at' => now()->startOfSecond()])->save();

            return $log;
        } catch (\BadMethodCallException) {
            // Cache store without locks
            return $write();
        }
    }

    public function hash(string $previous, array $row): string
    {
        return hash_hmac('sha256', $previous."\n".$this->canonical($row), $this->key());
    }

    /**
     * Walk the chain in ID order.
     *
     * @return array{checked: int, first: int|null, last: int|null, broken_at: int|null, reason: string|null}
     */
    public function verify(?int $fromId = null): array
    {
        $query = DB::table('ai_threat_logs')->whereNotNull('chain_hash');
        if ($fromId !== null) {
            $query->where('id', '>=', $fromId);
        }

        $previous = null;
        $checked = 0;
        $first = null;
        $last = null;

        foreach ($query->lazyById(500, 'id') as $row) {
            $row = (array) $row;
            $id = (int) $row['id'];

            if ($previous === null) {
                $first = $id;
                $previous = $this->predecessor($id);
            }

            if (! hash_equals($this->hash($previous, $row), (string) $row['chain_hash'])) {
                return $this->result($checked, $first, $last, $id, "log #{$id} was changed or moved, or a row before it was removed");
            }

            $previous = (string) $row['chain_hash'];
            $last = $id;
            $checked++;
        }

        return $this->checkHead($checked, $first, $last, $previous, $fromId);
    }

    /**
     * The chain can be internally consistent and still be missing its newest rows, so the head
     * is compared with the signed record kept outside the database.
     */
    private function checkHead(int $checked, ?int $first, ?int $last, ?string $lastHash, ?int $fromId): array
    {
        $state = $this->state();

        if ($state === null) {
            // Every chained row writes this file, so with rows in the chain and no file the
            // record of where the chain ends has been removed
            return $checked > 0
                ? $this->result($checked, $first, $last, $last, 'the audit anchor file is missing, so the end of the chain cannot be confirmed')
                : $this->result($checked, $first, $last, null, null);
        }

        if (! $state['trusted']) {
            return $this->result($checked, $first, $last, $last ?? 0, 'the audit anchor file was edited: its signature does not match');
        }

        $head = $state['head'];

        if ($head === null || ($fromId !== null && $head['id'] < $fromId)) {
            return $this->result($checked, $first, $last, null, null);
        }

        if ($last === null || $last < $head['id']) {
            $missing = $last === null ? 'every chained row is gone' : "rows after log #{$last} are gone";

            return $this->result($checked, $first, $last, $head['id'], "the last logged row was #{$head['id']}: {$missing}");
        }

        if ($last === $head['id'] && ! hash_equals($head['hash'], (string) $lastHash)) {
            return $this->result($checked, $first, $last, $last, "log #{$last} does not match the last recorded row");
        }

        return $this->result($checked, $first, $last, null, null);
    }

    private function result(int $checked, ?int $first, ?int $last, ?int $brokenAt, ?string $reason): array
    {
        return ['checked' => $checked, 'first' => $first, 'last' => $last, 'broken_at' => $brokenAt, 'reason' => $reason];
    }

    /**
     * Remember the last pruned row, so the first remaining row can still be checked.
     */
    public function saveAnchor(int $id, string $hash): void
    {
        $changes = ['anchor' => ['id' => $id, 'hash' => $hash]];
        $head = $this->head();

        // Everything up to the anchor has been deleted, so a head at or below it is gone with it
        if ($head !== null && $head['id'] <= $id) {
            $changes['head'] = null;
        }

        $this->writeState($changes);
    }

    /**
     * Remember the newest chained row, so removing rows from the end is still detectable.
     */
    public function saveHead(int $id, string $hash): void
    {
        $this->writeState(['head' => ['id' => $id, 'hash' => $hash]]);
    }

    /**
     * @return array{id: int, hash: string}|null
     */
    public function anchor(): ?array
    {
        $state = $this->state();

        return $state !== null && $state['trusted'] ? $state['anchor'] : null;
    }

    /**
     * @return array{id: int, hash: string}|null
     */
    public function head(): ?array
    {
        $state = $this->state();

        return $state !== null && $state['trusted'] ? $state['head'] : null;
    }

    /**
     * The anchor file, signed with the chain key so it cannot be rewritten to cover a deletion.
     *
     * @return array{anchor: array{id: int, hash: string}|null, head: array{id: int, hash: string}|null, trusted: bool}|null
     */
    private function state(): ?array
    {
        $path = $this->anchorPath();
        $data = is_file($path) ? json_decode((string) file_get_contents($path), true) : null;

        if (! is_array($data)) {
            return null;
        }

        // Only a file this package signed counts. There is no unsigned form to accept: the
        // anchor is what proves a prune was a prune, so an unsigned one proves nothing.
        $signature = (string) ($data['signature'] ?? '');
        $body = ['anchor' => $data['anchor'] ?? null, 'head' => $data['head'] ?? null];

        return [
            'anchor' => $this->point($body['anchor']),
            'head' => $this->point($body['head']),
            'trusted' => $signature !== '' && hash_equals(hash_hmac('sha256', CanonicalJson::encode($body), $this->key()), $signature),
        ];
    }

    private function writeState(array $changes): void
    {
        $state = $this->state();
        $keep = fn (string $key) => ($state['trusted'] ?? false) ? $state[$key] : null;

        // array_key_exists, not ??: a change may set a point to null on purpose
        $body = [
            'anchor' => array_key_exists('anchor', $changes) ? $changes['anchor'] : $keep('anchor'),
            'head' => array_key_exists('head', $changes) ? $changes['head'] : $keep('head'),
        ];

        $path = $this->anchorPath();
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0755, true);
        }

        file_put_contents($path, CanonicalJson::encode($body + [
            'signature' => hash_hmac('sha256', CanonicalJson::encode($body), $this->key()),
        ]), LOCK_EX);
    }

    /**
     * @return array{id: int, hash: string}|null
     */
    private function point(mixed $value): ?array
    {
        return is_array($value) && isset($value['id'], $value['hash'])
            ? ['id' => (int) $value['id'], 'hash' => (string) $value['hash']]
            : null;
    }

    /**
     * The hash the row at $id must link to: the chained row before it, else the prune anchor, else genesis.
     */
    private function predecessor(int $id): string
    {
        $hash = DB::table('ai_threat_logs')->whereNotNull('chain_hash')->where('id', '<', $id)->orderByDesc('id')->value('chain_hash');
        if (is_string($hash)) {
            return $hash;
        }

        $anchor = $this->anchor();

        return $anchor !== null && $anchor['id'] < $id ? $anchor['hash'] : '';
    }

    private function canonical(array $row): string
    {
        $values = [];

        foreach (self::FIELDS as $field) {
            $value = $row[$field] ?? null;

            $values[$field] = match (true) {
                $value === null => null,
                $field === 'created_at' => Carbon::parse($value instanceof \DateTimeInterface ? $value->format('Y-m-d H:i:s') : (string) $value)->format('Y-m-d H:i:s'),
                $field === 'headers_snapshot' => $this->canonicalJson($value),
                $field === 'confidence_score' => (int) $value,
                default => (string) $value,
            };
        }

        return CanonicalJson::encode($values);
    }

    private function canonicalJson(mixed $value): ?string
    {
        $decoded = is_array($value) ? $value : json_decode((string) $value, true);

        return is_array($decoded) ? CanonicalJson::encode($decoded) : null;
    }

    /**
     * A chain signed with a guessable key proves nothing, so there is no built-in fallback.
     */
    private function key(): string
    {
        $key = (string) ($this->config['audit']['chain_key'] ?? '') ?: (string) config('app.key');

        if (trim($key) === '') {
            throw new RuntimeException('AI Guard cannot seal the audit chain without an APP_KEY or ai-guard.audit.chain_key.');
        }

        return $key;
    }

    private function anchorPath(): string
    {
        $path = $this->config['audit']['anchor_path'] ?? null;

        return is_string($path) && $path !== '' ? $path : storage_path('app/ai-guard/audit-anchor.json');
    }
}
