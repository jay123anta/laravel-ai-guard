<?php

namespace JayAnta\AiGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use JayAnta\AiGuard\Services\RedTeam;
use JayAnta\AiGuard\Support\RedTeamMutator;

class AiGuardRedTeam extends Command
{
    protected $signature = 'ai-guard:redteam
        {--suite= : Categories to run: injection, extraction, jailbreak, tool, exfil, egress, sql, render, benign (default: all)}
        {--mutations=basic : Encodings applied to input attacks: none, basic, all, or a comma-separated list}
        {--url= : Black-box mode: POST every input case to this URL (run your app in block mode)}
        {--field=message : Request field that carries the payload in black-box mode}
        {--header=* : Request header for black-box mode, e.g. "Authorization: Bearer ..."}
        {--min-detection= : Fail when the detection rate is below this (0-1)}
        {--max-false-positives= : Fail when the false-positive rate is above this (0-1)}
        {--format=table : table or json}
        {--show-misses : List the attacks that were not caught and the benign cases that were}
        {--export= : Write the cases for another tool instead of running them: jsonl, promptfoo, garak}
        {--output= : File to write with --export}';

    protected $description = 'Run the red-team corpus against AI Guard and report detection and false-positive rates';

    /** Black-box responses refused for quota rather than by a detector */
    private int $quotaRefusals = 0;

    public function handle(RedTeam $redTeam): int
    {
        $mutations = $this->mutations();
        if ($mutations === null) {
            return self::FAILURE;
        }

        $suite = array_values(array_filter(array_map('trim', explode(',', (string) $this->option('suite')))));
        $unknown = array_diff($suite, RedTeam::CATEGORIES);
        if ($unknown !== []) {
            $this->error('Unknown categor'.(count($unknown) > 1 ? 'ies' : 'y').': '.implode(', ', $unknown).'. Use: '.implode(', ', RedTeam::CATEGORIES).'.');

            return self::FAILURE;
        }

        $cases = RedTeam::cases($suite, $mutations);

        if ($this->option('export')) {
            return $this->export($cases);
        }

        $url = $this->option('url');
        if (is_string($url) && $url !== '') {
            // Only text sent to an endpoint can be tested from the outside
            $cases = array_values(array_filter($cases, fn (array $case) => $case['target'] === 'input'));
            $report = $redTeam->report($cases, fn (array $case) => $this->blocked($url, (string) $case['text']));
            $mode = "black-box: {$url}";

            if ($this->quotaRefusals > 0) {
                $this->warn("{$this->quotaRefusals} request(s) were refused for quota (429/413), not by detection. Those cases were not measured — raise the tier for this client or slow the run down.");
            }
        } else {
            $report = $redTeam->report($cases);
            $mode = 'in-process';
        }

        $this->option('format') === 'json'
            ? $this->line((string) json_encode(['mode' => $mode, 'applied_mutations' => $mutations] + $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))
            : $this->printTable($report, $mode, $mutations);

        return $this->meetsThresholds($report['summary']) ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @return array<int, string>|null
     */
    private function mutations(): ?array
    {
        $option = strtolower(trim((string) $this->option('mutations')));

        $mutations = match ($option) {
            '', 'none' => [],
            'basic' => RedTeamMutator::BASIC,
            'all' => RedTeamMutator::ALL,
            default => array_values(array_filter(array_map('trim', explode(',', $option)))),
        };

        $unknown = array_diff($mutations, RedTeamMutator::ALL);
        if ($unknown !== []) {
            $this->error('Unknown mutation: '.implode(', ', $unknown).'. Use: none, basic, all, or '.implode(', ', RedTeamMutator::ALL).'.');

            return null;
        }

        return $mutations;
    }

    private function blocked(string $url, string $payload): bool
    {
        // A browser-like client, so the run measures the prompt-injection defences, not bot detection
        $headers = [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 ai-guard-redteam',
            'Accept-Language' => 'en',
        ];
        foreach ((array) $this->option('header') as $header) {
            [$name, $value] = array_pad(explode(':', (string) $header, 2), 2, '');
            if (trim($name) !== '') {
                $headers[trim($name)] = trim($value);
            }
        }

        try {
            $response = Http::timeout(15)->withHeaders($headers)->acceptJson()->post($url, [(string) $this->option('field') => $payload]);
        } catch (\Throwable $e) {
            $this->warn("Request failed: {$e->getMessage()}");

            return false;
        }

        return $this->isBlockResponse($response);
    }

    private function isBlockResponse(Response $response): bool
    {
        // A quota refusal says nothing about detection either way, so it is not counted as one —
        // the run is reported as incomplete instead
        if (in_array($response->status(), [429, 413], true)) {
            $this->quotaRefusals++;

            return false;
        }

        return $response->status() === 403 || is_string($response->json('threat_type'));
    }

    private function printTable(array $report, string $mode, array $mutations): void
    {
        $summary = $report['summary'];
        $this->info('AI Guard red team — '.$mode.', '.($summary['attacks'] + $summary['benign']).' cases'.($mutations === [] ? '' : ', mutations: '.implode(', ', $mutations)));
        $this->newLine();

        $rows = [];
        foreach ($report['categories'] as $category => $counts) {
            $rows[] = [$category, $counts['cases'], $counts['flagged'], $this->percent($counts['flagged'], $counts['cases']).($category === 'benign' ? ' (false positives)' : '')];
        }
        $this->table(['Category', 'Cases', 'Flagged', 'Rate'], $rows);

        if ($report['mutations'] !== []) {
            $this->table(['Mutation', 'Cases', 'Detected', 'Rate'], array_map(
                fn (string $mutation, array $counts) => [$mutation, $counts['cases'], $counts['flagged'], $this->percent($counts['flagged'], $counts['cases'])],
                array_keys($report['mutations']),
                $report['mutations']
            ));
        }

        $this->line(sprintf(
            'Detection: %s of %d attacks. False positives: %s of %d benign cases.',
            $this->percent($summary['detected'], $summary['attacks']),
            $summary['attacks'],
            $this->percent($summary['false_positives'], $summary['benign']),
            $summary['benign']
        ));

        if ($this->option('show-misses')) {
            $this->line('Missed: '.($report['misses'] === [] ? 'none' : implode(', ', $report['misses'])));
            $this->line('False positives: '.($report['false_positives'] === [] ? 'none' : implode(', ', $report['false_positives'])));
        }
    }

    private function meetsThresholds(array $summary): bool
    {
        $ok = true;
        $minDetection = $this->option('min-detection');
        $maxFalsePositives = $this->option('max-false-positives');

        if (is_numeric($minDetection) && $summary['detection_rate'] !== null && $summary['detection_rate'] < (float) $minDetection) {
            $this->error('Detection rate '.$summary['detection_rate'].' is below the required '.$minDetection.'.');
            $ok = false;
        }

        if (is_numeric($maxFalsePositives) && $summary['false_positive_rate'] !== null && $summary['false_positive_rate'] > (float) $maxFalsePositives) {
            $this->error('False-positive rate '.$summary['false_positive_rate'].' is above the allowed '.$maxFalsePositives.'.');
            $ok = false;
        }

        return $ok;
    }

    /**
     * @param  array<int, array<string, mixed>>  $cases
     */
    private function export(array $cases): int
    {
        $format = (string) $this->option('export');
        $url = (string) ($this->option('url') ?: 'http://localhost:8000/chat');
        $field = (string) $this->option('field');
        $inputs = array_values(array_filter($cases, fn (array $case) => $case['target'] === 'input'));

        [$extension, $content] = match ($format) {
            'jsonl' => ['jsonl', implode("\n", array_map(fn (array $case) => json_encode([
                'id' => $case['id'],
                'category' => $case['category'],
                'target' => $case['target'],
                'mutation' => $case['mutation'],
                'prompt' => $case['text'] ?? json_encode($case['payload'] ?? null),
                'expect_blocked' => $case['attack'],
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), $cases))."\n"],
            'promptfoo' => ['yaml', $this->promptfoo($inputs, $url, $field)],
            'garak' => ['json', (string) json_encode(['rest' => ['RestGenerator' => [
                'name' => 'AI Guard protected endpoint',
                'uri' => $url,
                'method' => 'post',
                'headers' => ['Content-Type' => 'application/json'],
                'req_template_json_object' => [$field => '$INPUT'],
                'response_json' => true,
                'response_json_field' => 'reply',
            ]]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n"],
            default => [null, null],
        };

        if ($extension === null) {
            $this->error("Unknown export format \"{$format}\". Use jsonl, promptfoo, or garak.");

            return self::FAILURE;
        }

        $path = (string) ($this->option('output') ?: 'ai-guard-redteam.'.$extension);
        file_put_contents($path, $content);

        $this->info("Wrote {$path}.");
        if ($format === 'garak') {
            $this->line("Run: python -m garak --model_type rest -G {$path} --probes promptinject,dan,encoding,latentinjection");
        } elseif ($format === 'promptfoo') {
            $this->line("Run: npx promptfoo eval -c {$path}");
        }

        return self::SUCCESS;
    }

    /**
     * @param  array<int, array<string, mixed>>  $cases
     */
    private function promptfoo(array $cases, string $url, string $field): string
    {
        $yaml = fn (mixed $value) => (string) json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $lines = [
            '# Generated by `php artisan ai-guard:redteam --export=promptfoo`.',
            '# Attacks should be refused (HTTP 403 from AI Guard in block mode); benign prompts answered.',
            'description: '.$yaml('AI Guard red-team corpus'),
            'providers:',
            '  - id: https',
            '    config:',
            '      url: '.$yaml($url),
            '      method: POST',
            '      headers:',
            '        Content-Type: application/json',
            '      body:',
            '        '.$field.': '.$yaml('{{prompt}}'),
            'tests:',
        ];

        foreach ($cases as $case) {
            $lines[] = '  - description: '.$yaml($case['id'].' ('.$case['category'].')');
            $lines[] = '    vars:';
            $lines[] = '      prompt: '.$yaml($case['text']);
            $lines[] = '    metadata:';
            $lines[] = '      expectBlocked: '.($case['attack'] ? 'true' : 'false');
        }

        return implode("\n", $lines)."\n";
    }

    private function percent(int|float|null $part, int|float|null $whole): string
    {
        return $whole ? number_format(100 * (float) $part / (float) $whole, 1).'%' : '—';
    }
}
