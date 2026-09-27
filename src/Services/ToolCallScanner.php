<?php

namespace JayAnta\AiGuard\Services;

use JayAnta\AiGuard\Support\TextNormalizer;

/**
 * Scans agent tool traffic — MCP tool definitions (tool poisoning), call
 * arguments, and tool results — for instructions smuggled to the model.
 */
class ToolCallScanner
{
    public const KINDS = ['definition', 'arguments', 'result'];

    private const STACKING_STEP = 5;

    private const MAX_STACKING_BONUS = 15;

    private array $config;

    private PromptInjectionDetector $injectionDetector;

    private TextNormalizer $normalizer;

    /**
     * @var array<int, array{id: string, regex: string, weight: int}>
     */
    private array $patterns;

    public function __construct(array $config, ?PromptInjectionDetector $injectionDetector = null, ?TextNormalizer $normalizer = null)
    {
        $this->config = $config;
        $this->normalizer = $normalizer ?? new TextNormalizer;
        $this->injectionDetector = $injectionDetector ?? new PromptInjectionDetector($config, $this->normalizer);
        $this->patterns = $this->buildPatterns();
    }

    /**
     * @param  array<mixed>|string  $payload  A tool definition, arguments, or result (e.g. an MCP JSON-RPC object)
     * @param  string  $kind  'definition', 'arguments', or 'result'
     */
    public function scan(array|string $payload, string $kind = 'result'): array
    {
        $kind = in_array($kind, self::KINDS, true) ? $kind : 'result';
        // A list of [path, value] pairs, not a map keyed by path: a literal "a.b" key and a nested
        // a => b share a path, and a map would let one silently replace the other
        $fields = is_string($payload) ? [['', $payload]] : $this->flatten($payload);

        $best = null;
        $findings = [];

        foreach ($fields as [$path, $value]) {
            $hits = $this->poisoningHits($value);

            $injection = $this->injectionDetector->analyzeText($value);
            if ($injection['detected']) {
                $hits[] = ['id' => 'prompt_injection['.$injection['matched_pattern'].']', 'weight' => $injection['confidence_score']];
            }

            if ($hits === []) {
                continue;
            }

            usort($hits, fn (array $a, array $b) => $b['weight'] <=> $a['weight']);
            $score = min(100, $hits[0]['weight'] + min(self::MAX_STACKING_BONUS, self::STACKING_STEP * (count($hits) - 1)));

            $finding = ['field' => (string) $path, 'confidence_score' => $score, 'signals' => array_column($hits, 'id')];
            $findings[] = $finding;
            $finding['value'] = $value;

            if ($best === null || $score > $best['confidence_score']) {
                $best = $finding;
            }
        }

        $minScore = (int) ($this->config['prompt_injection']['min_score'] ?? PromptInjectionDetector::DEFAULT_MIN_SCORE);

        if ($best === null || $best['confidence_score'] < $minScore) {
            return [
                'detected' => false,
                'threat_type' => null,
                'threat_source' => null,
                'confidence_score' => $best['confidence_score'] ?? 0,
                'matched_pattern' => null,
                'payload_snippet' => null,
                'findings' => $findings,
            ];
        }

        $prefix = $best['field'] !== '' ? $best['field'].': ' : '';

        return [
            'detected' => true,
            'threat_type' => 'tool_injection',
            'threat_source' => 'tool_'.$kind,
            'confidence_score' => $best['confidence_score'],
            'matched_pattern' => mb_substr($prefix.implode(', ', $best['signals']), 0, 255),
            'payload_snippet' => mb_substr($best['value'], 0, (int) ($this->config['logging']['max_payload_length'] ?? 500)),
            'findings' => $findings,
        ];
    }

    /**
     * Every string leaf, and every string key, as [dotted path, text] — e.g.
     * ["inputSchema.properties.a.description", "..."]. The path is a label for the report only;
     * two fields sharing a label are still two entries.
     *
     * @param  array<mixed>  $data
     * @return array<int, array{0: string, 1: string}>
     */
    private function flatten(array $data, string $prefix = ''): array
    {
        $fields = [];

        foreach ($data as $key => $value) {
            // A long key is shortened in the label, never in what is scanned
            $label = mb_substr((string) $key, 0, 40);
            $path = $prefix === '' ? $label : $prefix.'.'.$label;

            // Names are read by the model too — a schema property, an annotation key, or an
            // argument name carries instructions just as well as a description does
            if (is_string($key) && trim($key) !== '' && ! is_numeric($key)) {
                $fields[] = [$path.'[name]', $key];
            }

            if (is_array($value)) {
                array_push($fields, ...$this->flatten($value, $path));
            } elseif (is_string($value) && trim($value) !== '') {
                $fields[] = [$path, $value];
            }
        }

        return $fields;
    }

    /**
     * @return array<int, array{id: string, weight: int}>
     */
    private function poisoningHits(string $value): array
    {
        $variants = array_column($this->normalizer->analyze($value)['variants'], 'text');
        $hits = [];

        foreach ($this->patterns as $pattern) {
            foreach ($variants as $variant) {
                if (preg_match($pattern['regex'], $variant) === 1) {
                    $hits[] = ['id' => $pattern['id'], 'weight' => $pattern['weight']];
                    break;
                }
            }
        }

        return $hits;
    }

    /**
     * Tool-poisoning signals, weighted like the prompt-injection patterns.
     *
     * @return array<int, array{id: string, regex: string, weight: int}>
     */
    private function buildPatterns(): array
    {
        $definitions = [
            // "Don't mention this to the user" — the defining trait of a poisoned tool
            ['conceal_from_user', 85,
                '\b(?:do\s+not|don\'?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|show(?:ing)?|notify(?:ing)?|alert(?:ing)?)\b.{0,80}\buser\b'],
            ['tool_shadowing', 75,
                '\b(?:instead\s+of|rather\s+than)\s+(?:using|calling)\s+(?:the\s+)?[\w-]+(?:\s+tool)?\b|\bignore\s+(?:the\s+)?(?:other|previous|existing|original)\s+tools?\b|\bwhen\s+(?:the\s+)?[\w-]+\s+tool\s+is\s+(?:used|called|invoked)\b'],
            ['covert_forwarding', 75,
                '\b(?:always|also|silently|secretly)\s+(?:send|forward|cc|bcc|copy|include)\b.{0,60}(?:@|https?:\/\/)'],
            ['hidden_directive_tag', 70,
                '<\s*\/?\s*(?:important|system|instructions?|secret|hidden|admin|critical|note\s+to\s+(?:the\s+)?(?:ai|assistant|model|llm))\s*>'],
            ['exfiltration_instruction', 70,
                '\b(?:send|post|upload|forward|transmit|exfiltrate|leak)\b.{0,60}\bhttps?:\/\/'],
            ['pass_as_parameter', 60,
                '\bpass\s+(?:its|the|their|all|that)\s+(?:content|contents|value|data|output|text)\s+(?:as|in|into|through)\b'],
            ['sensitive_file_access', 45,
                '(?:~|\$HOME|%USERPROFILE%)?[\/\\\\]?\.(?:ssh|aws|kube|docker|gnupg)\b|\bid_(?:rsa|ed25519|ecdsa)\b|\b(?:mcp|claude_desktop_config|credentials|secrets)\.json\b|\/etc\/(?:passwd|shadow)\b|\.(?:env|npmrc|pypirc|netrc|git-credentials)\b'],
            // Legitimate tools also say "call X before using this tool", so this only counts in combination
            ['cross_tool_instruction', 40,
                '\b(?:before|after|when(?:ever)?|prior\s+to)\s+(?:using|calling|invoking|running)\s+(?:this|any|the|other|another|every)\s+(?:\w+\s+)?tools?\b'],
        ];

        return array_map(fn (array $d) => ['id' => $d[0], 'weight' => $d[1], 'regex' => '/'.$d[2].'/iu'], $definitions);
    }
}
