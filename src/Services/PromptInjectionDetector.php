<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;

class PromptInjectionDetector
{
    private array $config;
    private array $patterns;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->patterns = $this->buildPatterns();
    }

    public function detect(Request $request): array
    {
        if (!($this->config['prompt_injection']['enabled'] ?? true)) {
            return $this->buildEmptyResult();
        }

        $inputs = [];

        if ($this->config['prompt_injection']['scan_inputs'] ?? true) {
            $inputs = array_merge($inputs, $request->except(['_token', '_method']));
        }

        if ($this->config['prompt_injection']['scan_query'] ?? false) {
            $inputs = array_merge($inputs, $request->query() ?? []);
        }

        foreach ($inputs as $value) {
            $result = $this->scanValue($value);
            if ($result['detected']) {
                return $result;
            }
        }

        return $this->buildEmptyResult();
    }

    public function scanValue(mixed $value): array
    {
        if (is_array($value)) {
            foreach ($value as $item) {
                $result = $this->scanValue($item);
                if ($result['detected']) {
                    return $result;
                }
            }
            return $this->buildEmptyResult();
        }

        if (!is_string($value)) {
            return $this->buildEmptyResult();
        }

        $maxLength = $this->config['prompt_injection']['max_input_length'] ?? 10000;
        if (strlen($value) > $maxLength) {
            return $this->buildEmptyResult();
        }

        foreach ($this->patterns as $pattern) {
            if (preg_match('/' . $pattern . '/i', $value)) {
                return [
                    'detected' => true,
                    'threat_type' => 'prompt_injection',
                    'threat_source' => 'prompt_injection_pattern',
                    'confidence_score' => 90,
                    'matched_pattern' => $pattern,
                    'payload_snippet' => $this->truncatePayload($value),
                ];
            }
        }

        return $this->buildEmptyResult();
    }

    public function getPatternCount(): int
    {
        return count($this->patterns);
    }

    public function isEnabled(): bool
    {
        return $this->config['prompt_injection']['enabled'] ?? true;
    }

    private function buildPatterns(): array
    {
        return [
            // Instruction override attempts
            'ignore previous instructions',
            'ignore all previous instructions',
            'disregard (your|all|previous|the above)',
            'forget (everything|all|your instructions|what)',
            'override (your|all|previous|the)',

            // Role manipulation
            'you are now',
            'act as (a|an|if)',
            'pretend (you are|to be|that you)',
            'roleplay as',
            'your new (role|persona|identity|instructions)',
            'from now on you (are|will|must)',

            // System prompt attacks
            '(reveal|show|display|print|output|tell me) (your|the) (system prompt|instructions|rules|constraints)',
            'what (are|were) your (original|initial|system|base) instructions',
            'repeat (everything|all|your|the) (above|before|prior|previous)',

            // DAN and jailbreak patterns
            '\bDAN\b',
            'do anything now',
            'jailbreak',
            'bypass (your|all|the|safety|content)',
            'without (any |your )?(restrictions|limitations|filters|guidelines)',

            // Developer/admin privilege escalation
            'developer mode',
            'admin mode',
            'sudo (mode|access|override)',
            'maintenance mode',
            'debug mode',
            'you are in (developer|admin|sudo|test)',

            // Data extraction attempts
            '(output|print|show|display|repeat|dump) (all|every|the) (data|records|entries|users|passwords|keys)',
            '(ignore|bypass|skip) (validation|sanitization|security|filters)',

            // Token/context manipulation
            '<\|im_start\|>',
            '<\|im_end\|>',
            '\[INST\]',
            '\[\/INST\]',
            '<<SYS>>',
            '<<\/SYS>>',
        ];
    }

    private function buildEmptyResult(): array
    {
        return [
            'detected' => false,
            'threat_type' => null,
            'threat_source' => null,
            'confidence_score' => 0,
            'matched_pattern' => null,
            'payload_snippet' => null,
        ];
    }

    private function truncatePayload(string $value): string
    {
        $maxLength = $this->config['logging']['max_payload_length'] ?? 500;

        if (strlen($value) <= $maxLength) {
            return $value;
        }

        return substr($value, 0, $maxLength) . '...';
    }
}
