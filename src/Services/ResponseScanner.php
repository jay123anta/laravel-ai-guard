<?php

namespace JayAnta\AiGuard\Services;

use JayAnta\AiGuard\Support\SensitiveDataPatterns;
use Symfony\Component\HttpFoundation\Response;

class ResponseScanner
{
    // 8+ consecutive Unicode tag characters — invisible text riding along with visible content
    private const TAG_RUN = '/[\x{E0000}-\x{E007F}]{8,}/u';

    // The same run as JSON escapes: json_encode writes each tag character as the surrogate pair DB40 + DC20..DC7E
    private const ESCAPED_TAG_RUN = '/(?:\\\\u[dD][bB]40\\\\u[dD][cC][0-7][0-9a-fA-F]){8,}/';

    private const MAX_HIDDEN_CHUNK = 5000;

    private array $config;

    private array $patterns;

    private ?PromptInjectionDetector $injectionDetector;

    public function __construct(array $config, ?PromptInjectionDetector $injectionDetector = null)
    {
        $this->config = $config;
        $this->patterns = $this->buildPatterns();
        $this->injectionDetector = $injectionDetector;
    }

    public function scan(Response $response): array
    {
        if (! ($this->config['response_scanning']['enabled'] ?? false)) {
            return $this->buildEmptyResult();
        }

        $contentType = (string) $response->headers->get('Content-Type', '');
        if (! $this->isScannable($contentType)) {
            return $this->buildEmptyResult();
        }

        $content = $response->getContent();
        if ($content === false || $content === '') {
            return $this->buildEmptyResult();
        }

        $maxLength = $this->config['response_scanning']['max_response_length'] ?? 50000;
        if (strlen($content) > $maxLength) {
            $content = substr($content, 0, $maxLength);
        }

        $leakResult = $this->scanForLeaks($content);
        $hiddenResult = $this->scanForHiddenInjection($content, $contentType);

        if ($hiddenResult['detected'] && $hiddenResult['confidence_score'] >= $leakResult['confidence_score']) {
            return array_merge($hiddenResult, ['leaks' => $leakResult['leaks']]);
        }

        if ($leakResult['detected']) {
            return array_merge($leakResult, ['hidden_injections' => $hiddenResult['hidden_injections']]);
        }

        return $this->buildEmptyResult();
    }

    /**
     * PII and secrets leaking in the response body.
     */
    public function scanForLeaks(string $content): array
    {
        $leaks = [];

        foreach ($this->patterns as $key => $pattern) {
            if (! ($this->config['response_scanning']['scan_'.$key] ?? true)) {
                continue;
            }

            if (preg_match($pattern['regex'], $content, $matches)) {
                $leaks[] = [
                    'type' => $key,
                    'label' => $pattern['label'],
                    'severity' => $pattern['severity'],
                    'matched' => $this->redact($matches[0]),
                ];
            }
        }

        if (empty($leaks)) {
            return $this->buildEmptyResult();
        }

        $highestSeverity = max(array_column($leaks, 'severity'));
        $leakTypes = array_column($leaks, 'type');

        return [
            'detected' => true,
            'threat_type' => 'pii_leak',
            'threat_source' => 'response_scanner',
            'confidence_score' => min($highestSeverity, 100),
            'matched_pattern' => implode(', ', $leakTypes),
            'payload_snippet' => 'PII detected: '.implode(', ', array_column($leaks, 'label')),
            'leaks' => $leaks,
            'hidden_injections' => [],
        ];
    }

    /**
     * Indirect prompt injection: instructions hidden from human readers but read
     * by AI agents and browsers that consume the page (opt-in: scan_hidden_injection).
     */
    public function scanForHiddenInjection(string $content, string $contentType = 'text/html'): array
    {
        if ($this->injectionDetector === null || ! ($this->config['response_scanning']['scan_hidden_injection'] ?? false)) {
            return $this->buildEmptyResult();
        }

        $chunks = $this->extractTagSmuggledText($content);
        if (stripos($contentType, 'html') !== false) {
            $chunks = array_merge($chunks, $this->extractHiddenHtmlText($content));
        }

        $best = null;
        $findings = [];

        foreach ($chunks as $chunk) {
            $analysis = $this->injectionDetector->analyzeText(mb_substr($chunk['text'], 0, self::MAX_HIDDEN_CHUNK));

            if (! $analysis['detected']) {
                continue;
            }

            $findings[] = [
                'how' => $chunk['how'],
                'confidence_score' => $analysis['confidence_score'],
                'signals' => $analysis['matched_pattern'],
                'text' => mb_substr($chunk['text'], 0, 200),
            ];

            if ($best === null || $analysis['confidence_score'] > $best['analysis']['confidence_score']) {
                $best = ['how' => $chunk['how'], 'analysis' => $analysis];
            }
        }

        if ($best === null) {
            return $this->buildEmptyResult();
        }

        return [
            'detected' => true,
            'threat_type' => 'indirect_prompt_injection',
            'threat_source' => 'response_scanner',
            'confidence_score' => $best['analysis']['confidence_score'],
            'matched_pattern' => 'hidden:'.$best['how'].': '.$best['analysis']['matched_pattern'],
            'payload_snippet' => $best['analysis']['payload_snippet'],
            'leaks' => [],
            'hidden_injections' => $findings,
        ];
    }

    public function isEnabled(): bool
    {
        return $this->config['response_scanning']['enabled'] ?? false;
    }

    public function getPatternCount(): int
    {
        return count($this->patterns);
    }

    private function isScannable(string $contentType): bool
    {
        $scannable = ['text/html', 'application/json', 'text/plain', 'text/xml', 'application/xml'];

        foreach ($scannable as $type) {
            if (stripos($contentType, $type) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, array{how: string, text: string}>
     */
    private function extractTagSmuggledText(string $content): array
    {
        $decodedRuns = [];

        if (preg_match_all(self::TAG_RUN, $content, $matches)) {
            foreach ($matches[0] as $run) {
                $decoded = '';
                foreach (mb_str_split($run) as $char) {
                    $ascii = mb_ord($char) - 0xE0000;
                    if ($ascii >= 0x20 && $ascii <= 0x7E) {
                        $decoded .= chr($ascii);
                    }
                }
                $decodedRuns[] = $decoded;
            }
        }

        // JSON responses carry the characters as escaped surrogate pairs
        if (preg_match_all(self::ESCAPED_TAG_RUN, $content, $matches)) {
            foreach ($matches[0] as $run) {
                preg_match_all('/[dD][cC]([0-7][0-9a-fA-F])/', $run, $lows);
                $decoded = '';
                foreach ($lows[1] as $low) {
                    $ascii = (int) hexdec($low);
                    if ($ascii >= 0x20 && $ascii <= 0x7E) {
                        $decoded .= chr($ascii);
                    }
                }
                $decodedRuns[] = $decoded;
            }
        }

        $chunks = [];
        foreach ($decodedRuns as $decoded) {
            if (trim($decoded) !== '') {
                $chunks[] = ['how' => 'unicode_tags', 'text' => $decoded];
            }
        }

        return $chunks;
    }

    /**
     * Text a browser would not show: comments, hidden attributes, and CSS-hidden elements.
     *
     * @return array<int, array{how: string, text: string}>
     */
    private function extractHiddenHtmlText(string $html): array
    {
        $chunks = [];

        if (preg_match_all('/<!--(.*?)-->/s', $html, $comments)) {
            foreach ($comments[1] as $comment) {
                if (trim($comment) !== '') {
                    $chunks[] = ['how' => 'html_comment', 'text' => trim($comment)];
                }
            }
        }

        if (! class_exists(\DOMDocument::class)) {
            return $chunks;
        }

        $dom = new \DOMDocument;
        $previous = libxml_use_internal_errors(true);
        $loaded = $dom->loadHTML('<?xml encoding="UTF-8">'.$html, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if (! $loaded) {
            return $chunks;
        }

        // Lower-case the style attribute and drop spaces so "Display: None" matches too
        $style = "translate(@style, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ', 'abcdefghijklmnopqrstuvwxyz')";
        $queries = [
            'hidden_attribute' => '//*[@hidden]',
            'aria_hidden' => "//*[@aria-hidden='true']",
            'display_none' => "//*[contains({$style}, 'display:none')]",
            'visibility_hidden' => "//*[contains({$style}, 'visibility:hidden')]",
            'zero_font_size' => "//*[contains(concat({$style}, ';'), 'font-size:0;') or contains({$style}, 'font-size:0px') or contains({$style}, 'font-size:0em') or contains({$style}, 'font-size:0pt')]",
            'zero_opacity' => "//*[contains(concat({$style}, ';'), 'opacity:0;')]",
            'offscreen' => "//*[contains({$style}, 'left:-9999') or contains({$style}, 'text-indent:-9999') or contains({$style}, 'top:-9999')]",
        ];

        $xpath = new \DOMXPath($dom);

        foreach ($queries as $how => $query) {
            $nodes = $xpath->query($query);
            if ($nodes === false) {
                continue;
            }

            foreach ($nodes as $node) {
                $text = trim($node->textContent);
                if ($text !== '') {
                    $chunks[] = ['how' => $how, 'text' => $text];
                }
            }
        }

        return $chunks;
    }

    private function buildPatterns(): array
    {
        return SensitiveDataPatterns::all();
    }

    private function redact(string $value): string
    {
        $length = strlen($value);
        if ($length <= 6) {
            return str_repeat('*', $length);
        }

        return substr($value, 0, 3).str_repeat('*', $length - 6).substr($value, -3);
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
            'leaks' => [],
            'hidden_injections' => [],
        ];
    }
}
