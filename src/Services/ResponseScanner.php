<?php

namespace JayAnta\AiGuard\Services;

use Symfony\Component\HttpFoundation\Response;

class ResponseScanner
{
    private array $config;
    private array $patterns;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->patterns = $this->buildPatterns();
    }

    public function scan(Response $response): array
    {
        if (!($this->config['response_scanning']['enabled'] ?? false)) {
            return $this->buildEmptyResult();
        }

        $contentType = $response->headers->get('Content-Type', '');
        if (!$this->isScannable($contentType)) {
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

        $leaks = [];

        foreach ($this->patterns as $key => $pattern) {
            if (!($this->config['response_scanning']['scan_' . $key] ?? true)) {
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
            'payload_snippet' => 'PII detected: ' . implode(', ', array_column($leaks, 'label')),
            'leaks' => $leaks,
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

    private function buildPatterns(): array
    {
        return [
            'email' => [
                'label' => 'Email Address',
                'severity' => 70,
                'regex' => '/[a-zA-Z0-9._%+\-]{3,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/',
            ],
            'phone' => [
                'label' => 'Phone Number',
                'severity' => 75,
                'regex' => '/(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/',
            ],
            'credit_card' => [
                'label' => 'Credit Card Number',
                'severity' => 95,
                'regex' => '/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/',
            ],
            'ssn' => [
                'label' => 'Social Security Number',
                'severity' => 95,
                'regex' => '/\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/',
            ],
            'api_key' => [
                'label' => 'API Key',
                'severity' => 90,
                'regex' => '/(?:sk|pk|api|key|token|secret|password|bearer)[-_]?(?:live|test|prod)?[-_]?[a-zA-Z0-9]{20,}/',
            ],
            'aws_key' => [
                'label' => 'AWS Access Key',
                'severity' => 95,
                'regex' => '/\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/',
            ],
            'private_key' => [
                'label' => 'Private Key',
                'severity' => 95,
                'regex' => '/-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/',
            ],
            'jwt_token' => [
                'label' => 'JWT Token',
                'severity' => 85,
                'regex' => '/eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/',
            ],
            'ip_address' => [
                'label' => 'Internal IP Address',
                'severity' => 50,
                'regex' => '/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/',
            ],
            'database_url' => [
                'label' => 'Database Connection String',
                'severity' => 95,
                'regex' => '/(?:mysql|postgres|pgsql|mongodb|redis|sqlite):\/\/[^\s"\'<>]{10,}/',
            ],
        ];
    }

    private function redact(string $value): string
    {
        $length = strlen($value);
        if ($length <= 6) {
            return str_repeat('*', $length);
        }
        return substr($value, 0, 3) . str_repeat('*', $length - 6) . substr($value, -3);
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
        ];
    }
}
