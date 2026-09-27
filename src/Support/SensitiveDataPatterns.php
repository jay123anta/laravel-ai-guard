<?php

namespace JayAnta\AiGuard\Support;

/**
 * PII and secret patterns shared by the response scanner (leak detection)
 * and the ML layer (redaction before text leaves the server).
 */
class SensitiveDataPatterns
{
    /**
     * @return array<string, array{label: string, severity: int, regex: string}>
     */
    public static function all(): array
    {
        return [
            'private_key' => [
                'label' => 'Private Key',
                'severity' => 95,
                'regex' => '/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/',
            ],
            'database_url' => [
                'label' => 'Database Connection String',
                'severity' => 95,
                'regex' => '/(?:mysql|postgres|pgsql|mongodb|redis|sqlite):\/\/[^\s"\'<>]{10,}/',
            ],
            // AI-era secrets — listed before the generic api_key pattern so redaction labels them precisely
            'anthropic_key' => [
                'label' => 'Anthropic API Key',
                'severity' => 95,
                'regex' => '/\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}/',
            ],
            'openai_key' => [
                'label' => 'OpenAI API Key',
                'severity' => 95,
                'regex' => '/\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}/',
            ],
            'github_token' => [
                'label' => 'GitHub Token',
                'severity' => 95,
                'regex' => '/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/',
            ],
            'huggingface_token' => [
                'label' => 'Hugging Face Token',
                'severity' => 90,
                'regex' => '/\bhf_[A-Za-z0-9]{30,}/',
            ],
            'google_api_key' => [
                'label' => 'Google API Key',
                'severity' => 90,
                'regex' => '/\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])/',
            ],
            'slack_token' => [
                'label' => 'Slack Token',
                'severity' => 90,
                'regex' => '/\bxox[baprs]-[A-Za-z0-9\-]{10,}/',
            ],
            'jwt_token' => [
                'label' => 'JWT Token',
                'severity' => 85,
                'regex' => '/eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/',
            ],
            'aws_key' => [
                'label' => 'AWS Access Key',
                'severity' => 95,
                'regex' => '/\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/',
            ],
            'api_key' => [
                'label' => 'API Key',
                'severity' => 90,
                // Either a key written the way vendors write them (sk_live_…, pk-test-…) or a
                // named secret being assigned a value. The trigger word must start a word and be
                // followed by a separator: without that, "taskDefinitionArnForProduction" and
                // "apiClientBundle9fJk21xMzQ" read as secrets, and a page mentioning either is
                // withheld in block mode.
                // A name may carry a prefix (DB_PASSWORD, AWS_SECRET_ACCESS_KEY), so it is bounded by
                // "not a letter or digit" rather than \b, which an underscore defeats. A quoted value
                // may hold any non-space character; an unquoted one only token characters.
                'regex' => '/\b(?:sk|pk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{16,}'
                    .'|\b(?:sk|pk)[-_][A-Za-z0-9]{20,}'
                    .'|\bglpat-[A-Za-z0-9_\-]{20,}'
                    .'|\bbearer\s+[A-Za-z0-9._\-]{20,}'
                    .'|\bauthorization:\s*(?:token|basic)\s+[A-Za-z0-9._\-+\/=]{20,}'
                    .'|(?<![A-Za-z0-9])(?:[A-Za-z0-9]+_)*(?:api[-_ ]?(?:key|token|secret)|access[-_ ]?(?:token|key)|auth[-_ ]?token|private[-_ ]?token|secret(?:[-_ ]?access)?[-_ ]?key|client[-_ ]?secret|password|passwd)(?![A-Za-z0-9])'
                    .'["\']?\s*[:=]\s*(?:"[^"\s]{8,}"|\'[^\'\s]{8,}\'|[A-Za-z0-9._\-\/+]{16,})/i',
            ],
            'email' => [
                'label' => 'Email Address',
                'severity' => 70,
                // One-character local parts are real addresses ("a@example.com"). The local part
                // has to start at a boundary, and "@2x.png" is a retina image density, not a domain.
                'regex' => '/(?<![\/a-zA-Z0-9._%+\-])[a-zA-Z0-9._%+\-]+@(?!\d+(?:\.\d+)?x\.(?:png|jpe?g|gif|webp|svg|avif|bmp|ico)\b)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/',
            ],
            'credit_card' => [
                'label' => 'Credit Card Number',
                'severity' => 95,
                // Also written in groups ("4242 4242 4242 4242", Amex "3782 822463 10005"),
                // with the same separator throughout so arbitrary digit runs don't match.
                // 2221-2720 is Mastercard's second range, issued since 2017.
                'regex' => '/\b(?:(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|6(?:011|5\d{2}))([ -]?)\d{4}\1\d{4}\1\d{4}|4\d{12}|3[47]\d{2}([ -]?)\d{6}\2\d{5})\b/',
            ],
            'ssn' => [
                'label' => 'Social Security Number',
                'severity' => 95,
                // Separators are mandatory — an unseparated 9-digit run matches
                // far too many non-SSN values
                'regex' => '/\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b/',
            ],
            'phone' => [
                'label' => 'Phone Number',
                'severity' => 75,
                // Requires a separator before the last group so bare 10-digit
                // numbers (IDs, timestamps) don't match. The second branch is any
                // international number: a country code and 8 to 16 more digits.
                'regex' => '/(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]\d{4}\b|\+\d(?:[-.\s]?\(?\d\)?){8,16}\b/',
            ],
            'ip_address' => [
                'label' => 'Internal IP Address',
                'severity' => 50,
                'regex' => '/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/',
            ],
        ];
    }

    /**
     * Replace every PII/secret match with a [REDACTED:type] marker.
     *
     * @param  array<int, string>  $skip  Pattern keys to leave untouched
     */
    public static function redact(string $text, array $skip = []): string
    {
        foreach (self::all() as $key => $pattern) {
            if (in_array($key, $skip, true)) {
                continue;
            }

            $text = (string) preg_replace($pattern['regex'], '[REDACTED:'.$key.']', $text);
        }

        return $text;
    }
}
