<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Support\SensitiveDataPatterns;
use PHPUnit\Framework\TestCase;

class SensitiveDataPatternsTest extends TestCase
{
    /**
     * @return array<int, array{0: string, 1: string}>
     */
    private static function aiSecrets(): array
    {
        return [
            ['anthropic_key', 'sk-ant-api03-'.str_repeat('Ab3_', 12)],
            ['openai_key', 'sk-proj-'.str_repeat('Xy9-', 12)],
            ['openai_key', 'sk-svcacct-'.str_repeat('Qw8_', 10)],
            ['github_token', 'ghp_'.str_repeat('a1B2', 9)],
            ['github_token', 'github_pat_'.str_repeat('A1b2_', 6)],
            ['huggingface_token', 'hf_'.str_repeat('AbCd1', 7)],
            ['google_api_key', 'AIza'.str_repeat('Sy0_', 8).'abc'],
            ['slack_token', 'xoxb-1234567890-abcdefABCDEF'],
        ];
    }

    public function test_ai_era_secrets_are_detected(): void
    {
        $patterns = SensitiveDataPatterns::all();

        foreach (self::aiSecrets() as [$key, $secret]) {
            $this->assertMatchesRegularExpression($patterns[$key]['regex'], "config: {$secret} end", $key);
            $this->assertGreaterThanOrEqual(90, $patterns[$key]['severity']);
        }
    }

    public function test_ai_era_secrets_are_redacted_with_their_own_label(): void
    {
        foreach (self::aiSecrets() as [$key, $secret]) {
            $redacted = SensitiveDataPatterns::redact("token {$secret} end");

            $this->assertStringNotContainsString($secret, $redacted, $key);
            $this->assertStringContainsString("[REDACTED:{$key}]", $redacted, $key);
        }
    }

    public function test_existing_patterns_still_apply(): void
    {
        $redacted = SensitiveDataPatterns::redact('Email jane.doe@example.com, card 4111111111111111, key sk_live_'.str_repeat('a', 24));

        $this->assertStringContainsString('[REDACTED:email]', $redacted);
        $this->assertStringContainsString('[REDACTED:credit_card]', $redacted);
        $this->assertStringContainsString('[REDACTED:api_key]', $redacted);
    }

    public function test_redaction_can_skip_types(): void
    {
        $redacted = SensitiveDataPatterns::redact('Mail jane.doe@example.com from 10.0.0.5', ['ip_address']);

        $this->assertStringContainsString('10.0.0.5', $redacted);
        $this->assertStringContainsString('[REDACTED:email]', $redacted);
    }

    public function test_ordinary_text_is_untouched(): void
    {
        $text = 'The skeleton key opened the ghost house on AIzawa street.';

        $this->assertSame($text, SensitiveDataPatterns::redact($text));
    }
}
