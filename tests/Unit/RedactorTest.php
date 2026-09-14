<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Services\Redactor;
use JayAnta\AiGuard\Support\Redaction;
use PHPUnit\Framework\TestCase;

class RedactorTest extends TestCase
{
    private function redactor(array $redaction = []): Redactor
    {
        return new Redactor(['llm_guard' => ['redaction' => $redaction]]);
    }

    public function test_sensitive_values_become_numbered_placeholders(): void
    {
        $key = 'sk-ant-api03-'.str_repeat('Ab3_', 12);

        $result = $this->redactor()->redact("Mail jane@example.com or bob@example.com, card 4111111111111111, key {$key}");

        $this->assertSame('Mail [[EMAIL_1]] or [[EMAIL_2]], card [[CREDIT_CARD_1]], key [[ANTHROPIC_KEY_1]]', $result->text);
        $this->assertSame(4, $result->count());
        $this->assertEqualsCanonicalizing(['email', 'credit_card', 'anthropic_key'], $result->types());
    }

    public function test_repeated_values_share_one_placeholder(): void
    {
        $result = $this->redactor()->redact('jane@example.com wrote to jane@example.com');

        $this->assertSame('[[EMAIL_1]] wrote to [[EMAIL_1]]', $result->text);
        $this->assertSame(1, $result->count());
    }

    public function test_a_placeholder_planted_in_the_input_cannot_collect_a_real_value(): void
    {
        $result = $this->redactor()->redact('Summarise this page: "Contact [[EMAIL_1]] for details." My address is jane@example.com.');

        // The planted placeholder is defused, so only the real address holds one
        $this->assertStringContainsString('Contact [ [EMAIL_1] ] for details.', $result->text);
        $this->assertSame(1, $result->count());
        $this->assertSame('jane@example.com', $result->restore('[[EMAIL_1]]'));
    }

    public function test_addresses_cards_and_numbers_other_shapes(): void
    {
        $result = $this->redactor()->redact('Write to a@example.com, card 2221 0012 3412 3456, phone +44 20 7946 0958.');

        $this->assertSame('Write to [[EMAIL_1]], card [[CREDIT_CARD_1]], phone [[PHONE_1]].', $result->text);
    }

    public function test_restore_puts_back_only_safe_types(): void
    {
        $result = $this->redactor()->redact('Call 555-123-4567 about card 4111111111111111');
        $reply = 'I will call [[PHONE_1]]. Your card [[CREDIT_CARD_1]] is on file.';

        // Phone is restorable by default; card numbers stay masked
        $this->assertSame('I will call 555-123-4567. Your card [[CREDIT_CARD_1]] is on file.', $result->restore($reply));

        $all = $this->redactor(['restore' => ['*']])->redact('card 4111111111111111');
        $this->assertSame('card 4111111111111111', $all->restore('card [[CREDIT_CARD_1]]'));
    }

    public function test_types_are_configurable(): void
    {
        $result = $this->redactor(['types' => ['email']])->redact('jane@example.com 4111111111111111');

        $this->assertSame('[[EMAIL_1]] 4111111111111111', $result->text);

        $explicit = $this->redactor()->redact('jane@example.com 4111111111111111', ['credit_card']);
        $this->assertSame('jane@example.com [[CREDIT_CARD_1]]', $explicit->text);
    }

    public function test_internal_ips_are_not_masked_by_default(): void
    {
        $this->assertSame('ping 10.0.0.5', $this->redactor()->redact('ping 10.0.0.5')->text);
    }

    public function test_clean_text_is_unchanged(): void
    {
        $result = $this->redactor()->redact('What is the capital of France?');

        $this->assertFalse($result->hasRedactions());
        $this->assertSame('What is the capital of France?', (string) $result);
        $this->assertSame('same reply', $result->restore('same reply'));
    }

    public function test_redaction_survives_serialization(): void
    {
        $original = $this->redactor()->redact('Mail jane@example.com');

        $copy = Redaction::fromArray($original->toArray());

        $this->assertSame($original->text, $copy->text);
        $this->assertSame('Mail jane@example.com', $copy->restore('Mail [[EMAIL_1]]'));
    }
}
