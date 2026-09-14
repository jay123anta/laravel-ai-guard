<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Services\Redactor;
use JayAnta\AiGuard\Support\SensitiveDataPatterns;
use PHPUnit\Framework\TestCase;

class CardNumberPatternTest extends TestCase
{
    private function isCard(string $text): bool
    {
        return preg_match(SensitiveDataPatterns::all()['credit_card']['regex'], $text) === 1;
    }

    public function test_card_numbers_as_people_write_them(): void
    {
        foreach ([
            '4242424242424242',
            '4242 4242 4242 4242',
            '4242-4242-4242-4242',
            '5555 5555 5555 4444',
            '6011 1111 1111 1117',
            '378282246310005',
            '3782 822463 10005',
            '4222222222222',
        ] as $card) {
            $this->assertTrue($this->isCard("pay with {$card} please"), $card);
        }
    }

    public function test_other_numbers_do_not_match(): void
    {
        foreach ([
            '4242 4242-4242 4242',     // mixed separators
            '1234 5678 9012 3456',     // no card prefix
            'Order 42424242 shipped',
            'Call 555-123-4567',
            '2026-09-11 14:03:22',
        ] as $text) {
            $this->assertFalse($this->isCard($text), $text);
        }
    }

    public function test_grouped_cards_are_redacted_and_stay_masked(): void
    {
        $redaction = (new Redactor([]))->redact('Email ann@example.com, card 4242 4242 4242 4242');

        $this->assertSame('Email [[EMAIL_1]], card [[CREDIT_CARD_1]]', $redaction->text);
        $this->assertSame('ann@example.com: [[CREDIT_CARD_1]]', $redaction->restore('[[EMAIL_1]]: [[CREDIT_CARD_1]]'));
        $this->assertStringContainsString('[REDACTED:credit_card]', SensitiveDataPatterns::redact('card 3782 822463 10005'));
    }
}
