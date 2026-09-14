<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Services\BotSignatures;
use PHPUnit\Framework\TestCase;

class BotSignaturesTest extends TestCase
{
    public function test_find_all_bots_returns_every_matching_category(): void
    {
        $matches = BotSignatures::findAllBots('sqlmap/1.8#stable (compatible; Googlebot/2.1)');

        $categories = array_column($matches, 'category');
        $this->assertContains('search_engines', $categories);
        $this->assertContains('bad_bots', $categories);
    }

    public function test_find_bot_picks_highest_confidence_match(): void
    {
        // Appending a search engine name must not mask a malicious tool
        $bot = BotSignatures::findBot('sqlmap/1.8#stable (compatible; Googlebot/2.1)');

        $this->assertNotNull($bot);
        $this->assertSame('bad_bots', $bot['category']);
        $this->assertSame('sqlmap', $bot['matched_bot']);
    }

    public function test_find_bot_skips_excluded_categories(): void
    {
        $bot = BotSignatures::findBot('Mozilla/5.0 HeadlessChrome/120.0 Googlebot', ['search_engines']);

        $this->assertNotNull($bot);
        $this->assertSame('scrapers', $bot['category']);

        $this->assertNull(BotSignatures::findBot('Googlebot/2.1', ['search_engines']));
    }

    public function test_ai_bots_are_split_by_purpose(): void
    {
        $cases = [
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)' => 'ai_training',
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)' => 'ai_training',
            'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)' => 'ai_search',
            'Claude-SearchBot/1.0' => 'ai_search',
            'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)' => 'ai_search',
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)' => 'ai_agents',
            'Claude-User/1.0' => 'ai_agents',
            'Mozilla/5.0 (compatible; Perplexity-User/1.0)' => 'ai_agents',
        ];

        foreach ($cases as $userAgent => $category) {
            $this->assertSame($category, BotSignatures::findBot($userAgent)['category'] ?? null, $userAgent);
        }
    }

    public function test_no_duplicate_tokens_within_a_category(): void
    {
        foreach (BotSignatures::getCategories() as $key => $category) {
            $lower = array_map('strtolower', $category['bots']);
            $this->assertSame(
                count($lower),
                count(array_unique($lower)),
                "Duplicate tokens in {$key}: ".implode(', ', array_diff_assoc($lower, array_unique($lower)))
            );
        }
    }

    public function test_control_tokens_are_known_but_never_matched_in_traffic(): void
    {
        foreach (BotSignatures::CONTROL_TOKENS as $token) {
            $this->assertTrue(BotSignatures::isKnownToken($token));

            // Never a traffic signature itself (a real crawler token inside it, like Applebot, may still match)
            $this->assertNotSame($token, BotSignatures::findBot($token)['matched_bot'] ?? null, "{$token} should not be a traffic signature");
            foreach (BotSignatures::getCategories() as $category) {
                $this->assertNotContains($token, $category['bots']);
            }
        }
    }

    public function test_legacy_tokens_are_flagged_and_still_matched(): void
    {
        $this->assertTrue(BotSignatures::isLegacyToken('Claude-Web'));
        $this->assertTrue(BotSignatures::isLegacyToken('ANTHROPIC-AI'));
        $this->assertFalse(BotSignatures::isLegacyToken('ClaudeBot'));
        $this->assertSame('ai_training', BotSignatures::findBot('Claude-Web/1.0')['category']);
    }

    public function test_tokens_match_on_word_boundaries(): void
    {
        $this->assertNull(BotSignatures::findBot('Mozilla/5.0 (compatible; Vegas Browser)'));
        $this->assertNull(BotSignatures::findBot('Zeusbot/1.0'));
        $this->assertNull(BotSignatures::findBot('Joomla! - Open Source Content Management'));
        $this->assertSame('libcurl', BotSignatures::findBot('libcurl/8.4.0')['matched_bot']);
        $this->assertSame('curl', BotSignatures::findBot('curl/8.4.0')['matched_bot']);
        $this->assertSame('SemrushBot-BA', BotSignatures::findBot('Mozilla/5.0 (compatible; SemrushBot-BA; +http://www.semrush.com/bot.html)')['matched_bot']);
    }

    public function test_category_aliases_expand(): void
    {
        $this->assertSame(['ai_search', 'ai_agents'], BotSignatures::expandCategories(['ai_assistants']));
        $this->assertSame(['search_engines', 'ai_search', 'ai_agents'], BotSignatures::expandCategories(['search_engines', 'ai_assistants', 'ai_search']));
    }

    public function test_confidence_overrides_change_the_winner(): void
    {
        $this->assertSame(60, BotSignatures::findBot('ChatGPT-User/1.0')['confidence']);
        $this->assertSame(90, BotSignatures::findBot('ChatGPT-User/1.0', [], ['ai_agents' => 90])['confidence']);
    }

    public function test_find_bot_returns_null_for_browsers(): void
    {
        $this->assertNull(BotSignatures::findBot(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ));
        $this->assertSame([], BotSignatures::findAllBots(''));
    }
}
