<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Services\RobotsTxtParser;
use PHPUnit\Framework\TestCase;

class RobotsTxtParserTest extends TestCase
{
    public function test_consecutive_user_agent_lines_share_one_group(): void
    {
        $parser = new RobotsTxtParser(
            "User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /private\n\nUser-agent: *\nDisallow: /tmp\n"
        );

        // Both bots named in the group get its rules — and only its rules
        $this->assertSame(['/private'], $parser->disallowedPaths('GPTBot'));
        $this->assertSame(['/private'], $parser->disallowedPaths('ClaudeBot'));
        $this->assertFalse($parser->isAllowed('GPTBot', '/private/data'));
        $this->assertTrue($parser->isAllowed('GPTBot', '/tmp/cache'));

        // Unnamed bots fall back to the "*" group
        $this->assertSame(['/tmp'], $parser->disallowedPaths('CCBot'));
        $this->assertFalse($parser->isAllowed('CCBot', '/tmp/cache'));
        $this->assertTrue($parser->isAllowed('CCBot', '/private/data'));
    }

    public function test_specific_group_replaces_wildcard_group(): void
    {
        $parser = new RobotsTxtParser("User-agent: *\nDisallow: /\n\nUser-agent: Googlebot\nDisallow: /admin\n");

        $this->assertTrue($parser->isAllowed('Googlebot', '/blog'));
        $this->assertFalse($parser->isAllowed('Googlebot', '/admin'));
        $this->assertFalse($parser->isAllowed('GPTBot', '/blog'));
    }

    public function test_empty_specific_group_allows_everything(): void
    {
        $parser = new RobotsTxtParser("User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nDisallow:\n");

        $this->assertTrue($parser->isAllowed('GPTBot', '/anything'));
        $this->assertFalse($parser->isAllowed('CCBot', '/anything'));
    }

    public function test_longest_match_wins_and_allow_wins_ties(): void
    {
        $parser = new RobotsTxtParser("User-agent: *\nDisallow: /docs\nAllow: /docs/public\nAllow: /shop\nDisallow: /shop\n");

        $this->assertFalse($parser->isAllowed('GPTBot', '/docs/internal'));
        $this->assertTrue($parser->isAllowed('GPTBot', '/docs/public/page'));
        $this->assertSame([], array_values(array_diff(['/docs', '/shop'], $parser->disallowedPaths('GPTBot'))));

        // Same length — Allow wins
        $this->assertTrue($parser->isAllowed('GPTBot', '/shop/cart'));
    }

    public function test_wildcards_and_end_anchor(): void
    {
        $parser = new RobotsTxtParser("User-agent: *\nDisallow: /*.pdf$\nDisallow: /search*q=\n");

        $this->assertFalse($parser->isAllowed('GPTBot', '/files/report.pdf'));
        $this->assertTrue($parser->isAllowed('GPTBot', '/files/report.pdf.html'));
        $this->assertFalse($parser->isAllowed('GPTBot', '/search?q=laravel'));
        $this->assertTrue($parser->isAllowed('GPTBot', '/search'));
    }

    public function test_matching_is_case_insensitive_and_ignores_comments_and_versions(): void
    {
        $parser = new RobotsTxtParser("# block AI\nuser-agent: gptbot # OpenAI\nDISALLOW: /secret\n");

        $this->assertFalse($parser->isAllowed('GPTBot', '/secret'));
        $this->assertFalse($parser->isAllowed('GPTBot/', '/secret'));
        $this->assertTrue($parser->isAllowed('GPTBot', '/public'));
    }

    public function test_robots_txt_itself_is_always_allowed(): void
    {
        $parser = new RobotsTxtParser("User-agent: *\nDisallow: /\n");

        $this->assertTrue($parser->isAllowed('GPTBot', '/robots.txt'));
        $this->assertFalse($parser->isAllowed('GPTBot', '/'));
    }

    public function test_check_reports_the_winning_rule(): void
    {
        $parser = new RobotsTxtParser("User-agent: *\nDisallow: /api\n");

        $result = $parser->check('GPTBot', '/api/users');

        $this->assertFalse($result['allowed']);
        $this->assertSame(['type' => 'disallow', 'path' => '/api'], $result['rule']);
        $this->assertSame(['allowed' => true, 'rule' => null], $parser->check('GPTBot', '/about'));
    }

    public function test_empty_file_allows_everything(): void
    {
        $parser = new RobotsTxtParser('');

        $this->assertTrue($parser->isAllowed('GPTBot', '/'));
        $this->assertSame([], $parser->rulesFor('GPTBot'));
    }
}
