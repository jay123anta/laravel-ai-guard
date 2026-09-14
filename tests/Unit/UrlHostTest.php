<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Support\UrlHost;
use PHPUnit\Framework\TestCase;

class UrlHostTest extends TestCase
{
    /**
     * @return array<string, array{0: string, 1: string|null}>
     */
    public static function urls(): array
    {
        return [
            'plain' => ['https://evil.test/p.png', 'evil.test'],
            'missing slash' => ['https:/evil.test/p.png', 'evil.test'],
            'three slashes' => ['https:///evil.test/p.png', 'evil.test'],
            'four slashes' => ['https:////evil.test/p.png', 'evil.test'],
            'protocol relative' => ['//evil.test/p.png', 'evil.test'],
            'slash backslash' => ['/\evil.test/p.png', 'evil.test'],
            'backslashes' => ['https:\\\\evil.test/p.png', 'evil.test'],
            'backslash userinfo' => ['http://evil.test\\@example.com/', 'evil.test'],
            'userinfo' => ['https://example.com@evil.test/', 'evil.test'],
            'tab inside' => ["https://evil\t.test/", 'evil.test'],
            'newline inside' => ["https://evil\n.test/", 'evil.test'],
            'uppercase' => ['HTTPS://EVIL.TEST/', 'evil.test'],
            'trailing dot' => ['https://evil.test./', 'evil.test'],
            'port' => ['https://evil.test:8443/x', 'evil.test'],
            'mailto' => ['mailto:leak@evil.test?subject=x', 'evil.test'],
            'mailto with name' => ['mailto:Bob%20<leak@evil.test>', 'evil.test'],
            'relative path' => ['/images/a.png', null],
            'relative bare' => ['a.png', null],
            'anchor' => ['#section', null],
            'query only' => ['?a=1', null],
            'data image' => ['data:image/png;base64,AAAA', ''],
            'javascript' => ['javascript:alert(1)', ''],
        ];
    }

    /**
     * @dataProvider urls
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('urls')]
    public function test_host_matches_what_a_browser_would_fetch(string $url, ?string $expected): void
    {
        $this->assertSame($expected, UrlHost::host($url));
    }

    public function test_matches_allows_relative_and_own_domains_only(): void
    {
        $allowed = ['cdn.example.com'];

        $this->assertTrue(UrlHost::matches(null, $allowed), 'relative');
        $this->assertTrue(UrlHost::matches('cdn.example.com', $allowed));
        $this->assertTrue(UrlHost::matches('img.cdn.example.com', $allowed));
        $this->assertFalse(UrlHost::matches('', $allowed), 'unparsable is never same-site');
        $this->assertFalse(UrlHost::matches('cdn.example.com.evil.test', $allowed));
        $this->assertFalse(UrlHost::matches('evil.test', $allowed));
        $this->assertFalse(UrlHost::matches('evil.test', ['', ' ', '.']), 'empty entries never match');
    }

    public function test_hosts_in_finds_destinations_anywhere_in_arguments(): void
    {
        $hosts = UrlHost::hostsIn([
            'to' => 'Bob <attacker@evil.test>',
            'body' => 'please see https:/sneaky.test/x and //relative.test/y',
            'https://key.test/x' => 'value',
            'nested' => ['deep' => (object) ['url' => 'ftp://object.test/f']],
            'plain' => 'evil.test/collect?d=secret',
            'harmless' => 'just some words',
            'count' => 42,
        ]);

        foreach (['evil.test', 'sneaky.test', 'relative.test', 'key.test', 'object.test'] as $host) {
            $this->assertContains($host, $hosts);
        }
    }

    public function test_hosts_in_ignores_ordinary_text(): void
    {
        $this->assertSame([], UrlHost::hostsIn([
            'subject' => 'Order 4242 shipped',
            'note' => 'See the attached notes and call me back.',
            'when' => '2026-09-14 10:00',
        ]));
    }
}
