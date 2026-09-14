<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\HtmlString;
use JayAnta\AiGuard\Facades\AiGuard;
use JayAnta\AiGuard\Tests\TestCase;

class SafeRenderingTest extends TestCase
{
    private function html(string $text, array $options = []): string
    {
        return AiGuard::safeHtml($text, $options)->toHtml();
    }

    public function test_markdown_is_rendered_and_raw_html_is_escaped(): void
    {
        $html = $this->html("**Hi** there <script>alert(1)</script>\n\n- one\n- two");

        $this->assertStringContainsString('<strong>Hi</strong>', $html);
        $this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
        $this->assertStringContainsString('<li>two</li>', $html);
        $this->assertStringNotContainsString('<script', $html);
        $this->assertInstanceOf(HtmlString::class, AiGuard::safeHtml('x'));
    }

    public function test_allowed_html_is_still_sanitized(): void
    {
        $input = '<p onclick="steal()" style="x">a</p><script>bad()</script><iframe src="https://evil.test"></iframe>'
            .'<a href="javascript:alert(1)">c</a><a href="jav&#x09;ascript:alert(2)">d</a><a href="data:text/html,x">e</a>'
            .'<custom-tag>kept text</custom-tag><!-- note --><details><summary>s</summary>t</details>';

        // The sanitizer on its own
        $this->assertSame('<p>a</p>cdekept textst', $this->html($input, ['markdown' => false, 'html_input' => 'allow']));

        // Through Markdown (GFM's tag filter escapes script/iframe as text; the sanitizer removes the rest)
        $html = $this->html($input, ['html_input' => 'allow']);
        foreach (['<script', '<iframe', 'onclick', 'javascript:', 'data:text', '<custom-tag', '<details', '<!--'] as $unsafe) {
            $this->assertStringNotContainsString($unsafe, $html);
        }
        $this->assertStringContainsString('<p>a</p>', $html);
    }

    public function test_images_that_could_exfiltrate_data_are_removed(): void
    {
        config()->set('ai-guard.llm_guard.allowed_domains', ['cdn.example.com']);
        $this->refreshAiGuard();

        $html = $this->html('![chart](https://evil.test/p.png?d=SECRET) ![logo](https://img.cdn.example.com/a.png) ![local](/img/a.png)');

        $this->assertStringNotContainsString('evil.test', $html);
        $this->assertStringContainsString('[chart]', $html);
        $this->assertStringContainsString('src="https://img.cdn.example.com/a.png"', $html);
        $this->assertStringContainsString('referrerpolicy="no-referrer"', $html);
        $this->assertStringContainsString('src="/img/a.png"', $html);

        $this->assertStringNotContainsString('<img', $this->html('![logo](https://img.cdn.example.com/a.png)', ['images' => 'none']));
        $this->assertStringContainsString('src="https://evil.test/p.png"', $this->html('![x](https://evil.test/p.png)', ['images' => 'all']));

        // Raw HTML images and protocol-relative / backslash tricks
        $html = $this->html('<img src="//evil.test/x.png" alt="a"><img src="/\evil.test/y.png"><img src="data:image/svg+xml;base64,PHN2Zz4=">', ['markdown' => false, 'html_input' => 'allow']);
        $this->assertSame('[a]', $html);
    }

    public function test_links_are_hardened_or_shown_as_text(): void
    {
        $this->assertSame(
            '<p><a href="https://evil.test/?q=1" rel="nofollow noopener noreferrer">docs</a></p>',
            $this->html('[docs](https://evil.test/?q=1)')
        );

        $this->assertSame(
            '<p>docs (https://evil.test/?q=1)</p>',
            $this->html('[docs](https://evil.test/?q=1)', ['links' => 'allowed_domains'])
        );

        $this->assertStringContainsString('target="_blank"', $this->html('[a](https://localhost/x)', ['links' => 'allowed_domains', 'link_target' => '_blank']));
        $this->assertSame('<p>docs</p>', $this->html('[docs](https://example.com)', ['links' => 'none']));
    }

    public function test_urls_that_only_a_browser_resolves_are_not_treated_as_same_site(): void
    {
        config()->set('ai-guard.llm_guard.allowed_domains', ['cdn.example.com']);
        $this->refreshAiGuard();

        // parse_url() reports no host for these; browsers fetch evil.test
        foreach (['https:/evil.test/p.png', 'https:///evil.test/p.png', '///evil.test/p.png', 'https:\\\\evil.test/p.png'] as $url) {
            $html = $this->html("![chart]({$url})");

            $this->assertStringNotContainsString('evil.test', $html, $url);
            $this->assertStringContainsString('[chart]', $html, $url);
        }

        $this->assertStringContainsString('src="https://img.cdn.example.com/a.png"', $this->html('![ok](https://img.cdn.example.com/a.png)'));
    }

    public function test_mailto_links_respect_the_allowed_domains_mode(): void
    {
        config()->set('ai-guard.llm_guard.allowed_domains', ['example.com']);
        $this->refreshAiGuard();

        $this->assertSame('<p>write us (mailto:leak@evil.test?subject=SECRET)</p>', $this->html('[write us](mailto:leak@evil.test?subject=SECRET)', ['links' => 'allowed_domains']));
        $this->assertStringContainsString('href="mailto:help@example.com"', $this->html('[write us](mailto:help@example.com)', ['links' => 'allowed_domains']));
    }

    public function test_plain_text_mode(): void
    {
        $this->assertSame(
            "<p>line1<br>\nline2</p><p>&lt;b&gt;x&lt;/b&gt; &amp; y</p>",
            $this->html("line1\nline2\n\n<b>x</b> & y", ['markdown' => false])
        );
        $this->assertSame('', $this->html(''));
    }

    public function test_blade_directives(): void
    {
        $html = Blade::render('<div>@aiSafe($reply)</div>', ['reply' => '**b** <img src=x onerror=alert(1)>']);

        $this->assertStringContainsString('<strong>b</strong>', $html);
        $this->assertStringNotContainsString('<img', $html);

        $this->assertStringContainsString('<em>x</em>', Blade::render('{{ \JayAnta\AiGuard\Facades\AiGuard::safeHtml($x) }}', ['x' => '*x*']));
        $this->assertSame(AiGuard::cspNonce(), Blade::render('@aiNonce'));
    }

    public function test_csp_middleware_sets_a_nonce_policy(): void
    {
        config()->set('ai-guard.llm_guard.allowed_domains', ['cdn.example.com']);

        Route::get('/chat-page', fn () => response(AiGuard::cspNonce()))->middleware('ai-guard.csp');
        Route::get('/chat-page-ro', fn () => response('ok'))->middleware('ai-guard.csp:report-only');
        Route::get('/chat-page-own', fn () => response('ok', 200, ['Content-Security-Policy' => "default-src 'none'"]))->middleware('ai-guard.csp');

        $response = $this->get('/chat-page');
        $nonce = $response->getContent();
        $policy = (string) $response->headers->get('Content-Security-Policy');

        $this->assertNotEmpty($nonce);
        $this->assertStringContainsString("script-src 'self' 'nonce-{$nonce}'", $policy);
        $this->assertStringContainsString("img-src 'self' data: https://cdn.example.com https://*.cdn.example.com", $policy);
        $this->assertStringContainsString("object-src 'none'", $policy);

        $this->assertNotSame($nonce, $this->get('/chat-page')->getContent(), 'A fresh nonce per request');

        $readOnly = $this->get('/chat-page-ro');
        $this->assertTrue($readOnly->headers->has('Content-Security-Policy-Report-Only'));
        $this->assertFalse($readOnly->headers->has('Content-Security-Policy'));

        $this->assertSame("default-src 'none'", $this->get('/chat-page-own')->headers->get('Content-Security-Policy'));

        // Configuring one directive keeps the rest of the defaults
        config()->set('ai-guard.llm_guard.csp.directives', ['connect-src' => ["'self'", 'https://api.example.com'], 'frame-ancestors' => null]);
        $policy = (string) $this->get('/chat-page')->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("connect-src 'self' https://api.example.com", $policy);
        $this->assertStringContainsString("object-src 'none'", $policy);
        $this->assertStringContainsString("base-uri 'none'", $policy);
        $this->assertStringNotContainsString('frame-ancestors', $policy);
    }
}
