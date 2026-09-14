<?php

namespace JayAnta\AiGuard\Services;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMText;
use Illuminate\Support\HtmlString;
use JayAnta\AiGuard\Support\UrlHost;
use League\CommonMark\GithubFlavoredMarkdownConverter;

/**
 * Renders model output as HTML that is safe to put on a page (OWASP LLM05). Markdown
 * is converted with raw HTML escaped, then an allow-list sanitizer removes scripts,
 * event handlers, dangerous URLs, and images that would load from — and leak chat
 * data to — hosts you have not allowed.
 */
class SafeRenderer
{
    private const TAGS = [
        'p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'b', 'em', 'i', 'u', 's', 'del', 'ins',
        'blockquote', 'code', 'pre', 'kbd', 'mark', 'sup', 'sub', 'span', 'div', 'ul', 'ol', 'li',
        'a', 'img', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption',
    ];

    // Removed together with everything inside them
    private const DROP = [
        'script', 'style', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'form', 'input', 'button',
        'select', 'textarea', 'svg', 'math', 'template', 'noscript', 'link', 'meta', 'base', 'head', 'title',
        'audio', 'video', 'source', 'track', 'canvas', 'portal', 'dialog',
    ];

    private const DEFAULTS = [
        'markdown' => true,
        'html_input' => 'escape',
        'images' => 'allowed_domains',
        'links' => 'all',
        'link_rel' => 'nofollow noopener noreferrer',
        'link_target' => null,
    ];

    private array $config;

    private DOMDocument $document;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * @param  array{markdown?: bool, html_input?: string, images?: string, links?: string, link_rel?: string, link_target?: string|null}  $options
     */
    public function render(string $text, array $options = []): HtmlString
    {
        $options = array_merge(self::DEFAULTS, (array) ($this->config['llm_guard']['rendering'] ?? []), $options);
        $htmlInput = in_array($options['html_input'], ['escape', 'strip', 'allow'], true) ? (string) $options['html_input'] : 'escape';

        $html = $options['markdown'] ? $this->markdown($text, $htmlInput) : $this->plain($text, $htmlInput);

        return new HtmlString($this->sanitize($html, $options));
    }

    /**
     * Clean an HTML fragment against the allow-list.
     */
    public function sanitize(string $html, array $options = []): string
    {
        $options = array_merge(self::DEFAULTS, (array) ($this->config['llm_guard']['rendering'] ?? []), $options);

        if (trim($html) === '') {
            return '';
        }

        if (! class_exists(DOMDocument::class)) {
            $text = (string) preg_replace('#<('.implode('|', self::DROP).')\b.*?</\1\s*>#is', '', $html);

            return htmlspecialchars(html_entity_decode(strip_tags($text), ENT_QUOTES | ENT_HTML5, 'UTF-8'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }

        $this->document = new DOMDocument('1.0', 'UTF-8');
        $previous = libxml_use_internal_errors(true);
        $this->document->loadHTML('<?xml encoding="UTF-8"?><div>'.$html.'</div>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        $root = null;
        foreach ($this->document->childNodes as $node) {
            if ($node instanceof DOMElement) {
                $root = $node;
                break;
            }
        }

        if ($root === null) {
            return '';
        }

        // An unbalanced </div> in the input closes the wrapper, leaving the rest of the answer
        // as the wrapper's siblings. Put it back inside so it is sanitized and kept, instead of
        // being dropped without a word.
        while ($root->nextSibling !== null) {
            $root->appendChild($root->nextSibling);
        }

        $this->clean($root, $options);

        $out = '';
        foreach ($root->childNodes as $child) {
            $out .= $this->document->saveHTML($child);
        }

        return trim($out);
    }

    private function markdown(string $text, string $htmlInput): string
    {
        if (! class_exists(GithubFlavoredMarkdownConverter::class)) {
            return $this->plain($text, $htmlInput);
        }

        $converter = new GithubFlavoredMarkdownConverter([
            'html_input' => $htmlInput,
            'allow_unsafe_links' => false,
            'max_nesting_level' => 50,
        ]);

        return (string) $converter->convert($text);
    }

    private function plain(string $text, string $htmlInput): string
    {
        if ($htmlInput === 'allow') {
            return $text;
        }

        $text = $htmlInput === 'strip' ? strip_tags($text) : $text;
        $paragraphs = array_filter(preg_split('/\R{2,}/u', trim($text)) ?: [], fn (string $p) => trim($p) !== '');

        return implode('', array_map(
            fn (string $p) => '<p>'.nl2br(htmlspecialchars($p, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), false).'</p>',
            $paragraphs
        ));
    }

    private function clean(DOMNode $parent, array $options): void
    {
        foreach (iterator_to_array($parent->childNodes) as $node) {
            if ($node instanceof DOMText) {
                continue;
            }

            if (! $node instanceof DOMElement) {
                $parent->removeChild($node);

                continue;
            }

            $tag = strtolower($node->tagName);

            if (in_array($tag, self::DROP, true)) {
                $parent->removeChild($node);

                continue;
            }

            // Children first, so unwrapping an element never exposes uncleaned nodes
            $this->clean($node, $options);

            if (! in_array($tag, self::TAGS, true)) {
                $this->unwrap($node);

                continue;
            }

            $this->filterElement($node, $tag, $options);
        }
    }

    private function filterElement(DOMElement $element, string $tag, array $options): void
    {
        $attributes = [];
        foreach (iterator_to_array($element->attributes) as $attribute) {
            $attributes[strtolower($attribute->nodeName)] = (string) $attribute->nodeValue;
        }
        foreach (array_keys($attributes) as $name) {
            $element->removeAttribute($name);
        }

        if (isset($attributes['title'])) {
            $element->setAttribute('title', mb_substr($attributes['title'], 0, 200));
        }

        match ($tag) {
            'a' => $this->filterLink($element, $attributes['href'] ?? null, $options),
            'img' => $this->filterImage($element, $attributes, $options),
            'td', 'th' => $this->filterCell($element, $attributes),
            'ol' => isset($attributes['start']) && ctype_digit($attributes['start']) ? $element->setAttribute('start', $attributes['start']) : null,
            'code', 'pre', 'span' => isset($attributes['class']) && preg_match('/^language-[\w+#-]{1,30}$/', $attributes['class']) ? $element->setAttribute('class', $attributes['class']) : null,
            default => null,
        };
    }

    private function filterLink(DOMElement $link, ?string $href, array $options): void
    {
        $url = $href === null ? null : $this->safeUrl($href, ['http', 'https', 'mailto']);
        $mode = (string) $options['links'];

        if ($url === null || $mode === 'none' || ($mode === 'allowed_domains' && ! $this->isAllowedHost($url))) {
            // Show where a refused link pointed, so a disguised link cannot mislead
            if ($url !== null && $mode === 'allowed_domains' && trim($link->textContent) !== $url) {
                $link->appendChild($this->document->createTextNode(' ('.$url.')'));
            }
            $this->unwrap($link);

            return;
        }

        $link->setAttribute('href', $url);
        $link->setAttribute('rel', (string) $options['link_rel']);

        if (is_string($options['link_target']) && $options['link_target'] !== '') {
            $link->setAttribute('target', $options['link_target']);
        }
    }

    private function filterImage(DOMElement $image, array $attributes, array $options): void
    {
        $mode = (string) $options['images'];
        $src = isset($attributes['src']) ? $this->safeUrl($attributes['src'], ['http', 'https'], true) : null;
        $alt = trim((string) ($attributes['alt'] ?? ''));

        if ($src === null || $mode === 'none' || ($mode === 'allowed_domains' && ! $this->isAllowedHost($src))) {
            $image->parentNode?->replaceChild($this->document->createTextNode($alt === '' ? '' : '['.$alt.']'), $image);

            return;
        }

        $image->setAttribute('src', $src);
        if ($alt !== '') {
            $image->setAttribute('alt', $alt);
        }
        $image->setAttribute('loading', 'lazy');
        $image->setAttribute('referrerpolicy', 'no-referrer');
    }

    private function filterCell(DOMElement $cell, array $attributes): void
    {
        foreach (['colspan', 'rowspan'] as $name) {
            if (isset($attributes[$name]) && ctype_digit($attributes[$name])) {
                $cell->setAttribute($name, $attributes[$name]);
            }
        }

        if (isset($attributes['align']) && in_array($attributes['align'], ['left', 'center', 'right'], true)) {
            $cell->setAttribute('align', $attributes['align']);
        }
    }

    /**
     * The URL with whitespace and control characters removed, or null when its scheme is not allowed.
     *
     * @param  array<int, string>  $schemes
     */
    private function safeUrl(string $url, array $schemes, bool $allowDataImages = false): ?string
    {
        // Normalised first, so what is checked is what the browser will fetch
        $url = UrlHost::normalize($url);

        if ($url === '') {
            return null;
        }

        if (preg_match('/^([a-z][a-z0-9+.\-]*):/i', $url, $match)) {
            $scheme = strtolower($match[1]);

            if ($scheme === 'data') {
                return $allowDataImages && preg_match('#^data:image/(png|gif|jpe?g|webp);base64,[a-z0-9+/=]+$#i', $url) ? $url : null;
            }

            return in_array($scheme, $schemes, true) ? $url : null;
        }

        return $url;
    }

    private function isAllowedHost(string $url): bool
    {
        // data: images carry their bytes with them — there is nowhere for them to leak to
        if (preg_match('/^data:/i', UrlHost::clean($url))) {
            return true;
        }

        return UrlHost::matches(UrlHost::host($url), $this->allowedDomains());
    }

    /**
     * @return array<int, string>
     */
    private function allowedDomains(): array
    {
        $allowed = array_map('strval', (array) ($this->config['llm_guard']['allowed_domains'] ?? []));

        // Your own site. Taken from app.url rather than the request, which carries a client-supplied Host
        $own = app()->bound('config') ? (string) parse_url((string) config('app.url'), PHP_URL_HOST) : '';

        if ($own === '' && app()->bound('request')) {
            $own = (string) request()->getHost();
        }

        if ($own !== '') {
            $allowed[] = $own;
        }

        return $allowed;
    }

    private function unwrap(DOMElement $element): void
    {
        $parent = $element->parentNode;
        if ($parent === null) {
            return;
        }

        while ($element->firstChild !== null) {
            $parent->insertBefore($element->firstChild, $element);
        }

        $parent->removeChild($element);
    }
}
