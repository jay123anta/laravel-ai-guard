<?php

namespace JayAnta\AiGuard\Support;

/**
 * Where a URL would actually send a request — which is not always what parse_url() reports.
 * Browsers strip control characters, read a backslash as a slash, and ignore extra slashes
 * after a scheme, so "https:/evil.com", "https:///evil.com", "//evil.com" and
 * "http://evil.com\@example.com" all reach evil.com. Anything that is not plainly relative
 * therefore resolves to a host (possibly an empty one, which never matches an allow-list).
 */
final class UrlHost
{
    private const SCHEME = '[a-z][a-z0-9+.\-]*';

    /** How deep into tool arguments destinations are looked for before the value is refused */
    private const MAX_DEPTH = 12;

    /**
     * Drop the control characters a browser removes from inside a URL (tab, newline, DEL, …).
     * Spaces are kept: they end a URL rather than being ignored, so removing them here would
     * glue neighbouring words onto a host when scanning prose.
     */
    public static function clean(string $url): string
    {
        return (string) preg_replace('/[\x00-\x1F\x7F]+/', '', $url);
    }

    /**
     * The URL as a browser reads it: control characters and spaces gone, backslashes folded
     * to slashes, and a scheme's slash run collapsed to two ("https:/host" → "https://host").
     */
    public static function normalize(string $url): string
    {
        $url = str_replace('\\', '/', (string) preg_replace('/[\x00-\x20\x7F]+/', '', $url));

        return (string) preg_replace('#^('.self::SCHEME.'):/+#i', '$1://', $url, 1);
    }

    /**
     * The host a fetch would reach, or null when the URL is genuinely relative to this site.
     * A URL with a scheme but no parsable authority returns '' — unknown, never same-site.
     */
    public static function host(string $url): ?string
    {
        $url = self::normalize($url);

        if ($url === '') {
            return null;
        }

        // Protocol-relative URLs address a remote host
        if (str_starts_with($url, '//')) {
            $url = 'https:'.$url;
        } elseif (! preg_match('#^'.self::SCHEME.':#i', $url)) {
            return null;
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

        // mailto: and other address-carrying schemes send to the address's domain
        if (in_array($scheme, ['mailto', 'mail', 'sms', 'tel', 'callto'], true)) {
            return self::emailHost(substr($url, strlen($scheme) + 1));
        }

        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) ? self::canonical($host) : '';
    }

    /**
     * Lower-cased, without a trailing dot, port, or userinfo.
     */
    public static function canonical(string $host): string
    {
        $host = strtolower(trim($host));
        $host = (string) preg_replace('/^[^@]*@/', '', $host);
        $host = (string) preg_replace('/:\d*$/', '', $host);

        // A hostname ends at the first character that cannot appear in one ("evil.test>")
        $trimmed = preg_replace('/[^\p{L}\p{N}.\-].*$/u', '', $host);
        $host = is_string($trimmed) ? $trimmed : (string) preg_replace('/[^a-z0-9.\-].*$/', '', $host);

        return trim($host, '.');
    }

    /**
     * @param  array<int, string>  $domains
     */
    public static function matches(?string $host, array $domains): bool
    {
        // Relative URLs stay on this site
        if ($host === null) {
            return true;
        }

        if ($host === '') {
            return false;
        }

        foreach ($domains as $domain) {
            $domain = self::canonical((string) $domain);

            if ($domain !== '' && ($host === $domain || str_ends_with($host, '.'.$domain))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every host a value could send data to — URLs and email addresses found in strings,
     * array keys, array values, and object properties.
     *
     * @return array<int, string>
     */
    public static function hostsIn(mixed $value, int $depth = 0): array
    {
        // Past the depth limit the arguments are reported as an address that could not be read,
        // never as "no destinations": returning nothing here would let a URL nested deeply
        // enough walk straight through an egress allow-list
        if ($depth > self::MAX_DEPTH) {
            return [''];
        }

        if (is_object($value)) {
            $value = get_object_vars($value);
        }

        if (is_array($value)) {
            $hosts = [];

            foreach ($value as $key => $item) {
                if (is_string($key)) {
                    array_push($hosts, ...self::hostsInString($key));
                }

                array_push($hosts, ...self::hostsIn($item, $depth + 1));
            }

            return array_values(array_unique($hosts));
        }

        return is_string($value) ? self::hostsInString($value) : [];
    }

    /**
     * @return array<int, string>
     */
    private static function hostsInString(string $text): array
    {
        $hosts = [];

        // Control characters first, so a host split by a tab or newline is read as the browser reads it
        $text = self::clean($text);

        // Anything with a scheme, and protocol-relative URLs, anywhere in the string
        if (preg_match_all('#(?:'.self::SCHEME.':)?/{2,}[^\s"\'<>]+|'.self::SCHEME.':/+[^\s"\'<>]+#i', $text, $matches)) {
            foreach ($matches[0] as $candidate) {
                $hosts[] = (string) self::host($candidate);
            }
        }

        // Email addresses anywhere, not only when the whole value is one
        if (preg_match_all('/[A-Za-z0-9._%+\-]+@((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})/', $text, $matches)) {
            foreach ($matches[1] as $domain) {
                $hosts[] = self::canonical($domain);
            }
        }

        // A value that is itself a bare host, with or without a path ("evil.com/collect?d=1")
        $bare = trim($text);
        if (preg_match('#^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:[/?\#].*)?$#i', $bare)) {
            $hosts[] = (string) self::host('https://'.$bare);
        }

        return array_values(array_unique(array_filter($hosts, fn (string $host) => $host !== '' || $bare !== '')));
    }

    private static function emailHost(string $address): string
    {
        $address = self::clean(explode('?', $address, 2)[0]);
        $at = strrpos($address, '@');

        return $at === false ? '' : self::canonical(substr($address, $at + 1));
    }
}
