<?php

namespace JayAnta\AiGuard\Support;

/**
 * Thin DNS wrapper so bot verification can be tested without real lookups.
 */
class DnsResolver
{
    /**
     * PTR lookup. Null when the address has no reverse record.
     */
    public function reverse(string $ip): ?string
    {
        $host = @gethostbyaddr($ip);

        return ($host === false || $host === $ip || $host === '') ? null : $host;
    }

    /**
     * A and AAAA lookup.
     *
     * @return array<int, string>
     */
    public function forward(string $host): array
    {
        $ips = @gethostbynamel($host) ?: [];

        if (function_exists('dns_get_record')) {
            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        return array_values(array_unique($ips));
    }
}
