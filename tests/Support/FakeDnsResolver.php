<?php

namespace JayAnta\AiGuard\Tests\Support;

use JayAnta\AiGuard\Support\DnsResolver;

class FakeDnsResolver extends DnsResolver
{
    /** @var array<string, string> ip => PTR hostname */
    public array $ptr = [];

    /** @var array<string, array<int, string>> hostname => addresses */
    public array $addresses = [];

    public int $lookups = 0;

    public function reverse(string $ip): ?string
    {
        $this->lookups++;

        return $this->ptr[$ip] ?? null;
    }

    public function forward(string $host): array
    {
        $this->lookups++;

        return $this->addresses[strtolower(rtrim($host, '.'))] ?? [];
    }
}
