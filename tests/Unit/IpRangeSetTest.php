<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Services\IpRangeRepository;
use JayAnta\AiGuard\Support\IpRangeSet;
use PHPUnit\Framework\TestCase;

class IpRangeSetTest extends TestCase
{
    public function test_ipv4_ranges_and_boundaries(): void
    {
        $set = IpRangeSet::fromCidrs(['10.0.0.0/8', '192.168.1.7', '3.5.140.0/22']);

        $this->assertTrue($set->contains('10.0.0.0'));
        $this->assertTrue($set->contains('10.255.255.255'));
        $this->assertFalse($set->contains('11.0.0.0'));
        $this->assertTrue($set->contains('192.168.1.7'));
        $this->assertFalse($set->contains('192.168.1.8'));
        $this->assertTrue($set->contains('3.5.143.255'));
        $this->assertFalse($set->contains('3.5.144.0'));
        $this->assertTrue(IpRangeSet::fromCidrs(['0.0.0.0/0'])->contains('255.255.255.255'));
    }

    public function test_overlapping_ranges_are_merged(): void
    {
        $set = IpRangeSet::fromCidrs(['10.1.0.0/16', '10.0.0.0/8', '10.2.3.0/24', '172.16.0.0/12']);

        $this->assertSame(2, $set->count());
        $this->assertTrue($set->contains('10.2.3.4'));
    }

    public function test_ipv6_and_ipv4_mapped_addresses(): void
    {
        $set = IpRangeSet::fromCidrs(['2001:db8::/32', '::1/128', '2600:1f14::/35', '10.0.0.0/8']);

        $this->assertTrue($set->contains('2001:db8:ffff::1'));
        $this->assertFalse($set->contains('2001:db9::'));
        $this->assertTrue($set->contains('::1'));
        $this->assertFalse($set->contains('::2'), 'Hex bounds are compared as strings, not as numbers');
        $this->assertTrue($set->contains('2600:1f14:1fff:ffff::1'));
        $this->assertFalse($set->contains('2600:1f14:2000::1'));
        $this->assertTrue($set->contains('::ffff:10.1.2.3'));
    }

    public function test_invalid_entries_are_skipped(): void
    {
        $set = IpRangeSet::fromCidrs(['nope', '10.0.0.0/33', '', '1.2.3.0/x', '1.2.3.0/24']);

        $this->assertSame(1, $set->count());
        $this->assertFalse($set->contains('not an ip'));
    }

    public function test_round_trips_through_an_array(): void
    {
        $set = IpRangeSet::fromCidrs(['10.0.0.0/8', '2001:db8::/32']);
        $copy = IpRangeSet::fromArray(json_decode((string) json_encode($set->toArray()), true));

        $this->assertTrue($copy->contains('10.9.9.9'));
        $this->assertTrue($copy->contains('2001:db8::5'));
        $this->assertFalse($copy->contains('11.0.0.1'));
    }

    public function test_list_parsing(): void
    {
        $aws = '{"prefixes":[{"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f14::/35"}]}';
        $this->assertSame(['3.5.140.0/22', '2600:1f14::/35'], IpRangeRepository::parse($aws));

        $this->assertSame(['45.33.0.0/16', '2a03:b0c0::/32'], IpRangeRepository::parse("# networks\n45.33.0.0/16,US,,\n\n2a03:b0c0::/32 NL\nnot-a-range"));
        // A body with no ranges in it is not a range list, whatever format it is in: saving it
        // would replace the ranges in place with nothing
        $this->assertNull(IpRangeRepository::parse('<html><body>Service unavailable</body></html>'));
        $this->assertNull(IpRangeRepository::parse('{"prefixes":[]}'));
        $this->assertNull(IpRangeRepository::parse('{"error":"rate limited","retry_after":60}'));
    }
}
