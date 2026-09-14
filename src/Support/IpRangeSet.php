<?php

namespace JayAnta\AiGuard\Support;

/**
 * IP ranges compiled for fast lookups: each CIDR becomes a [start, end] pair, pairs are
 * sorted and merged, and a lookup is a binary search — cloud provider lists hold thousands
 * of prefixes. IPv4 bounds are integers; IPv6 bounds are lowercase hex, which sorts like
 * the numbers when compared with strcmp().
 */
final class IpRangeSet
{
    /**
     * @param  array<int, int>  $v4Starts
     * @param  array<int, int>  $v4Ends
     * @param  array<int, string>  $v6Starts
     * @param  array<int, string>  $v6Ends
     */
    private function __construct(
        private array $v4Starts,
        private array $v4Ends,
        private array $v6Starts,
        private array $v6Ends,
    ) {}

    /**
     * Invalid entries are skipped.
     *
     * @param  iterable<mixed>  $cidrs
     */
    public static function fromCidrs(iterable $cidrs): self
    {
        $v4 = [];
        $v6 = [];

        foreach ($cidrs as $cidr) {
            [$address, $bits] = array_pad(explode('/', trim((string) $cidr), 2), 2, null);
            $packed = @inet_pton((string) $address);

            if ($packed === false || ($bits !== null && ! ctype_digit($bits))) {
                continue;
            }

            $bytes = strlen($packed);
            $bits = $bits === null ? $bytes * 8 : (int) $bits;
            if ($bits > $bytes * 8) {
                continue;
            }

            $mask = self::mask($bytes, $bits);
            $start = $packed & $mask;
            $end = $packed | ~$mask;

            if ($bytes === 4) {
                $v4[] = [self::toInt($start), self::toInt($end)];
            } else {
                $v6[] = [bin2hex($start), bin2hex($end)];
            }
        }

        [$v4Starts, $v4Ends] = self::merge($v4, false);
        [$v6Starts, $v6Ends] = self::merge($v6, true);

        return new self($v4Starts, $v4Ends, $v6Starts, $v6Ends);
    }

    public function contains(string $ip): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }

        // IPv4-mapped IPv6 (::ffff:a.b.c.d) is looked up as IPv4
        if (strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10)."\xff\xff")) {
            $packed = substr($packed, 12);
        }

        return strlen($packed) === 4
            ? self::search($this->v4Starts, $this->v4Ends, self::toInt($packed), false)
            : self::search($this->v6Starts, $this->v6Ends, bin2hex($packed), true);
    }

    /**
     * Number of merged ranges.
     */
    public function count(): int
    {
        return count($this->v4Starts) + count($this->v6Starts);
    }

    /**
     * @return array{v4: array{0: array<int, int>, 1: array<int, int>}, v6: array{0: array<int, string>, 1: array<int, string>}}
     */
    public function toArray(): array
    {
        return ['v4' => [$this->v4Starts, $this->v4Ends], 'v6' => [$this->v6Starts, $this->v6Ends]];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            array_map('intval', (array) ($data['v4'][0] ?? [])),
            array_map('intval', (array) ($data['v4'][1] ?? [])),
            array_map('strval', (array) ($data['v6'][0] ?? [])),
            array_map('strval', (array) ($data['v6'][1] ?? [])),
        );
    }

    private static function mask(int $bytes, int $bits): string
    {
        $mask = str_repeat("\xff", intdiv($bits, 8));

        if ($bits % 8 !== 0) {
            $mask .= chr((0xFF << (8 - $bits % 8)) & 0xFF);
        }

        return str_pad($mask, $bytes, "\0");
    }

    private static function toInt(string $packed): int
    {
        return (int) unpack('N', $packed)[1];
    }

    /**
     * @param  array<int, array{0: int|string, 1: int|string}>  $ranges
     * @return array{0: array<int, int|string>, 1: array<int, int|string>}
     */
    private static function merge(array $ranges, bool $hex): array
    {
        usort($ranges, fn (array $a, array $b) => self::compare($a[0], $b[0], $hex));

        $starts = [];
        $ends = [];

        foreach ($ranges as [$start, $end]) {
            $last = count($ends) - 1;

            if ($last >= 0 && self::compare($start, $ends[$last], $hex) <= 0) {
                if (self::compare($end, $ends[$last], $hex) > 0) {
                    $ends[$last] = $end;
                }

                continue;
            }

            $starts[] = $start;
            $ends[] = $end;
        }

        return [$starts, $ends];
    }

    /**
     * @param  array<int, int|string>  $starts
     * @param  array<int, int|string>  $ends
     */
    private static function search(array $starts, array $ends, int|string $needle, bool $hex): bool
    {
        $low = 0;
        $high = count($starts) - 1;
        $found = -1;

        while ($low <= $high) {
            $mid = intdiv($low + $high, 2);

            if (self::compare($starts[$mid], $needle, $hex) <= 0) {
                $found = $mid;
                $low = $mid + 1;
            } else {
                $high = $mid - 1;
            }
        }

        return $found >= 0 && self::compare($needle, $ends[$found], $hex) <= 0;
    }

    private static function compare(int|string $a, int|string $b, bool $hex): int
    {
        return $hex ? strcmp((string) $a, (string) $b) : ((int) $a <=> (int) $b);
    }
}
