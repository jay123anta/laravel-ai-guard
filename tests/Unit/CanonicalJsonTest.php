<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Support\CanonicalJson;
use PHPUnit\Framework\TestCase;

class CanonicalJsonTest extends TestCase
{
    public function test_key_order_does_not_change_the_hash(): void
    {
        $this->assertSame(
            CanonicalJson::hash(['b' => 1, 'a' => ['y' => 2, 'x' => 3]]),
            CanonicalJson::hash(['a' => ['x' => 3, 'y' => 2], 'b' => 1])
        );
    }

    public function test_non_finite_numbers_never_hash_like_zero(): void
    {
        // json_decode('1e999') is INF; partial JSON output writes it as 0, so an approval for
        // an amount of 0 used to match an amount of 1e999
        $hashes = array_map(
            fn ($value) => CanonicalJson::hash(['amount' => $value]),
            [0, INF, -INF, NAN]
        );

        $this->assertCount(4, array_unique($hashes));
    }

    public function test_a_literal_tag_cannot_collide_with_an_encoded_value(): void
    {
        $this->assertNotSame(CanonicalJson::hash(["\xB1"]), CanonicalJson::hash(['ai-guard:b64:sQ==']));
    }

    public function test_deep_values_keep_their_types(): void
    {
        $deep = function (mixed $leaf): array {
            $value = $leaf;
            for ($i = 0; $i < 70; $i++) {
                $value = ['a' => $value];
            }

            return $value;
        };

        $this->assertCount(3, array_unique([
            CanonicalJson::hash($deep(true)),
            CanonicalJson::hash($deep(1)),
            CanonicalJson::hash($deep('1')),
        ]));

        $this->assertCount(3, array_unique([
            CanonicalJson::hash($deep(null)),
            CanonicalJson::hash($deep(false)),
            CanonicalJson::hash($deep('')),
        ]));
    }

    public function test_a_resource_does_not_hash_like_null(): void
    {
        $resource = fopen('php://memory', 'r');

        try {
            $this->assertNotSame(CanonicalJson::hash([null]), CanonicalJson::hash([$resource]));
        } finally {
            fclose($resource);
        }
    }
}
