<?php

namespace JayAnta\AiGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;

class ThreatDetected
{
    use Dispatchable;

    /**
     * @param array{
     *     detected: bool,
     *     threat_type: string|null,
     *     threat_source: string|null,
     *     confidence_score: int,
     *     matched_pattern: string|null,
     *     payload_snippet?: string|null
     * } $threat The detection result from the pipeline.
     * @param  string  $actionTaken  One of: 'logged', 'blocked', 'rate_limited'.
     */
    public function __construct(
        public readonly Request $request,
        public readonly array $threat,
        public readonly string $actionTaken,
    ) {}
}
