<?php

namespace JayAnta\AiGuard\Events;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;

class ThreatDetected
{
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

    /**
     * Dispatch the event. Written out rather than taken from Illuminate\Foundation's Dispatchable
     * trait, which ships only in laravel/framework — this package depends on the components.
     *
     * @param  array{detected: bool, threat_type: string|null, threat_source: string|null, confidence_score: int, matched_pattern: string|null, payload_snippet?: string|null}  $threat
     */
    public static function dispatch(Request $request, array $threat, string $actionTaken): void
    {
        Event::dispatch(new self($request, $threat, $actionTaken));
    }
}
