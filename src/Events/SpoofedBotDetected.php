<?php

namespace JayAnta\AiGuard\Events;

/**
 * A client claimed a verifiable identity and failed every check that could run. Fires in
 * addition to BotClassified.
 *
 * Interop contract ai-guard.verdict/1: at most once per request. Subscribe by class-name
 * string; see "Interop contract" in the README.
 */
final class SpoofedBotDetected extends BotVerdictEvent {}
