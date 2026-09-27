<?php

namespace JayAnta\AiGuard\Events;

/**
 * A client's identity was verified — by Web Bot Auth signature, published IP ranges, or
 * forward-confirmed reverse DNS. Fires in addition to BotClassified.
 *
 * Interop contract ai-guard.verdict/1: at most once per request. Subscribe by class-name
 * string; see "Interop contract" in the README.
 */
final class AgentVerified extends BotVerdictEvent {}
