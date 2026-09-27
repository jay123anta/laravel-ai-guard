<?php

namespace JayAnta\AiGuard\Events;

/**
 * A client was recognised: a known bot category, or a verified or spoofed identity.
 * Also fires for every request AgentVerified and SpoofedBotDetected cover.
 *
 * Interop contract ai-guard.verdict/1: at most once per request. Subscribe by class-name
 * string; see "Interop contract" in the README.
 */
final class BotClassified extends BotVerdictEvent {}
