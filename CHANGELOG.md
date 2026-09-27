# Changelog

All notable changes to `jayanta/laravel-ai-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.1](https://github.com/jay123anta/laravel-ai-guard/compare/v3.0.0...v3.0.1) — 2026-09-27

A patch release: laravel/ai 1.x support, a fix for signed agents being refused when two guard middlewares run, and bypasses closed in the output guard, SQL gate, secret patterns, MCP and the audit chain. No configuration or migration changes.

### Fixed

**laravel/ai**

- **laravel/ai 1.x support.** laravel/ai 1.0 runs agent middleware once per step (`PendingStep` → `StepResult`) instead of once per prompt, and `GuardPrompt` failed with a `TypeError` on it. `GuardPrompt` now handles both: under 1.x the input checks and the budget run on the first step, redaction is re-applied to every step (each step rebuilds its messages from history), the final answer is scanned and restored, and token usage is recorded for every step. The 0.x behaviour is unchanged.
- `AiGuard::guardTools()` now unwraps what laravel/ai unwraps: sub-agents, `ToolSearch` tool sets (recursively), and MCP server tools are guarded as well as plain tools and MCP client tools.

**Bot verification**

- A signed agent was refused as `spoofed_bot` on routes that used both the global middleware and `ai-guard.agents`: the second verification found the signature's nonce already spent. A request is now verified once and the result reused.
- Web Bot Auth follows `draft-ietf-webbotauth-httpsig-protocol-00`: a signature must cover `@authority` or `@target-uri`, and must cover `Signature-Agent` when that header is sent. A signature that does not is treated as unsupported, not verified.

**LLM features**

- **Budgets:** behind `ai-guard.llm`, `recordUsage()` now settles the input the middleware reserved on its own, so input is no longer counted twice when `reservedInputTokens` is not passed. Passing it still works.
- **Output guard:** fetched URLs are found in every attribute a browser loads from (`srcset` candidates, `poster`, `data`, `lowsrc`, `background`, `xlink:href`, and `<link>`, `<object>`, `<embed>`, `<iframe>`, `<track>`, `<input type=image>`, SVG `<image>`), in CSS `url()`, and in reference-style Markdown links and images.
- **SQL gate:** `[bracketed]` identifiers, parenthesised table references with an alias, and `CROSS/OUTER APPLY` are resolved, so a table outside `allowed_tables` can no longer be reached through them.
- **Tool calls:** `scanToolCall()` no longer loses an argument when two paths flatten to the same key, and the finding's snippet is the value that matched.
- **MCP:** a server allow-list entry no longer matches a URL that hides another host behind userinfo (`https://mcp.example.com:443@evil.test`). The `ai-guard.mcp` middleware scans the whole result, including `structuredContent`, and reads multi-line SSE `data:` events whole.
- **JSON Schema:** a numeric keyword with a non-numeric value is reported as uncheckable instead of being skipped, and an empty PHP array is checked against both array and object rules.
- **Tool pins:** values JSON cannot represent exactly (invalid UTF-8, NaN/INF, resources, nesting past 64 levels, strings that look like the package's own tags) are hashed losslessly, so two different definitions can no longer share a pin. Existing pins stay valid.

**Detection**

- Two prompt-injection patterns (`transcript_injection`, `fake_system_message`) took quadratic time on long runs of whitespace — a 1 MB input could hold a request for minutes. They are now linear.
- Invalid UTF-8 bytes and control characters can no longer hide a payload: text is analysed both with them removed and with them read as spaces, and the higher score is kept. Encoded payloads (base64, URL) containing a bad byte are repaired and decoded instead of skipped.
- Tag smuggling split around a real flag emoji is counted.
- Secret patterns: GitLab tokens (`glpat-`), `Authorization: token|basic`, prefixed names (`DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`), and quoted values (`"password": "…"`) are detected. Retina asset names (`logo@2x.png`) are no longer read as email addresses.

**Audit trail**

- Deleting the newest rows from the database and appending again no longer seals over the gap: a new row links to the signed head, so `ai-guard:audit-verify` reports the break.
- The API flush endpoint (`DELETE /ai-guard/api/flush`) now records what it deleted the way `ai-guard:prune` does, so the chain still verifies after a flush. Deleting rows directly in the database is still reported.

## [3.0.0](https://github.com/jay123anta/laravel-ai-guard/compare/v2.1.0...v3.0.0) — 2026-09-14

v3 updates the package for how AI traffic and attacks look in 2026. On the inbound side: AI bots split by purpose, crawler identity verification (Web Bot Auth, published IP ranges, reverse DNS), edge TLS fingerprints, and obfuscation-resistant weighted prompt-injection scoring. For the LLM features you build: usage budgets, moderation and topic policy, PII redaction, a tool-call firewall, MCP tool pinning, a laravel/ai integration, safe rendering of model output, a red-team command, and a tamper-evident audit trail with SIEM and OpenTelemetry export. See [UPGRADE.md](UPGRADE.md) before upgrading.

### Breaking changes

- **AI bots are split by purpose.** `ai_assistants` is replaced by `ai_search` (confidence 65 — OAI-SearchBot, Claude-SearchBot, PerplexityBot, …) and `ai_agents` (confidence 60 — ChatGPT-User, Claude-User, Perplexity-User, …); `ai_training` stays at 95. With the default `confidence_threshold` (70), block mode now blocks training crawlers but only **logs** AI search crawlers and user-triggered agents. Restore v2 behaviour with `bot_signatures.confidence => ['ai_search' => 90, 'ai_agents' => 90]`. The name `ai_assistants` is still accepted (as both new categories) in `disabled_categories`, `confidence`, and `ai-guard:robots-txt --categories`.
- Re-categorised: `ChatGPT-User`, `meta-externalfetcher`, `facebookexternalhit` → `ai_agents`; `meta-webindexer`, `Google-CloudVertexBot`, `iaskspider` → `ai_search`.
- **Prompt-injection scores are weighted.** Detections no longer all score 90: strong signals score 85–95, stacked signals up to 100, obfuscated payloads get +10. Single weak phrases ("you are now", "act as a", "enable developer mode", "debug mode", and now the bare word "jailbreak") stay below the new `prompt_injection.min_score` (50) on their own.
- Bot signatures match on word boundaries ("Vega" no longer matches "Vegas"). Removed false-positive-prone `Joomla` and `phpMyAdmin`, the non-existent `Googlebot-Extended`, and 4 case-duplicate entries. robots.txt-only control tokens (`Google-Extended`, `Applebot-Extended`, `Webzio-Extended`, `YandexAdditional`) are no longer matched against traffic — they are written to robots.txt instead.
- `ai_crawlers.user_agents` now defaults to `[]`, and tokens the signature database already knows are ignored there, so a known bot is always scored by its category (v2's list scored `DataForSeoBot`, `PetalBot`, and `Scrapy` as 95 "AI crawlers" and ignored `disabled_categories`).
- `BotSignatures::findBot()` returns the highest-confidence match (it returned the first match) and accepts excluded categories and confidence overrides.
- ML refinement: the provider now receives the scanned input values (PII-redacted, capped at `max_input_chars`) instead of the raw request body. A combined score below `min_score` is no longer reported as detected, and regex scores above the trigger range are never sent to ML.
- Default HuggingFace model is `meta-llama/Llama-Prompt-Guard-2-86M`.
- New required dependencies: `guzzlehttp/guzzle` `^7.5|^8.0` (the Laravel HTTP client used by ML drivers, alerts, and verification — previously assumed present) and `paragonie/sodium_compat` (Ed25519 for Web Bot Auth where `ext-sodium` is missing).
- New migrations: `upgrade_ai_threat_logs_table_to_v3` adds `bot_category`, `bot_verification`, and `chain_hash`; `create_ai_guard_mcp_pins_table` stores approved MCP tool definitions. Until the upgrade migration runs, threats are still logged without the new columns and a one-time warning is written to the log.
- `AiGuardMiddleware`'s constructor takes a `BotVerifier` (only affects code constructing it manually). Threat-log writing moved to `JayAnta\AiGuard\Support\ThreatLogger`.
- `ai-guard:robots-txt` defaults to `--categories=ai_training,ai_search,ai_agents` (the same bots as v2's default) and also writes the training control tokens.

### Added

**Guarding your own LLM features**

- **LLM route guard** — the `ai-guard.llm` middleware (`ai-guard.llm:premium` for a named tier): token and cost budgets per user or IP (requests and tokens per minute, tokens and USD per day, per-model prices, a global daily spend breaker, an input-size cap) enforced in every mode with a 429 and `Retry-After` (413 for oversized input); harm-category moderation (OpenAI `omni-moderation`, Llama Guard 3 on Ollama, or your own endpoint); topic policy (denied or allowed topics by keyword, regex, or a local classifier); and multi-turn escalation scoring that catches crescendo attacks spread over several messages. Facade: `estimateTokens()`, `checkBudget()`, `recordUsage()`, `budgetUsage()`, `moderate()`, `checkTopic()`, `observeConversation()`, `resetConversation()`.
- **PII redaction and spotlighting** — `AiGuard::redact()` replaces personal data and secrets with numbered placeholders before a prompt leaves your app, and `restore()` puts the safe types (email, phone by default) back into the reply; `AiGuard::spotlight()` marks untrusted content — delimiters, datamarking, or base64 — so the model treats it as data, not instructions.
- **Tool-call firewall** — `AiGuard::authorizeTool()` checks each tool call against per-tool policies: roles, JSON Schema argument validation, `ToolFirewall::define()` authorize callbacks, an egress domain allow-list, taint tracking (write and egress tools need a person's approval once untrusted content entered the conversation), signed single-use approval tokens (`approveToolCall()`), and a per-conversation call cap. `inspectToolResult()` scans results and spotlights untrusted ones; `taint()` marks a conversation. Threat types `tool_call_blocked` and `tool_call_held`.
- **MCP** — the `ai-guard.mcp` middleware for MCP servers you serve: every `tools/call` is policy-checked and scanned, refused calls get a JSON-RPC error, approvals travel in `X-AI-Guard-Approval`, and results are scanned. For servers you connect to, `AiGuard::guardMcpTools()` applies a server allow-list, pins every tool definition so a definition that changes after approval (a "rug pull") is caught, and scans for tool poisoning; `ai-guard:mcp-pins list|approve|forget`. Threat types `mcp_tool_changed` and `mcp_server_blocked`.
- **laravel/ai integration** (PHP 8.3+, Laravel 12+, optional) — the `GuardPrompt` agent middleware runs the budget, injection, topic, moderation, and escalation checks before the provider is called, can redact the prompt and restore the reply, scans the reply for exfiltration and instruction leaks, and records token usage (streamed replies are scanned when the stream ends). `AiGuard::guardTools()` puts agent tools and MCP client tools behind the tool firewall, using laravel/ai's own approval flow. A blocked prompt throws `AiGuardBlockedException`, which renders as a JSON 403, 429, or 413.
- **Safe rendering** — `AiGuard::safeHtml()` and the `@aiSafe` Blade directive render model output as Markdown with raw HTML escaped, then an allow-list sanitizer removes scripts, event handlers, dangerous URLs, and images that would load from — and leak chat data to — hosts you have not allowed. The `ai-guard.csp` middleware sends a Content-Security-Policy with a per-request nonce (`@aiNonce`, `AiGuard::cspNonce()`, shared with Vite).
- **SQL gate for model-written SQL** — `AiGuard::checkSql()` accepts one read-only statement over allowed tables, refuses file, sleep, and admin functions and system catalogs, and fails closed when quoting could be read two ways; `AiGuard::runReadOnlySql()` adds a row cap and a rolled-back, read-only transaction and throws `UnsafeSqlException`. Threat type `unsafe_sql`.
- **Red team** — `ai-guard:redteam` runs a bundled corpus of 100 cases (attacks and look-alike benign prompts, covering injection, extraction, jailbreaks, tool poisoning, output exfiltration, egress destinations hidden in tool arguments, model-written SQL, and unsafe rendering) through 11 encodings and reports detection and false-positive rates per category and per encoding; `--min-detection` and `--max-false-positives` fail CI; `--url` runs the corpus against a live endpoint; `--export` writes garak, promptfoo, or JSONL files.
- **Audit trail and export** — an opt-in tamper-evident hash chain (HMAC keyed by your `APP_KEY`) checked by `ai-guard:audit-verify`; `ai-guard:prune` deletes old logs and keeps the rest of the chain verifiable; threats go to a SIEM (signed JSON or CEF), to an OpenTelemetry collector as OTLP/HTTP log records (with `gen_ai.*` token usage), and to a log channel. Exports are buffered and sent when the request, command, or queued job ends.

**Detection**

- **Prompt-injection de-obfuscation:** zero-width and bidi characters, Unicode tag smuggling, emoji variation-selector smuggling, NFKC folding (with a pure-PHP fallback when `ext-intl` is missing), Cyrillic/Greek homoglyphs, leetspeak, letter-spacing, and base64 / URL / HTML-entity / escape-sequence payloads (`prompt_injection.deobfuscate`).
- 76 weighted prompt-injection patterns (was 33), including current chat-template tokens (Llama 3/4, Gemma, DeepSeek, Mistral, ChatML, tool-call markup), instruction overrides in 12 languages, system-prompt and hidden-rule extraction, secret dumping, conversation exfiltration, role-play jailbreaks, instructions hidden in HTML comments, many-shot jailbreaking, and Policy Puppetry (both also found after encoding); `prompt_injection.custom_patterns` and `PromptInjectionDetector::analyzeText()`.
- ML classifier-first routes (`ml_detection.always_run_on`) — ML judges every input on those paths and can detect what regex missed; borderline candidates below `min_score` are escalated too. `ml_detection.redact_pii` and `max_input_chars`.
- **Bot verification** (`bot_verification`, opt-in): Web Bot Auth / HTTP Message Signatures (RFC 9421) with key-directory lookup, nonce replay protection, and an SSRF guard; published IP ranges (Google, Bing, OpenAI, Perplexity); forward-confirmed reverse DNS. Impersonators are logged as `spoofed_bot`; signed agents browsing with a plain browser user-agent are identified. `AiGuard::verifyBot()`.
- **Edge fingerprints** — JA4 TLS fingerprints from Cloudflare or CloudFront (a browser user-agent with a non-browser JA4 is flagged, and known HTTP clients can be listed) and CDN bot scores, read only from trusted proxies; datacenter scoring for browser user-agents coming from AWS, Google Cloud, or Oracle Cloud (or any list or CIDRs you add); `ai-guard:refresh-ranges`. IP range lists are compiled for O(log n) lookups.
- **Signature feed and agent policy** — `ai-guard:update-signatures` adds tokens from the community [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) list (MIT; nothing is fetched unless you run it); `Google-Agent`; the `ai-guard.agents` route middleware (`verified` by default, `deny`, `allow`) decides whether user-triggered AI agents may use a page, enforced in every mode (threat type `ai_agent_denied`).
- Per-category confidence overrides (`bot_signatures.confidence`).
- Response scanner: Anthropic, OpenAI, GitHub, Hugging Face, Google, and Slack secret patterns; opt-in hidden indirect-prompt-injection scan (`response_scanning.scan_hidden_injection`) for HTML comments, hidden/`aria-hidden`/`display:none`/zero-size/off-screen elements, and tag-smuggled text.
- **LLM output guard:** `AiGuard::scanOutput()` (image/link exfiltration, secrets, harmful content via moderation, instructions for downstream agents, verbatim system-prompt leaks, with a sanitized copy), HMAC canary tokens (`AiGuard::withCanary()`, `canary()`, `isCanary()`), `AiGuard::scanToolCall()` for MCP tool definitions, arguments, and results, and `AiGuard::log()` to record any result.
- **AI preference signals:** `ai-guard.preferences` middleware (IETF AIPREF `Content-Usage` header) and `--content-usage` / `--content-signal` options on `ai-guard:robots-txt` (`ai_preferences` config).

**Platform**

- **Laravel 13 support** (PHP 8.3+), including Guzzle 8, which new Laravel 13 apps install by default. The test suite passes on Laravel 10, 11, 12, and 13, and the package is clean under both PHPStan 1 / Larastan 2 and PHPStan 2 / Larastan 3.
- New threat types, API filters, and dashboard labels: `spoofed_bot`, `indirect_prompt_injection`, `llm_output_threat`, `tool_injection`, `system_prompt_leak`, `llm_budget_exceeded`, `content_moderation`, `denied_topic`, `multi_turn_attack`, `tool_call_blocked`, `tool_call_held`, `mcp_tool_changed`, `mcp_server_blocked`, `unsafe_sql`, `ai_agent_denied`; stats keys, API filters (`bot_category`, `bot_verification`), dashboard category/verification badges, and more rows in `ai-guard:stats`.
- Middleware aliases `ai-guard`, `ai-guard.llm`, `ai-guard.mcp`, `ai-guard.csp`, `ai-guard.agents`, and `ai-guard.preferences`, registered automatically.
- `ThreatDetected` event dispatched on every detection (inbound threats, outbound leaks, tool and MCP decisions) with the request, the detection result, and the action taken — listener exceptions are caught so a broken listener never breaks request handling.
- `robots_txt.path` config option.
- `AiGuard::consumeBudget()` — checks a budget and reserves the estimate in one step, which is what the `ai-guard.llm` middleware and the laravel/ai integration now use, so simultaneous requests cannot each pass the same check.
- `AiGuard::observeConversation()` and `resetConversation()` take an optional subject; without one, a conversation's accumulated risk is stored per authenticated user, so a guessed conversation id reaches nothing.
- Config: `audit.max_buffered` (events held for one export flush), `audit.redact_payloads` (mask secrets and PII in exported payloads, on by default), `llm_guard.budgets.chars_per_token_cjk`, `llm_guard.moderation.flagged_confidence`, `llm_guard.spotlight.marker`.
- PHPStan (Larastan, level 6) static analysis: `composer analyse`, enforced in CI; `phpstan-integrations.neon.dist` also covers the optional laravel/ai integration.
- Laravel Pint code style: `composer format`, enforced in CI.
- CI: PHP 8.4 in the test matrix, and jobs that run the suite with laravel/ai installed on Laravel 12 and 13.
- `SECURITY.md` vulnerability disclosure policy, `CONTRIBUTING.md`, GitHub issue templates (bug, detection gap / false positive, feature request), and Dependabot config.
- `.gitattributes` export-ignore rules — Composer dist downloads no longer include tests, CI config, or tooling files.

### Deprecated

- The `llm_guard` ML driver. The LLM Guard project was archived in July 2026; the driver still works in v3, logs a warning once per process, and will be removed in v4. Use `huggingface` (Llama Prompt Guard 2) or `ollama` instead.

### Fixed

- **Lakera Guard driver disarmed block mode.** It read `category_scores.prompt_injection`, a field the v2 `/guard` API does not return, so every ML-refined detection scored 36 — below the block threshold. It now reads `flagged` and the `breakdown`, and leaves the regex score untouched on an unexpected response.
- **Search-engine user-agent bypass.** Appending a search engine name to any user-agent (`sqlmap/1.8 … Googlebot/2.1`) hid it behind the disabled `search_engines` category; the highest-confidence match now wins.
- **robots.txt parsing** now follows RFC 9309: consecutive `User-agent` lines share one group, `Allow` rules and longest-match precedence apply, a bot-specific group replaces the `*` group, and `*` / `$` wildcards work.
- HuggingFace driver called the retired `api-inference.huggingface.co`; it now uses `router.huggingface.co/hf-inference` (configurable `url`).
- Ollama driver: attacker text could steer its own classifier ("reply 0"). Input is now fenced, instructions live in the system role, the answer must match a JSON schema, and temperature is 0.
- `threat_source` and `matched_pattern` are truncated to their column sizes — an overflow used to throw and silently drop the log row.
- JSON API responses: Unicode tag characters are detected in their escaped (`\uDB40\uDCxx`) form too.
- Card numbers written in groups (`4242 4242 4242 4242`, `4242-4242-4242-4242`, Amex `3782 822463 10005`) were not detected or redacted — only unbroken digits were. Affects response scanning, output scanning, and redaction before ML calls.

Hardening found in this release's own security review, before any of it shipped:

- **URLs are resolved the way a browser resolves them.** `https:/evil.test`, `https:///evil.test`, `//evil.test`, backslash forms, and control characters inside a host all reach a remote host but have no host according to `parse_url()`, so an image or link in model output was treated as same-site, and an egress tool's destination went unseen. Destinations are now also found in nested values, array keys, and `mailto:` addresses, and a URL that cannot be parsed is never treated as same-site. Same-site is decided by `app.url`, not by the request's `Host` header.
- **The MCP middleware read the `Content-Type` header instead of the body**, so a JSON-RPC `tools/call` sent as `text/plain` skipped the tool firewall on a server that parses it anyway.
- **SQL gate:** MySQL `#` comments, an unterminated `"` or `` ` `` identifier, a CTE named after a real table (`WITH users AS (SELECT … FROM users)`), and `AS (…)` outside the `WITH` list (`WINDOW users AS ()`) could all hide a table or a second statement. PostgreSQL's XML dump functions (`query_to_xml`, `database_to_xml`, …) and `pg_*` / `pragma_*` catalogs are refused, and the row cap is only wrapped into SQL on dialects that take `LIMIT`.
- **State keys are bound to the authenticated subject.** An MCP client could clear or read another client's taint state by sending its `MCP-Session-Id`, and conversation risk was keyed by the client-supplied conversation id alone.
- **Long input is scanned in windows instead of skipped.** Padding a payload past `prompt_injection.max_input_length` walked it past every pattern; input over the limit is now scanned at its start and end, plus a window around anything a cheap raw pass matches.
- **Budgets are reserved as they are checked.** Concurrent requests each read the same total and all passed; and CJK, Kana, and Hangul are no longer counted at four characters per token, which under-counted a Japanese prompt fourfold.
- **A flagged moderation verdict is no longer demoted** below the block threshold by a low category score, and a verdict flagged without a named category is no longer dropped. An unknown moderation driver is reported instead of quietly moderating nothing.
- **The audit chain records its own head** (signed, next to the prune anchor), so deleting the newest rows — or emptying the table — no longer verifies clean. Hard-coded fallback HMAC keys are gone: without an `APP_KEY`, signing tool approvals or sealing the chain fails loudly instead of using a key anyone can guess.
- **Tool definitions are pinned in full** — title, annotations, output schema, and `_meta`, not only name, description, and input schema — tools whose definition is exposed through methods are read, and a tool with an unusable or duplicate name is refused rather than shadowing a pinned one.
- The per-conversation tool-call cap is kept in the cache, so it counts a whole conversation rather than restarting on each request; `laravel/ai` tool decisions are memoised per call id **and** arguments, so arguments edited during approval are decided again.
- The signature feed is treated as untrusted input: a token that would match ordinary browsers (`Mozilla`, `Chrome`, `AppleWebKit`), a one- or two-character token, and anything past a cap are refused when fetched *and* when loaded from disk, and signature patterns are compiled in chunks so an over-long pattern cannot fail silently.
- A JSON Schema keyword the argument validator does not implement is now an error instead of an unchecked argument; `allOf`, `anyOf`, `oneOf`, `not`, `multipleOf`, `uniqueItems`, `minProperties`, and `maxProperties` are implemented.
- **One invalid UTF-8 byte switched the prompt-injection layer off.** Every pattern is a `/u` pattern, and `preg_match()` matches nothing at all against invalid UTF-8 — appending a single `\xFF` to a payload took it from score 100 to 0, and past the ML escalation too. Input is now repaired to valid UTF-8 first (invalid bytes dropped, so a byte planted inside a word still matches), and the same byte no longer loses the threat-log row, empties a datamarked block, or collides two values in a signed hash.
- **Four ways to hide a table from the SQL gate's allow-list**: `FROM\`secrets\`` and `FROM"secrets"` with no space (the quotes fused with the keyword), `FROM (secrets)` and `FROM ((secrets))`, `FROM orders, (secrets)`, and MySQL's `STRAIGHT_JOIN`. An unterminated dollar-quote now fails closed like an unterminated quote. `runReadOnlySql()` caps rows as it reads them instead of wrapping the query in a derived table — wrapping broke a query ending in a `--` comment and any query selecting two columns of the same name on MySQL — and it takes the same `$options` as `checkSql()`, so the allow-list you check with is the one it runs with.
- **The output guard read URLs with `parse_url()`** while the renderer and the tool firewall used browser rules, so `![x](https://evil.test\@allowed.test/p.png?d=…)`, `//evil.test/…` and `https:/evil.test/…` were treated as same-site or not inspected at all. It now resolves hosts the same way everything else does, and inspects every URL shape rather than only `https://`.
- **Tool poisoning hidden in a name.** Only string values were scanned, never keys — an injection written as a schema property or annotation name reached the agent unflagged (score 100 as a description, 0 as a key).
- **On an MCP route the taint model never engaged**: the middleware scanned results itself instead of consulting the tool policies, so `untrusted_output` and `taint_all_tool_results` did nothing there, and results were skipped entirely unless the response was JSON — which MCP's Streamable HTTP transport never is. An untrusted tool now taints as it is called, and event-stream bodies are scanned.
- **A deeply nested URL walked past the egress allow-list** (`hostsIn()` returned "no destinations" past its depth limit, which reads as "nothing to block"); it now refuses the value instead.
- **Hash collisions in the canonical form** used for approval tokens and MCP pins: everything below depth 64 hashed alike, and invalid UTF-8 collapsed onto one substitute character — so a token shown to a person bound arguments it did not describe, and a pinned definition could be swapped below that depth without the rug-pull check noticing.
- **A full prune left the chain permanently unverifiable** — new rows sealed against genesis while verification expected the prune anchor — and an unsigned, legacy-shaped anchor file was trusted without checking, which covered up a truncation. A missing anchor is now reported rather than passing silently.
- **A moment's DNS trouble marked real crawlers as impostors for a day.** A failed lookup was indistinguishable from a contradicted one, and the `spoofed` verdict was cached for `cache_minutes` (24 hours by default); DNS-derived verdicts are now short-lived and an incomplete lookup is not evidence.
- **A JSON Schema `pattern` copied from a regex literal (`^\/tmp\/`) never compiled**, and inside `not` that inverted into a rule that accepted everything. Patterns that cannot compile are now reported before any value is checked, and array rules (`maxItems`, `uniqueItems`) are applied when `type` is a list such as `["array","null"]`.
- **`allowed_servers` prefixes matched across a host boundary** — `https://mcp.example.com*` also admitted `https://mcp.example.com.evil.test`.
- **Two false positives that blocked ordinary traffic in block mode**: two regional flag emoji in one message scored as Unicode tag smuggling (the threshold counted every run together rather than the longest), and the generic API-key pattern fired inside ordinary identifiers (`TaskAssignmentRepository`, `apiClientBundle9fJk21xMzQ`), which in block mode withheld the whole response. A missing `Accept-Language` no longer counts as a finding on its own — health checks and server-to-server calls were logged as threats with no source — and the fingerprint signals no longer treat Chromium-only headers and HTTP/2-forbidden `Connection` as missing, which scored ordinary Firefox and Safari traffic as suspicious.
- Safe rendering no longer drops everything after an unbalanced `</div>` in model output; a conversation id from an unauthenticated client no longer shares one namespace with every other guest; `AiGuard::recordUsage()` takes the reserved token count, so input is not charged twice against a quota; a custom moderation endpoint answering `1` or `"true"` is read as flagged instead of as unreachable; and the compiled range lists a long-running worker holds now expire, so `ai-guard:refresh-ranges` reaches it.
- Other fail-quiet paths closed: a range list whose body holds no ranges no longer replaces the ranges in place; the `ai-guard.llm` middleware reads bodies Laravel does not parse and scans keys as well as values; topic keywords still match when the input is not valid UTF-8, and a topic pattern that cannot compile is reported; a value that `json_encode()` refuses no longer collapses to `''` when hashing or signing; CSP directives you configure are merged onto the defaults; a newline in a CEF field can no longer forge an audit record; exported payloads are masked; the export buffer is capped; and a placeholder planted in an input can no longer collect a real value from `Redaction::restore()`.

### Changed

- The bare word "jailbreak" now scores 35 and only counts together with other signals, so questions about jailbreaking a phone or console are no longer flagged. Targeted forms ("jailbreak the AI") still score 85.
- Crawler IP range lists are cached as compiled range sets under new cache keys; each list is fetched once more after upgrading.
- `AiGuardManager::__construct()` no longer takes an `Application` argument (it was stored but never used). Only affects code instantiating the manager directly instead of via the container or `AiGuard` facade.
- Codebase reformatted with Laravel Pint (`laravel` preset); PHPDoc generics added to model scopes and collection-returning methods.
- Test suite grew from 60 to 438 tests; tests run the package's real migrations, block stray HTTP requests, use a per-test cache store, and include held-out prompt-injection phrasings that are not in the red-team corpus.
- Email addresses with a one-character local part, Mastercard's 2221–2720 range, and international phone numbers are now redacted and detected.

## [2.1.0](https://github.com/jay123anta/laravel-ai-guard/compare/v2.0.0...v2.1.0) — 2026-08-03

### Added

- `AiGuard::detectText($text)` — scan any string for prompt injection directly, without an HTTP request (queue jobs, chat pipelines, integrations such as laravel-natural-query)
- `php artisan ai-guard:robots-txt` — generate a robots.txt that blocks AI crawlers and scrapers from the signature database (`--categories`, `--all`, `--output`, `--append`)
- Bot signature database expanded from 149 to 364 curated bots, including AI training crawlers, AI agent bots, and scraping-as-a-service platforms (ZenRows, ScrapingBee, ScraperAPI, Oxylabs, Zyte, and more)

### Fixed

- `logging.enabled` and `alerts.alert_on` config options were silently ignored — both are now honored (Slack alerts can be restricted to blocked/rate-limited requests)
- ML detection (`ml_detection`) could never trigger: regex detections score 90 but the default `trigger_range` capped at 85; default is now `[40, 90]`
- The DAN jailbreak pattern matched the lowercase name "dan" (e.g. `dan@example.com`) at confidence 90 — now uppercase-only
- `httpx` was listed as a malicious bot, misclassifying the legitimate `python-httpx` client library — reclassified as data harvester (confidence 80)
- SSN and phone PII patterns matched any bare 9/10-digit number (order IDs, timestamps) — separators are now required
- Multibyte payloads could be truncated mid-character, producing invalid UTF-8 that crashed JSON API responses with a 500
- `GET /ai-guard/api/threats/{id}` with a non-numeric id returned a 500 TypeError — now a proper 404
- The API `threat_type` filter only recognized 4 of the 12 threat types and silently returned unfiltered results for the rest
- PII response blocking now respects `confidence_threshold`
- `AiGuard::detect()` facade now respects the `enabled` flag and IP/user-agent whitelists
- robots.txt misses are now cached (previously re-read the filesystem on every request when enforcement was enabled)

### Changed

- Config default `alerts.alert_on` is now `['logged', 'blocked', 'rate_limited']` (was the invalid value `['block', 'rate_limited']`); legacy values `'block'`/`'rate_limit'` in published configs are still accepted
- CI: Laravel 10/11 jobs install with `--no-blocking` (Composer ≥ 2.10 refuses EOL framework versions with unpatched security advisories); Laravel 12 remains fully policy-checked

## [2.0.0](https://github.com/jay123anta/laravel-ai-guard/compare/v1.0.0...v2.0.0) — 2026-03-26

### Added

- Categorized bot signature database with per-category confidence scoring (AI training, AI assistants, search engines, SEO tools, scrapers, bad bots, data harvesters)
- Honeypot trap routes — hidden paths no real user visits, instant 100 confidence on hit
- Response scanning — detect PII leaking in outgoing responses (emails, credit cards, SSNs, API keys, AWS keys, JWTs, private keys, database URLs)
- robots.txt enforcement — confidence boost when a bot violates your Disallow rules
- Request fingerprinting — detect bots faking browser user-agents via header analysis
- Optional ML-based prompt injection detection with pluggable drivers (Lakera, HuggingFace, Pangea, LLM Guard, Ollama, custom endpoint)
- New model scopes and stats for honeypot, PII, bad bot, and scraper threat types

## 1.0.0 — 2026-03-24

### Added

- Initial release: AI crawler detection, prompt injection scanning, data harvester detection
- `log_only` / `block` / `rate_limit` modes with confidence threshold
- Database threat logging, dashboard, REST API, Slack alerts, `ai-guard:stats` command
- SQLite and PostgreSQL support for the timeline query
