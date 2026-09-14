# Upgrading

## From 2.x to 3.0

Estimated time: 10–20 minutes. Most apps only need steps 1–3; step 4 lists behaviour changes worth checking before you switch back to `block` mode.

### 1. Update the package

```bash
composer require jayanta/laravel-ai-guard:^3.0
```

v3 adds two dependencies, installed automatically: `guzzlehttp/guzzle` and `paragonie/sodium_compat`.

### 2. Run the new migrations

```bash
php artisan vendor:publish --tag=ai-guard-migrations
php artisan migrate
```

This publishes two migrations next to your existing one (existing files are not overwritten):

- `upgrade_ai_threat_logs_table_to_v3.php` adds the `bot_category`, `bot_verification`, and `chain_hash` columns. It is safe to run more than once.
- `create_ai_guard_mcp_pins_table.php` stores approved MCP tool definitions, used only by `AiGuard::guardMcpTools()`.

If you skip this step nothing breaks — threats are still logged without the new columns, and a warning is written to your log once per process.

### 3. Update your published config

`vendor:publish --force` would overwrite your settings, so compare `config/ai-guard.php` with the package copy (`vendor/jayanta/laravel-ai-guard/config/ai-guard.php`) and add what you need. Keys you leave out fall back to the package defaults.

| Section | What changed |
|---|---|
| `ai_crawlers.user_agents` | Now defaults to `[]`. Keep only **custom** tokens that aren't in the signature database — known tokens listed here are ignored. |
| `bot_signatures` | New `confidence` overrides and `feed` (tokens added by `ai-guard:update-signatures`). `disabled_categories` accepts `ai_training`, `ai_search`, `ai_agents` (`ai_assistants` still works). |
| `prompt_injection` | New `min_score`, `deobfuscate`, `custom_patterns`. |
| `ml_detection` | New `always_run_on`, `max_input_chars`, `redact_pii`. HuggingFace `model` default and new `url`. The `llm_guard` driver is deprecated. |
| `response_scanning` | New `scan_*` keys for AI-era secrets (default on) and `scan_hidden_injection` (opt-in). |
| `robots_txt` | New `path`. |
| `fingerprinting` | New `edge` (JA4 fingerprints and CDN bot scores from trusted proxies) and `datacenter` (opt-in). |
| `bot_verification` | New section (opt-in). |
| `ai_preferences` | New section (opt-in). |
| `llm_guard` | New section for the LLM feature guards: output scanning and canaries, plus `redaction`, `spotlight`, `budgets`, `moderation`, `topics`, `conversations`, `tools`, `mcp`, `agents`, `rendering`, `csp`, and `sql`. |
| `audit` | New section: hash chain, retention, SIEM, OpenTelemetry, and log-channel export (all off by default). |

### 4. Review behaviour changes

**Block mode lets AI search and agents through (logged).** AI bots are now split by purpose:

| Category | Examples | v3 score | Blocked at threshold 70? |
|---|---|---|---|
| `ai_training` | GPTBot, ClaudeBot, CCBot, Bytespider | 95 | Yes |
| `ai_search` | OAI-SearchBot, Claude-SearchBot, PerplexityBot | 65 | No — logged |
| `ai_agents` | ChatGPT-User, Claude-User, Perplexity-User | 60 | No — logged |

In v2 all of these scored 90–95. Blocking training costs you nothing in AI answers, but blocking search crawlers and user-triggered agents removes your pages from AI answers, which is why v3 separates them. To keep v2's behaviour:

```php
'bot_signatures' => [
    'confidence' => ['ai_search' => 90, 'ai_agents' => 90],
],
```

To decide per page instead, put the `ai-guard.agents` middleware on the routes agents must not use.

**Prompt-injection scores are weighted.** If your code or tests compare `confidence_score` to `90`, update them: strong signals score 85–95, stacked signals up to 100. Single weak phrases ("act as a", "you are now", "enable developer mode", "debug mode", or the bare word "jailbreak") are no longer detected on their own; tune with `prompt_injection.min_score`.

**Look-alike user-agents no longer match.** Signatures match on word boundaries, `Joomla`/`phpMyAdmin` were removed from `bad_bots`, and control tokens such as `Google-Extended` are only written to robots.txt.

**ML sees less data.** Providers now receive the scanned input values (PII-redacted, capped at 4,000 characters) instead of the raw body, and strong regex detections are never sent to ML. If you relied on Lakera in v2, note it never worked with the v2 API (every refined score came out 36) — v3 fixes this.

**An `APP_KEY` is required for the signed features.** The audit hash chain and tool-approval tokens are HMAC-signed. v3 has no built-in fallback key: with an empty `APP_KEY` (and no `audit.chain_key`), sealing the chain or minting an approval throws instead of signing with a value anyone could guess. Run `php artisan key:generate` — Laravel apps already have one.

**Tool-argument schemas are checked strictly.** A JSON Schema keyword the argument validator does not implement (`$ref`, `patternProperties`, …) is now reported as an error, which denies the call, instead of being ignored — a silently dropped constraint is an unchecked tool argument. `allOf`, `anyOf`, `oneOf`, `not`, `multipleOf`, `uniqueItems`, `minProperties`, and `maxProperties` are implemented; annotations (`title`, `description`, `default`, `examples`) are accepted.

**The `llm_guard` ML driver is deprecated.** LLM Guard was archived in July 2026. The driver keeps working in v3 and logs a warning once per process; switch `ml_detection.driver` to `huggingface` or `ollama` before v4.

### 5. Code changes

Only relevant if you use these APIs directly:

- `BotSignatures::findBot($ua)` returns the highest-confidence match instead of the first. New optional arguments: excluded categories and confidence overrides.
- `AiGuardMiddleware` has a new constructor argument (`BotVerifier`). Resolve it from the container instead of constructing it.
- `RobotsTxtEnforcer::getDisallowedPaths($bot)` returns the rules of the bot's own group, or the `*` group only when it has none (RFC 9309).
- `AiThreatLog::getThreatSummary()` has new keys (`ai_training_crawlers`, `ai_search_crawlers`, `ai_agents`, `spoofed_bots`); existing keys are unchanged.
- Enforcing a budget yourself: call `AiGuard::consumeBudget()` rather than `checkBudget()` followed by a reservation — it reserves as it checks, so simultaneous requests cannot each pass the same check. `checkBudget()` stays available for showing a user where they stand.
- `AiGuard::observeConversation()` stores a conversation's risk per authenticated user. From a queued job, where there is no authenticated user, pass the subject as the third argument (and the same value to `resetConversation()`), or the job's messages will be scored separately from the request's.

### 6. Optional: turn on what's new

```php
// Catch crawlers that fake their identity (DNS lookups and range fetches are cached)
'bot_verification' => ['enabled' => true],

// Classify every input on chat endpoints with ML, not only regex-flagged ones
'ml_detection' => ['enabled' => true, 'always_run_on' => ['api/chat*']],

// Flag instructions hidden in pages that render user content
'response_scanning' => ['enabled' => true, 'scan_hidden_injection' => true],

// Tell AI crawlers how your content may be used
'ai_preferences' => ['content_usage' => 'train-ai=n'],

// Tamper-evident threat log, checked with `php artisan ai-guard:audit-verify`
'audit' => ['hash_chain' => true],
```

And for your own LLM features:

```php
// Budgets, moderation, topic policy, and multi-turn checks on the routes that call a model
Route::post('/chat', ChatController::class)->middleware('ai-guard.llm');

// Mask personal data before it leaves your app, and put it back in the reply
$redaction = AiGuard::redact($message);
$reply = $redaction->restore($llm->chat($redaction->text));

// Render the reply safely
return view('chat', ['reply' => AiGuard::safeHtml($reply)]);   // or @aiSafe($reply) in Blade

// laravel/ai agents: guard the prompt and the tools
public function middleware(): array { return [new GuardPrompt]; }
public function tools(): iterable { return AiGuard::guardTools([new SendEmail, new FetchPage]); }
```

Measure it in CI:

```bash
php artisan ai-guard:redteam --min-detection=0.9 --max-false-positives=0.05
```
