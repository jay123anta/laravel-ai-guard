# Laravel AI Guard

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![Total Downloads](https://img.shields.io/packagist/dt/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![PHP Version](https://img.shields.io/packagist/php-v/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![Laravel Version](https://img.shields.io/badge/laravel-10.x%20%7C%2011.x%20%7C%2012.x-blue?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![License](https://img.shields.io/packagist/l/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![Tests](https://img.shields.io/github/actions/workflow/status/jay123anta/laravel-ai-guard/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/jay123anta/laravel-ai-guard/actions)

Protect your Laravel app from AI scrapers, LLM crawlers, and prompt injection attacks.

## What It Does

Laravel AI Guard is a middleware-based security package with a multi-layer detection pipeline:

- **354 bot signatures** across 7 categories (AI training, AI assistants, SEO tools, scrapers, bad bots, data harvesters, search engines) with per-category confidence scoring
- **30 prompt injection patterns** across 7 attack categories, with recursive nested input scanning
- **Honeypot trap routes** — hidden paths that real users never visit, instant 100 confidence on hit
- **PII leak detection** — scans outgoing responses for emails, credit cards, SSNs, API keys, JWTs, AWS keys, private keys, and database URLs
- **robots.txt enforcement** — boosts confidence when bots violate your Disallow rules
- **Request fingerprinting** — detects bots faking browser user-agents by analyzing header patterns
- **Optional ML detection** — pluggable ML providers (Lakera, HuggingFace, Pangea, LLM Guard, Ollama, or custom) for borderline cases, zero dependencies

All detections are logged to your database with a built-in dashboard, 10 REST API endpoints, an Artisan command, and Slack alerts.

## Requirements

- PHP 8.1 or higher
- Laravel 10.x, 11.x, or 12.x
- A database supported by Laravel (MySQL, PostgreSQL, SQLite)

No additional PHP extensions or external services required.

## Installation

```bash
composer require jayanta/laravel-ai-guard
```

Publish and run migrations:

```bash
php artisan vendor:publish --tag=ai-guard-migrations
php artisan migrate
```

Publish the config file:

```bash
php artisan vendor:publish --tag=ai-guard-config
```

## Quick Start

Register the middleware globally so every request is scanned.

**Laravel 11 / 12** — `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware::class);
})
```

**Laravel 10** — `app/Http/Kernel.php`:

```php
protected $middleware = [
    // ...existing middleware
    \JayAnta\AiGuard\Http\Middleware\AiGuardMiddleware::class,
];
```

That's it. AI Guard is now monitoring all incoming requests in `log_only` mode.

### Recommended First Steps

1. **Start in `log_only` mode** (default) — detects and logs everything, blocks nothing
2. **Remove auth from dashboard** temporarily to view it without login:
   ```php
   // config/ai-guard.php
   'dashboard' => ['middleware' => ['web']],
   ```
3. **Visit the dashboard** at `http://your-app.com/ai-guard` to see detections
4. **Whitelist your tools** — add Postman, your monitoring service, and internal IPs:
   ```php
   'false_positives' => [
       'whitelist_ips' => ['your-office-ip'],
       'whitelist_user_agents' => ['PostmanRuntime', 'Insomnia'],
   ],
   ```
5. **Review detections for a few days** before switching to `block` or `rate_limit` mode
6. **Re-enable auth** on dashboard and API before going to production

## Detection Pipeline

Every request passes through this pipeline:

```
Request
  1. Whitelist check         → skip if IP/UA whitelisted
  2. Honeypot trap check     → instant 100 confidence
  3. Bot signature detection → 354 bots, 7 categories
     a. robots.txt check     → boost confidence if Disallow violated
  4. Prompt injection scan   → 30 patterns, recursive input scanning
     a. ML enhancement       → optional, borderline cases only
  5. Fingerprint analysis    → header order, missing headers, Accept anomalies
  6. Action                  → log / block / rate_limit based on mode + threshold
  7. Response scanning       → outbound PII leak detection
```

## Configuration

After publishing, the config file is at `config/ai-guard.php`.

### Mode

```php
// Options: 'log_only', 'block', 'rate_limit'
'mode' => 'log_only',
```

- **log_only** — Detect and log threats, never block. Start here.
- **block** — Return 403 for threats above the confidence threshold.
- **rate_limit** — Apply rate limiting to detected threats via cache.

### Confidence Threshold

```php
// Minimum score (0-100) to trigger action in block/rate_limit mode
'confidence_threshold' => 70,
```

### Bot Signatures (354 bots, 7 categories)

```php
'bot_signatures' => [
    'enabled' => true,
    // Categories to DISABLE (search_engines disabled by default — don't block Google)
    'disabled_categories' => ['search_engines'],
],
```

| Category | Count | Default Confidence | Enabled |
|----------|-------|--------------------|---------|
| `ai_training` | 63 | 95 | Yes |
| `ai_assistants` | 44 | 90 | Yes |
| `seo_tools` | 58 | 60 | Yes |
| `scrapers` | 47 | 85 | Yes |
| `bad_bots` | 59 | 95 | Yes |
| `data_harvesters` | 46 | 80 | Yes |
| `search_engines` | 37 | 30 | No (disabled) |

You can also define custom AI crawler user-agents in the `ai_crawlers` config section:

```php
'ai_crawlers' => [
    'enabled' => true,
    'user_agents' => [
        'GPTBot', 'ChatGPT-User', 'Claude-Web', 'ClaudeBot', 'anthropic-ai',
        'CCBot', 'PerplexityBot', 'YouBot', 'cohere-ai', 'AI2Bot',
        // Add your own...
    ],
],
```

### Prompt Injection

```php
'prompt_injection' => [
    'enabled' => true,
    'scan_inputs' => true,       // Scan POST/PUT/PATCH body
    'scan_query' => false,       // Scan GET query params
    'max_input_length' => 10000, // Skip inputs longer than this
],
```

### Honeypot Traps

```php
'honeypot' => [
    'enabled' => true,
    'trap_paths' => null,  // null = use default trap paths, or provide your own array
],
```

Default trap paths include `/admin-backup`, `/wp-admin`, `/.env`, `/.git/config`, `/api/v1/users.json`, `/backup.sql`, `/phpinfo.php`, and more. Any request to a trap path scores 100 confidence instantly.

> **Note:** Honeypot paths are checked against the request path exactly. If your app has a real route at any of these paths, override `trap_paths` with your own array to avoid conflicts.

### Response Scanning (PII Leak Detection)

```php
'response_scanning' => [
    'enabled' => false,           // Off by default — enable when your app has AI features
    'max_response_length' => 50000,
    'scan_email' => true,
    'scan_phone' => true,
    'scan_credit_card' => true,
    'scan_ssn' => true,
    'scan_api_key' => true,
    'scan_aws_key' => true,
    'scan_private_key' => true,
    'scan_jwt_token' => true,
    'scan_ip_address' => false,   // Disabled — too noisy for most apps
    'scan_database_url' => true,
],
```

Scans outgoing HTML, JSON, and text responses for leaked PII before they leave your server.

### robots.txt Enforcement

```php
'robots_txt' => [
    'enabled' => false,
    'confidence_boost' => 30,   // Extra points if bot violates Disallow rules
    'cache_minutes' => 60,
],
```

Parses your `public/robots.txt` and boosts confidence by 30 when a detected bot is crawling a disallowed path.

### Request Fingerprinting

```php
'fingerprinting' => [
    'enabled' => false,
    'min_score' => 30,
],
```

Analyzes 5 signals: missing browser headers, alphabetical header order, anomalous Accept header, no keep-alive, no navigation context. Catches bots that fake browser user-agent strings.

### ML Detection (Optional)

```php
'ml_detection' => [
    'enabled' => false,           // Off by default — package stays lightweight
    'driver' => 'lakera',         // lakera, huggingface, pangea, llm_guard, ollama, custom
    'trigger_range' => [40, 85],  // Only call ML for borderline regex scores
    'regex_weight' => 0.4,        // Combined score: regex 40% + ML 60%
],
```

ML runs **only when regex flags something borderline** (score between 40-85). 99% of requests never touch ML.

| Driver | Provider | Cost | Latency | Data Privacy |
|--------|----------|------|---------|-------------|
| `lakera` | [Lakera Guard](https://platform.lakera.ai/) | 10K free/mo | 50-150ms | SaaS |
| `huggingface` | [Meta Prompt Guard](https://huggingface.co/meta-llama/Prompt-Guard-86M) | ~1K free/day | 200-500ms | SaaS |
| `pangea` | [Pangea AI Guard](https://pangea.cloud/) | Free community | 100-300ms | SaaS |
| `llm_guard` | [LLM Guard](https://llm-guard.com/) | Free (self-hosted) | 100-500ms | Self-hosted |
| `ollama` | [Ollama](https://ollama.com/) | Free | 50-200ms | Self-hosted |
| `custom` | Your own endpoint | Varies | Varies | You control |

To enable, add your API key to `.env` and set `enabled` to `true`:

```bash
# .env
AI_GUARD_LAKERA_KEY=your-key-here
```

```php
// config/ai-guard.php
'ml_detection' => [
    'enabled' => true,
    'driver' => 'lakera',
],
```

### Rate Limiting

```php
'rate_limiting' => [
    'enabled' => true,
    'max_attempts' => 60,
    'decay_minutes' => 1,
    'cache_driver' => 'default',
],
```

### Alerts

```php
'alerts' => [
    'slack_webhook' => null,                  // Your Slack webhook URL
    'alert_threshold' => 90,                  // Only alert above this score
    'alert_on' => ['block', 'rate_limited'],  // Which actions trigger alerts
],
```

### Dashboard & API Authentication

```php
'dashboard' => [
    'enabled' => true,
    'path' => 'ai-guard',
    'middleware' => ['web', 'auth'],       // Requires login by default
],

'api' => [
    'enabled' => true,
    'prefix' => 'ai-guard',
    'middleware' => ['api', 'auth:sanctum'],  // Requires Sanctum token by default
],
```

For local development without authentication:

```php
'dashboard' => ['middleware' => ['web']],
'api' => ['middleware' => ['api']],
```

> **Security note:** Always re-enable authentication before deploying to production. The dashboard and API expose IP addresses, request URLs, and threat data.

### False Positives

```php
'false_positives' => [
    'whitelist_ips' => [],
    'whitelist_user_agents' => [],
],
```

> **Important:** If you test your API with tools like Postman, Insomnia, or curl, add them to the whitelist. Otherwise your own test requests will be logged as threats.

```php
'false_positives' => [
    'whitelist_ips' => [
        '203.0.113.10',     // Your office IP
    ],
    'whitelist_user_agents' => [
        'PostmanRuntime',   // Postman
        'Insomnia',         // Insomnia
        'UptimeRobot',      // Uptime monitoring
        'Pingdom',          // Performance monitoring
    ],
],
```

## Dashboard

After installation, visit your dashboard at:

```
http://your-app.com/ai-guard
```

![Dashboard](https://via.placeholder.com/800x400?text=AI+Guard+Dashboard)

The dashboard shows:

- Total threats detected in the last 24 hours
- Breakdown by threat type (AI crawlers, prompt injections, data harvesters, honeypot traps, bad bots, PII leaks)
- Count of blocked and rate-limited requests
- Top threat sources and IP addresses
- Recent threat log with confidence scores and actions taken
- Auto-refreshes every 30 seconds

## REST API

All endpoints are prefixed with your configured prefix (default: `/ai-guard`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ai-guard/api/threats` | List threats (paginated, filterable) |
| GET | `/ai-guard/api/threats/{id}` | Get single threat details |
| GET | `/ai-guard/api/stats` | Threat summary counts |
| GET | `/ai-guard/api/top-sources` | Top threat sources ranked |
| GET | `/ai-guard/api/top-ips` | Top threat IPs ranked |
| GET | `/ai-guard/api/timeline` | Hourly threat timeline |
| GET | `/ai-guard/api/confidence-breakdown` | High/medium/low breakdown |
| GET | `/ai-guard/api/detector-info` | Detector config and pattern counts |
| POST | `/ai-guard/api/threats/{id}/false-positive` | Mark threat as false positive |
| DELETE | `/ai-guard/api/flush` | Delete threat logs (requires `?confirm=yes`) |

### Query Parameters

**GET /ai-guard/api/threats**

| Parameter | Default | Description |
|-----------|---------|-------------|
| hours | 24 | Lookback window (max 8760) |
| limit | 50 | Results per page (max 200) |
| threat_type | — | Filter: `ai_crawler`, `prompt_injection`, `data_harvester`, `honeypot_trap`, `pii_leak`, `bad_bot`, `scraper`, `seo_bot` |
| action_taken | — | Filter: `logged`, `blocked`, `rate_limited` |

## Artisan Command

```bash
php artisan ai-guard:stats
php artisan ai-guard:stats --hours=48
```

## Detection Details

### Bot Signatures (354 bots in 7 categories)

**AI Training Bots** (63 bots, confidence: 95) — GPTBot, ChatGPT-User, ClaudeBot, CCBot, Bytespider, Diffbot, DeepSeekBot, TikTokSpider, Google-CloudVertexBot, cohere-training-data-crawler, and more.

**AI Assistants** (44 bots, confidence: 90) — PerplexityBot, YouBot, PhindBot, KagiBot, Claude-SearchBot, Gemini-Deep-Research, DuckAssistBot, MistralAI-User, and more.

**SEO Tools** (58 bots, confidence: 60) — AhrefsBot, SemrushBot, MJ12bot, DotBot, DataForSeoBot, Seobility, XoviBot, BrightEdge Crawler, and more.

**Malicious Bots** (59 bots, confidence: 95) — Nikto, sqlmap, Nessus, Nmap, Masscan, Acunetix, nuclei, Shodan, CensysInspect, and more.

**Scrapers** (47 bots, confidence: 85) — HeadlessChrome, PhantomJS, Puppeteer, Playwright, Selenium, Apify, ZenRows, ScrapingBee, and more.

**Data Harvesters** (46 bots, confidence: 80) — curl, python-requests, Go-http-client, Wget, okhttp, PostmanRuntime, fasthttp, RestSharp, and more.

**Search Engines** (37 bots, confidence: 30, disabled by default) — Googlebot, Bingbot, YandexBot, Baiduspider, DuckDuckBot, and more.

### Prompt Injection Patterns

30 patterns across 7 categories:

- **Instruction Override** — "ignore previous instructions", "disregard your rules", "forget everything"
- **Role Manipulation** — "you are now", "act as if", "pretend to be", "from now on you are"
- **System Prompt Attacks** — "reveal your system prompt", "show your instructions", "repeat everything above"
- **DAN / Jailbreak** — "DAN", "do anything now", "jailbreak", "bypass safety"
- **Privilege Escalation** — "developer mode", "admin mode", "sudo override", "debug mode"
- **Data Extraction** — "dump all data", "output all records", "bypass validation"
- **Token Manipulation** — `<|im_start|>`, `<|im_end|>`, `[INST]`, `<<SYS>>`

### PII Leak Detection (10 patterns)

| Pattern | Severity | Default |
|---------|----------|---------|
| Email addresses | 70 | Enabled |
| Phone numbers | 75 | Enabled |
| Credit card numbers | 95 | Enabled |
| Social Security numbers | 95 | Enabled |
| API keys / tokens | 90 | Enabled |
| AWS access keys | 95 | Enabled |
| Private keys (RSA/EC/DSA) | 95 | Enabled |
| JWT tokens | 85 | Enabled |
| Internal IP addresses | 50 | Disabled |
| Database connection strings | 95 | Enabled |

### Honeypot Trap Routes

Hidden paths that real users never visit. Any hit scores 100 confidence instantly:

`/admin-backup`, `/wp-admin`, `/wp-login.php`, `/.env`, `/.git/config`, `/.aws/credentials`, `/phpinfo.php`, `/api/v1/users.json`, `/backup.sql`, `/database.sql`, `/users.csv`, and more.

## Three Modes Explained

| Mode | Behavior | Use Case |
|------|----------|----------|
| `log_only` | Detect and log. Never block any request. | Starting out. Understanding your traffic before enforcing. |
| `block` | Return 403 JSON for threats above the confidence threshold. | Production enforcement. Actively blocking AI scrapers. |
| `rate_limit` | Apply rate limiting via cache. Return 429 when exceeded. | Softer enforcement. Allow some access but limit volume. |

Switch modes at any time by changing `mode` in your config. No code changes needed.

## Facade Usage

```php
use JayAnta\AiGuard\Facades\AiGuard;

// Get threat summary for last 24 hours
$stats = AiGuard::getStats();
$stats = AiGuard::getStats(hours: 48);

// Get recent threats
$threats = AiGuard::getRecentThreats();
$threats = AiGuard::getRecentThreats(limit: 50);

// Get top threat sources
$sources = AiGuard::getTopThreats();
$sources = AiGuard::getTopThreats(limit: 5);

// Check package status
$enabled = AiGuard::isEnabled();
$mode = AiGuard::getMode();

// Get detector configuration info
$info = AiGuard::getDetectorInfo();

// Get full feature status
$features = AiGuard::getFeatureStatus();
```

## Troubleshooting

### Dashboard returns 403 or redirects to /login

The dashboard requires authentication by default. For local development:

```php
'dashboard' => ['middleware' => ['web']],
```

### My own curl/Postman requests are being logged as threats

Add your testing tools to the whitelist:

```php
'false_positives' => [
    'whitelist_user_agents' => ['PostmanRuntime', 'Insomnia'],
],
```

### Honeypot conflicts with my real routes

If your app has routes like `/admin` or `/api/v1/users.json`, override the trap paths:

```php
'honeypot' => [
    'trap_paths' => [
        '/.env',
        '/.git/config',
        '/backup.sql',
        '/wp-login.php',
        // Only paths your app does NOT use
    ],
],
```

### Everything is being blocked (403)

Check that `mode` is set to `log_only` (not `block`) and that `confidence_threshold` is appropriate:

```php
'mode' => 'log_only',             // Start here
'confidence_threshold' => 70,     // Lower = more blocking
```

### The table ai_threat_logs doesn't exist

Run the migration:

```bash
php artisan vendor:publish --tag=ai-guard-migrations
php artisan migrate
```

### Config changes aren't taking effect

Clear the config cache:

```bash
php artisan config:clear
```

### SEO bots (AhrefsBot, SemrushBot) are being logged

SEO tools score 60 confidence by default. If you use these tools and don't want them logged, either:

- Add them to your whitelist: `'whitelist_user_agents' => ['AhrefsBot', 'SemrushBot']`
- Or disable the `seo_tools` category: `'disabled_categories' => ['search_engines', 'seo_tools']`

### The package is slowing down my app

AI Guard adds ~1ms per request in regex-only mode. If you notice slowness:

- Disable response scanning (it scans every outgoing response body)
- Disable fingerprinting (it analyzes headers on every request)
- Ensure ML detection is disabled unless you need it
- Check that your `ai_threat_logs` table has indexes (they're created by the migration)

## Testing

```bash
composer test
```

The test suite includes 53 full-cycle tests with 492 assertions:

- **Feature tests (18)** — Complete request -> middleware -> detection -> database logging -> model queries -> stats pipeline
- **Unit tests (35)** — AiDetector and PromptInjectionDetector covering all 7 attack categories, confidence stacking, whitelist bypass, config toggles, recursive scanning, and edge cases

## Changelog

### 2.0.0

- 354 curated bot signatures across 7 categories with per-category confidence scoring
- Honeypot trap routes (30 default paths, instant 100 confidence)
- PII leak detection — scans outgoing responses for 10 sensitive data patterns
- robots.txt enforcement — boosts confidence when bots violate Disallow rules
- Request fingerprinting — 5-signal analysis to detect bots faking browser UAs
- Optional ML detection — 6 pluggable providers (Lakera, HuggingFace, Pangea, LLM Guard, Ollama, custom), zero dependencies
- New threat types: honeypot_trap, pii_leak, bad_bot, scraper, seo_bot, suspicious_fingerprint
- New query scopes: honeypotTraps(), piiLeaks(), badBots(), scrapers()
- Expanded stats: honeypot_traps, pii_leaks, bad_bots, scrapers in getThreatSummary()
- getFeatureStatus() facade method for full feature overview

### 1.0.0

- AI crawler detection (20+ bots)
- Prompt injection detection (30 patterns across 7 categories)
- Data harvester detection
- Three operating modes: log_only, block, rate_limit
- Dashboard with real-time stats and auto-refresh
- 10 REST API endpoints
- Artisan `ai-guard:stats` command
- Slack webhook alerts for high-confidence threats
- IP and user-agent whitelisting
- Full test suite with CI matrix (PHP 8.1-8.3, Laravel 10-12)

## Credits

Created by [Jay Anta](mailto:jay123anta@gmail.com).

## License

The MIT License (MIT). See [LICENSE](LICENSE) for more information.
