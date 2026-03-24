# Laravel AI Guard

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![Total Downloads](https://img.shields.io/packagist/dt/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![PHP Version](https://img.shields.io/packagist/php-v/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![Laravel Version](https://img.shields.io/badge/laravel-10.x%20%7C%2011.x%20%7C%2012.x-blue?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![License](https://img.shields.io/packagist/l/jayanta/laravel-ai-guard.svg?style=flat-square)](https://packagist.org/packages/jayanta/laravel-ai-guard)
[![Tests](https://img.shields.io/github/actions/workflow/status/jay123anta/laravel-ai-guard/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/jay123anta/laravel-ai-guard/actions)

Protect your Laravel app from AI scrapers, LLM crawlers, and prompt injection attacks.

## What It Does

Laravel AI Guard is a middleware-based security package that detects and blocks AI-related threats to your application. It identifies 20+ known AI crawler user-agents (GPTBot, ClaudeBot, CCBot, and others), scans incoming requests for prompt injection attacks targeting your AI features, and flags data harvesters using generic automation tools. All detections are logged to your database with a built-in dashboard for monitoring.

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

### AI Crawlers

```php
'ai_crawlers' => [
    'enabled' => true,
    'user_agents' => [
        'GPTBot', 'ChatGPT-User', 'Claude-Web', 'ClaudeBot', 'anthropic-ai',
        'CCBot', 'PerplexityBot', 'YouBot', 'cohere-ai', 'AI2Bot',
        'Bytespider', 'Diffbot', 'ImagesiftBot', 'Omgilibot', 'Applebot-Extended',
        'DataForSeoBot', 'PetalBot', 'Scrapy', 'AhrefsBot', 'SemrushBot',
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

### Data Harvesters

```php
'data_harvesters' => [
    'enabled' => true,
    'check_accept_language' => true,  // Flag missing Accept-Language header
    'check_sequential_urls' => false, // Disabled by default (too noisy)
    'generic_user_agents' => [
        'curl', 'python-requests', 'Go-http-client', 'Java/',
        'libwww-perl', 'Wget', 'HTTPie', 'axios', 'node-fetch',
    ],
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

### Dashboard

```php
'dashboard' => [
    'enabled' => true,
    'path' => 'ai-guard',        // Available at /ai-guard
    'middleware' => ['web'],
],
```

### API

```php
'api' => [
    'enabled' => true,
    'prefix' => 'ai-guard',      // Routes at /ai-guard/api/*
    'middleware' => ['api'],
],
```

### False Positives

```php
'false_positives' => [
    'whitelist_ips' => [],           // IPs that are never flagged
    'whitelist_user_agents' => [],   // User-agents that are never flagged
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
- Breakdown by threat type (AI crawlers, prompt injections, data harvesters)
- Count of blocked and rate-limited requests
- Top threat sources and IP addresses
- Recent threat log with confidence scores and actions taken
- Auto-refreshes every 30 seconds

By default, the dashboard requires authentication (`['web', 'auth']`). The API requires `auth:sanctum`. You can customize this in `config/ai-guard.php`:

```php
// Dashboard — remove 'auth' for local dev without login
'dashboard' => [
    'middleware' => ['web'],
],

// API — use a different guard if needed
'api' => [
    'middleware' => ['api', 'auth:api'],
],
```

> **Security note:** Never expose the dashboard or API without authentication in production. The endpoints display IP addresses, request URLs, and threat data.

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
| DELETE | `/ai-guard/api/flush` | Delete threat logs |

### Query Parameters

**GET /ai-guard/api/threats**

| Parameter | Default | Description |
|-----------|---------|-------------|
| hours | 24 | Lookback window |
| limit | 50 | Results per page |
| threat_type | — | Filter: `ai_crawler`, `prompt_injection`, `data_harvester` |
| action_taken | — | Filter: `logged`, `blocked`, `rate_limited` |

**DELETE /ai-guard/api/flush**

| Parameter | Default | Description |
|-----------|---------|-------------|
| hours | — | Delete records older than N hours. Omit to delete all. |

## Artisan Command

```bash
php artisan ai-guard:stats
```

```bash
php artisan ai-guard:stats --hours=48
```

Example output:

```
AI Guard — Threat Statistics (last 24 hours)
──────────────────────────────────────────────────

+---------------------------+-------+
| Metric                    | Count |
+---------------------------+-------+
| Total Threats Detected    | 142   |
| AI Crawlers               | 89    |
| Prompt Injections         | 12    |
| Data Harvesters           | 41    |
| Requests Blocked          | 34    |
| Requests Rate Limited     | 17    |
+---------------------------+-------+

Top Threat IPs:
+----------------+------+----------------+
| IP Address     | Hits | Max Confidence |
+----------------+------+----------------+
| 45.33.32.156   | 38   | 95             |
| 91.108.4.0     | 22   | 95             |
| 203.0.113.50   | 15   | 80             |
+----------------+------+----------------+

Top Threat Sources:
+------------------+------+
| Source           | Hits |
+------------------+------+
| GPTBot           | 45   |
| ClaudeBot        | 28   |
| curl             | 19   |
+------------------+------+

Confidence Breakdown:
+----------------+-------+
| Level          | Count |
+----------------+-------+
| High (90+)     | 89    |
| Medium (70-89) | 41    |
| Low (<70)      | 12    |
+----------------+-------+
```

## Detection Details

### AI Crawlers Detected

| Bot Name | Company | Purpose |
|----------|---------|---------|
| GPTBot | OpenAI | Training data collection |
| ChatGPT-User | OpenAI | ChatGPT browsing feature |
| Claude-Web | Anthropic | Claude web browsing |
| ClaudeBot | Anthropic | Training data collection |
| anthropic-ai | Anthropic | General crawling |
| CCBot | Common Crawl | Open web corpus |
| PerplexityBot | Perplexity AI | Search index |
| YouBot | You.com | Search index |
| cohere-ai | Cohere | Training data collection |
| AI2Bot | Allen AI | Research crawling |
| Bytespider | ByteDance | Training data collection |
| Diffbot | Diffbot | Structured data extraction |
| ImagesiftBot | Imagesift | Image indexing |
| Omgilibot | Omgili | Discussion crawling |
| Applebot-Extended | Apple | Extended crawling for AI |
| DataForSeoBot | DataForSEO | SEO data collection |
| PetalBot | Huawei | Search index |
| Scrapy | Open source | Web scraping framework |
| AhrefsBot | Ahrefs | SEO crawling |
| SemrushBot | Semrush | SEO crawling |

### Prompt Injection Patterns

30 patterns across 7 categories:

- **Instruction Override** — "ignore previous instructions", "disregard your rules", "forget everything"
- **Role Manipulation** — "you are now", "act as if", "pretend to be", "from now on you are"
- **System Prompt Attacks** — "reveal your system prompt", "show your instructions", "repeat everything above"
- **DAN / Jailbreak** — "DAN", "do anything now", "jailbreak", "bypass safety"
- **Privilege Escalation** — "developer mode", "admin mode", "sudo override", "debug mode"
- **Data Extraction** — "dump all data", "output all records", "bypass validation"
- **Token Manipulation** — `<|im_start|>`, `<|im_end|>`, `[INST]`, `<<SYS>>`

### Data Harvester Signals

Detection triggers:

- Generic automation user-agents: curl, python-requests, Go-http-client, Wget, and others
- Missing `Accept-Language` header (adds +20 to confidence score)
- Combined signals stack: a curl request with no Accept-Language scores 100

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
```

## False Positives

Whitelist trusted IPs and user-agents in `config/ai-guard.php`:

```php
'false_positives' => [
    'whitelist_ips' => [
        '203.0.113.10',    // Your monitoring service
        '198.51.100.0',    // Your partner's crawler
    ],
    'whitelist_user_agents' => [
        'UptimeRobot',     // Uptime monitoring
        'Pingdom',         // Performance monitoring
    ],
],
```

Whitelisted requests skip all detection entirely — they are never logged or flagged.

You can also mark individual threat logs as false positives via the API:

```bash
curl -X POST http://your-app.com/ai-guard/api/threats/42/false-positive
```

## Testing

```bash
composer test
```

The test suite includes 53 full-cycle tests with 492 assertions:

- **Feature tests (18)** — Complete request → middleware → detection → database logging → model queries → stats pipeline
- **Unit tests (35)** — AiDetector and PromptInjectionDetector covering all 7 attack categories, confidence stacking, whitelist bypass, config toggles, recursive scanning, and edge cases

## Changelog

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
