# Changelog

All notable changes to `jayanta/laravel-ai-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
