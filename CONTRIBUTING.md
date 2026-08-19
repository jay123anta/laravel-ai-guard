# Contributing

Thanks for considering contributing to Laravel AI Guard!

## Reporting Issues

- **Security vulnerabilities**: see [SECURITY.md](SECURITY.md) — do not open a public issue.
- **Detection gaps** (a bot or injection payload that slips through): open an issue with the user-agent string or payload. New signatures are the most valuable contribution this package gets.
- **False positives** (legitimate traffic being flagged): open an issue with the user-agent / payload and which detector flagged it.
- **Bugs**: use the bug report template and include your PHP, Laravel, and package versions.

## Development Setup

```bash
git clone https://github.com/jay123anta/laravel-ai-guard.git
cd laravel-ai-guard
composer install
```

## Before Submitting a PR

Run the full check suite locally:

```bash
composer test        # PHPUnit test suite
composer analyse     # PHPStan static analysis
composer format      # Laravel Pint code style (auto-fixes)
```

All three must pass in CI before a PR is merged.

## Guidelines

- **Add tests** for any new detector, signature category, config option, or bug fix.
- **New bot signatures** go in `src/Services/BotSignatures.php` in the correct category — include a comment linking the bot's documentation or observed user-agent if it's obscure.
- **New prompt injection patterns** go in `src/Services/PromptInjectionDetector.php` with a test case in `tests/Unit/PromptInjectionDetectorTest.php` covering both a match and a near-miss (to guard against false positives).
- **Keep zero runtime dependencies** beyond `illuminate/*`. ML integrations must stay optional and HTTP-based.
- **Update the CHANGELOG** under an `Unreleased` heading, following [Keep a Changelog](https://keepachangelog.com/).
- **One feature or fix per PR** — small PRs get reviewed faster.

## Style

Code style is enforced by [Laravel Pint](https://laravel.com/docs/pint) with the config in `pint.json`. Run `composer format` before committing; CI will fail on style violations.
