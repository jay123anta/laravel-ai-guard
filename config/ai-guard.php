<?php

return [

    // Master switch. Set to false to disable all detection.
    'enabled' => true,

    // Options: 'log_only', 'block', 'rate_limit'
    // log_only: detect and log, never block
    // block: return 403 for threats above threshold
    // rate_limit: apply rate limiting via cache
    'mode' => 'log_only',

    // Minimum confidence score (0-100) to trigger action in block/rate_limit mode
    'confidence_threshold' => 70,

    // AI crawler detection settings
    'ai_crawlers' => [
        // Enable AI crawler detection
        'enabled' => true,

        // Known AI crawler user-agent strings
        'user_agents' => [
            'GPTBot',
            'ChatGPT-User',
            'Claude-Web',
            'ClaudeBot',
            'anthropic-ai',
            'CCBot',
            'PerplexityBot',
            'YouBot',
            'cohere-ai',
            'AI2Bot',
            'Bytespider',
            'Diffbot',
            'ImagesiftBot',
            'Omgilibot',
            'Applebot-Extended',
            'DataForSeoBot',
            'PetalBot',
            'Scrapy',
            'AhrefsBot',
            'SemrushBot',
        ],
    ],

    // Prompt injection detection settings
    'prompt_injection' => [
        // Enable prompt injection scanning
        'enabled' => true,

        // Scan POST/PUT/PATCH request inputs
        'scan_inputs' => true,

        // Scan GET query parameters
        'scan_query' => false,

        // Skip scanning inputs longer than this many characters
        'max_input_length' => 10000,
    ],

    // Data harvester detection settings
    'data_harvesters' => [
        // Enable data harvester detection
        'enabled' => true,

        // Flag requests missing Accept-Language header
        'check_accept_language' => true,

        // Flag sequential URL patterns (disabled by default, too noisy)
        'check_sequential_urls' => false,

        // Known generic/scripted user-agent strings
        'generic_user_agents' => [
            'curl',
            'python-requests',
            'Go-http-client',
            'Java/',
            'libwww-perl',
            'Wget',
            'HTTPie',
            'axios',
            'node-fetch',
        ],
    ],

    // Rate limiting settings (used when mode is 'rate_limit')
    'rate_limiting' => [
        // Enable rate limiting
        'enabled' => true,

        // Maximum requests allowed within the decay window
        'max_attempts' => 60,

        // Decay window in minutes
        'decay_minutes' => 1,

        // Cache driver to use ('default' uses your app's default cache driver)
        'cache_driver' => 'default',
    ],

    // Logging settings
    'logging' => [
        // Enable logging to database
        'enabled' => true,

        // Log channel to use (uses your app's default log channel)
        'channel' => 'stack',

        // Snapshot request headers into headers_snapshot column
        'log_headers' => true,

        // Truncate payload_snippet to this many characters
        'max_payload_length' => 500,
    ],

    // Alert settings
    'alerts' => [
        // Slack webhook URL for high-confidence alerts (null to disable)
        'slack_webhook' => null,

        // Only alert on confidence scores above this value
        'alert_threshold' => 90,

        // Which action_taken values trigger an alert
        'alert_on' => ['block', 'rate_limited'],
    ],

    // Dashboard settings
    'dashboard' => [
        // Enable the web dashboard
        'enabled' => true,

        // Dashboard URL path (available at /ai-guard)
        'path' => 'ai-guard',

        // Middleware applied to dashboard routes
        // IMPORTANT: Add 'auth' to require login in production
        'middleware' => ['web', 'auth'],
    ],

    // API settings
    'api' => [
        // Enable the API endpoints
        'enabled' => true,

        // API route prefix (routes at /ai-guard/api/*)
        'prefix' => 'ai-guard',

        // Middleware applied to API routes
        // IMPORTANT: Add authentication middleware in production (e.g. 'auth:sanctum')
        'middleware' => ['api', 'auth:sanctum'],
    ],

    // False positive management
    'false_positives' => [
        // IPs that are never flagged (add your own crawlers, monitoring tools)
        'whitelist_ips' => [],

        // User-agent strings that are never flagged
        'whitelist_user_agents' => [],
    ],

];
