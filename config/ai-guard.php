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

    // -------------------------------------------------------------------------
    // v2 Features
    // -------------------------------------------------------------------------

    // Categorized bot signatures (150+ bots in 7 categories)
    'bot_signatures' => [
        // Enable categorized bot detection
        'enabled' => true,

        // Categories to DISABLE (search_engines disabled by default — don't block Google)
        'disabled_categories' => ['search_engines'],
    ],

    // Honeypot trap routes — hidden paths no real user would visit
    'honeypot' => [
        // Enable honeypot detection
        'enabled' => true,

        // Trap paths — any request to these paths = instant 100 confidence
        // Override with your own paths, or leave null to use defaults
        'trap_paths' => null,
    ],

    // Response scanning — detect PII leaking in outgoing responses
    'response_scanning' => [
        // Enable response scanning (scans HTML/JSON/text responses)
        'enabled' => false,

        // Max response size to scan (bytes) — skip large responses
        'max_response_length' => 50000,

        // Toggle individual PII types
        'scan_email' => true,
        'scan_phone' => true,
        'scan_credit_card' => true,
        'scan_ssn' => true,
        'scan_api_key' => true,
        'scan_aws_key' => true,
        'scan_private_key' => true,
        'scan_jwt_token' => true,
        'scan_ip_address' => false,       // Disabled — too noisy for most apps
        'scan_database_url' => true,
    ],

    // robots.txt enforcement — boost confidence if bot ignores Disallow rules
    'robots_txt' => [
        // Enable robots.txt compliance checking
        'enabled' => false,

        // Extra confidence points if bot violates robots.txt
        'confidence_boost' => 30,

        // Cache robots.txt parsing (minutes)
        'cache_minutes' => 60,
    ],

    // Request fingerprinting — detect bots faking browser user-agents
    'fingerprinting' => [
        // Enable fingerprint analysis
        'enabled' => false,

        // Minimum suspicion score to flag (0-100)
        'min_score' => 30,
    ],

    // ML-based detection — optional, zero dependencies, one Http::post() call
    // Enhances regex detection with ML for borderline cases
    'ml_detection' => [
        // Enable ML detection (off by default — package stays lightweight)
        'enabled' => false,

        // ML provider: 'lakera', 'huggingface', 'pangea', 'llm_guard', 'ollama', 'custom'
        'driver' => 'lakera',

        // Only call ML when regex confidence is within this range
        // Below min = too low to bother, above max = regex is confident enough
        'trigger_range' => [40, 85],

        // Score weighting: regex_weight + ml_weight = 1.0
        'regex_weight' => 0.4,

        'drivers' => [
            // Lakera Guard — fastest (50-150ms), best accuracy, 10K free/month
            // Sign up: https://platform.lakera.ai/
            'lakera' => [
                'api_key' => env('AI_GUARD_LAKERA_KEY'),
                'url' => 'https://api.lakera.ai/v2/guard',
                'timeout' => 3,
            ],

            // HuggingFace — Meta Prompt Guard model, ~1K free/day
            // Sign up: https://huggingface.co/ (free account + API token)
            'huggingface' => [
                'api_key' => env('AI_GUARD_HF_KEY'),
                'model' => 'meta-llama/Prompt-Guard-86M',
                'timeout' => 5,
            ],

            // Pangea AI Guard — free community plan, also does PII
            // Sign up: https://pangea.cloud/
            'pangea' => [
                'api_key' => env('AI_GUARD_PANGEA_KEY'),
                'url' => 'https://ai-guard.us.aws.pangea.cloud/v1/text/guard',
                'recipe' => 'pangea_prompt_guard',
                'timeout' => 3,
            ],

            // LLM Guard — self-hosted, MIT, zero vendor lock-in
            // Deploy: docker run -p 8000:8000 protectai/llm-guard-api
            'llm_guard' => [
                'url' => 'http://localhost:8000/analyze/prompt',
                'timeout' => 3,
            ],

            // Ollama — local LLM, completely self-hosted, no data leaves server
            // Install: https://ollama.com/ then: ollama pull llama3.2:1b
            'ollama' => [
                'url' => 'http://localhost:11434/api/generate',
                'model' => 'llama3.2:1b',
                'timeout' => 5,
            ],

            // Your own endpoint — must return JSON with a score field
            'custom' => [
                'url' => env('AI_GUARD_ML_URL'),
                'api_key' => env('AI_GUARD_ML_KEY'),
                'headers' => [],
                'score_field' => 'score',
                'timeout' => 3,
            ],
        ],
    ],

];
