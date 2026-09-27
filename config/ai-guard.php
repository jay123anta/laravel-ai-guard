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

        // Extra AI crawler user-agent tokens to flag at confidence 95.
        // Only for tokens NOT in the built-in signature database — known tokens
        // are scored by their category (bot_signatures) and entries for them here are ignored.
        'user_agents' => [],
    ],

    // Prompt injection detection settings
    'prompt_injection' => [
        // Enable prompt injection scanning
        'enabled' => true,

        // Scan request input: the body and the query string, whatever the method
        'scan_inputs' => true,

        // Scan the query string even when scan_inputs is off
        'scan_query' => false,

        // Input longer than this is scanned in overlapping windows rather than skipped,
        // so padding a payload cannot walk it past the patterns
        'max_input_length' => 10000,

        // Minimum combined score (0-100) for an input to count as an injection.
        // Every pattern carries a weight; weak phrases ("debug mode", "act as a")
        // stay below this on their own and only count in combination.
        'min_score' => 50,

        // Normalize Unicode tricks (zero-width, fullwidth, homoglyphs, tag
        // characters) and decode base64 / URL / HTML-entity payloads before matching
        'deobfuscate' => true,

        // Your own patterns, scored like the built-in ones:
        // ['id' => 'internal_codename', 'pattern' => 'project\s+nightingale', 'weight' => 90]
        'custom_patterns' => [],
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
        // Applies in 'rate_limit' mode; false logs the threat without limiting the client.
        // Counters use Laravel's rate limiter, which runs on your default cache store.
        'enabled' => true,

        // Maximum requests allowed within the decay window
        'max_attempts' => 60,

        // Decay window in minutes
        'decay_minutes' => 1,
    ],

    // Logging settings
    'logging' => [
        // Enable logging to database
        'enabled' => true,

        // Snapshot request headers into headers_snapshot column
        'log_headers' => true,

        // Truncate payload_snippet to this many characters
        'max_payload_length' => 500,
    ],

    // Audit trail and export
    'audit' => [
        // Tamper-evident log: each row stores an HMAC of the previous row's hash and its own
        // contents (needs the v3 upgrade migration). Check it: php artisan ai-guard:audit-verify
        'hash_chain' => false,

        // Key for the chain HMAC (null = your APP_KEY)
        'chain_key' => null,

        // Where ai-guard:prune records the last deleted row (null = storage/app/ai-guard/audit-anchor.json)
        'anchor_path' => null,

        // Delete logs older than this many days with `php artisan ai-guard:prune` (null = keep them)
        'retention_days' => null,

        // Events held for one export flush; beyond this the rest are dropped and a warning is logged
        'max_buffered' => 500,

        // Mask secrets and personal data in the captured payload before it is exported
        'redact_payloads' => true,

        // Send every threat to your SIEM when the request ends
        'siem' => [
            'url' => env('AI_GUARD_SIEM_URL'),

            // json | cef (ArcSight Common Event Format)
            'format' => 'json',

            // Signs the body: X-AI-Guard-Signature: sha256=<HMAC-SHA256 of the body>
            'secret' => env('AI_GUARD_SIEM_SECRET'),
            'timeout' => 3,
        ],

        // OpenTelemetry: threats and model token usage as OTLP/HTTP (JSON) log records
        'otlp' => [
            // e.g. http://localhost:4318 (/v1/logs is added)
            'endpoint' => env('AI_GUARD_OTLP_ENDPOINT'),
            'headers' => [],
            'service_name' => env('APP_NAME', 'laravel'),

            // Also send gen_ai token usage recorded by budgets and laravel/ai agents
            'usage' => true,
            'timeout' => 3,
        ],

        // Also write every threat to this log channel (null = off)
        'log_channel' => null,
    ],

    // Alert settings
    'alerts' => [
        // Slack webhook URL for high-confidence alerts (null to disable)
        'slack_webhook' => null,

        // Only alert on confidence scores above this value
        'alert_threshold' => 90,

        // Which action_taken values trigger an alert ('logged', 'blocked', 'rate_limited')
        // Remove 'logged' to only alert when a request was actually blocked/rate limited
        'alert_on' => ['logged', 'blocked', 'rate_limited'],
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

    // Categorized bot signatures. AI bots are split by purpose:
    //   ai_training (95) — collects content to train models (GPTBot, ClaudeBot, CCBot)
    //   ai_search   (65) — builds AI answer indexes (OAI-SearchBot, Claude-SearchBot, PerplexityBot)
    //   ai_agents   (60) — live fetches for a user (ChatGPT-User, Claude-User, Perplexity-User)
    // Blocking training costs you nothing in AI answers; blocking search/agents removes
    // you from them. With the default threshold (70), block mode stops training
    // crawlers but only logs AI search and agents.
    'bot_signatures' => [
        // Enable categorized bot detection
        'enabled' => true,

        // Categories to DISABLE (search_engines disabled by default — don't block Google).
        // The v2 name 'ai_assistants' is accepted and means ai_search + ai_agents.
        'disabled_categories' => ['search_engines'],

        // Per-category confidence overrides — your per-purpose policy.
        // Example: ['ai_agents' => 90] blocks user-triggered AI fetches in block mode.
        'confidence' => [],

        // Extra tokens from the community ai.robots.txt list (MIT licence), added by
        // `php artisan ai-guard:update-signatures`. Nothing is fetched unless you run
        // (or schedule) that command; saved tokens are loaded on boot.
        'feed' => [
            'enabled' => true,
            'url' => 'https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json',

            // Where the tokens are saved (null = storage/app/ai-guard/bot-signatures.json)
            'path' => null,
        ],
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

        // AI-era secrets
        'scan_anthropic_key' => true,
        'scan_openai_key' => true,
        'scan_github_token' => true,
        'scan_huggingface_token' => true,
        'scan_google_api_key' => true,
        'scan_slack_token' => true,

        // Indirect prompt injection (opt-in): flag instructions hidden from human
        // readers but read by AI agents — HTML comments, display:none / hidden /
        // aria-hidden / zero-size / off-screen elements, and invisible Unicode tag text.
        // Useful when pages render user-generated content (reviews, profiles, comments).
        'scan_hidden_injection' => false,
    ],

    // robots.txt enforcement — boost confidence if bot ignores Disallow rules
    'robots_txt' => [
        // Enable robots.txt compliance checking
        'enabled' => false,

        // Extra confidence points if bot violates robots.txt
        'confidence_boost' => 30,

        // Cache robots.txt parsing (minutes)
        'cache_minutes' => 60,

        // Path to robots.txt (null = public_path('robots.txt'))
        'path' => null,
    ],

    // Request fingerprinting — detect bots faking browser user-agents
    'fingerprinting' => [
        // Enable fingerprint analysis
        'enabled' => false,

        // Minimum suspicion score to flag (0-100)
        'min_score' => 30,

        // What your CDN saw at the edge. Read only from requests that came through a trusted
        // proxy (configure Laravel's TrustProxies), because anyone can send these headers.
        'edge' => [
            'enabled' => true,
            'require_trusted_proxy' => true,

            // Headers holding the client's JA4 TLS fingerprint: CloudFront sends
            // CloudFront-Viewer-JA4-Fingerprint; on Cloudflare add cf-ja4 with a transform rule
            // (value: cf.bot_management.ja4). A browser user-agent with a non-browser JA4 is flagged.
            'ja4_headers' => ['cf-ja4', 'cloudfront-viewer-ja4-fingerprint', 'x-ja4'],

            // JA4 fingerprints, or JA4_a prefixes such as 't13d1812h1', of HTTP clients to flag
            'client_ja4' => [],

            // Bot score header (Cloudflare: 1 = automated ... 99 = human; add it with a transform
            // rule, value cf.bot_management.score). Scores from 1 to the threshold are flagged.
            'bot_score_header' => 'cf-bot-score',
            'bot_score_threshold' => 29,
        ],

        // A browser user-agent from a cloud network. Weak evidence on its own (VPNs, corporate
        // proxies), so it only adds to the other signals. Warm the lists: ai-guard:refresh-ranges
        'datacenter' => [
            'enabled' => false,
            'score' => 25,

            // Range list URLs and/or CIDRs, per network
            'ranges' => [
                'aws' => 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'gcp' => 'https://www.gstatic.com/ipranges/cloud.json',
                'oracle' => 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json',
            ],

            // Fetch a list during a request when its cache is cold (false = only ai-guard:refresh-ranges does)
            'fetch_on_request' => true,
            'cache_minutes' => 1440,
            'timeout' => 5,
        ],
    ],

    // Bot verification — prove a crawler is who it claims to be. A request that
    // claims a verifiable crawler (e.g. "Googlebot") but fails every check that
    // could run is logged as 'spoofed_bot'. Verdicts land in bot_verification.
    'bot_verification' => [
        // Off by default: makes reverse-DNS lookups and fetches published IP range lists (all cached)
        'enabled' => false,

        // Tried in this order; the first that confirms wins
        'methods' => ['web_bot_auth', 'ip_ranges', 'reverse_dns'],

        // Cache for verdicts, range lists, and key directories (minutes). Failed lookups retry after 5 minutes.
        'cache_minutes' => 1440,

        // Score for a request whose claimed crawler identity fails verification
        'spoofed_confidence' => 90,

        // HTTP timeout (seconds) for fetching range lists
        'timeout' => 3,

        // Web Bot Auth (HTTP Message Signatures, RFC 9421). Signed agents are
        // identified even when they browse with an ordinary Chrome user-agent.
        'web_bot_auth' => [
            // Signature-Agent values whose key directory may be fetched
            'trusted_agents' => ['https://chatgpt.com'],

            // true = accept any https Signature-Agent that resolves to a public host
            'allow_any_agent' => false,

            // Pin a key directory URL: ['https://agent.example' => 'https://agent.example/keys.json']
            'directory_overrides' => [],

            // Category recorded for verified signed agents
            'category' => 'ai_agents',

            // Accepted signature age when no expires parameter is sent, and clock skew (seconds)
            'max_age' => 300,
            'clock_skew' => 30,

            'timeout' => 3,
        ],

        // Crawlers that can be verified: published IP range lists and/or reverse-DNS suffixes.
        // Reverse DNS is forward-confirmed (the hostname must resolve back to the same IP).
        'crawlers' => [
            'Googlebot' => [
                'ip_ranges' => ['https://developers.google.com/static/search/apis/ipranges/googlebot.json'],
                'reverse_dns' => ['googlebot.com', 'google.com', 'googleusercontent.com'],
            ],
            'GoogleOther' => ['reverse_dns' => ['googlebot.com', 'google.com']],
            'Google-InspectionTool' => ['reverse_dns' => ['googlebot.com', 'google.com']],
            'bingbot' => [
                'ip_ranges' => ['https://www.bing.com/toolbox/bingbot.json'],
                'reverse_dns' => ['search.msn.com'],
            ],
            'Applebot' => ['reverse_dns' => ['applebot.apple.com']],
            'YandexBot' => ['reverse_dns' => ['yandex.ru', 'yandex.net', 'yandex.com']],
            'Baiduspider' => ['reverse_dns' => ['baidu.com', 'baidu.jp']],
            'Amazonbot' => ['reverse_dns' => ['crawl.amazonbot.amazon']],
            'GPTBot' => ['ip_ranges' => ['https://openai.com/gptbot.json']],
            'OAI-SearchBot' => ['ip_ranges' => ['https://openai.com/searchbot.json']],
            'ChatGPT-User' => ['ip_ranges' => ['https://openai.com/chatgpt-user.json']],
            'PerplexityBot' => ['ip_ranges' => ['https://www.perplexity.com/perplexitybot.json']],
        ],
    ],

    // Interop contract (ai-guard.verdict/1) — events other code can listen to by class-name
    // string, with no dependency on this package: BotClassified, AgentVerified, and
    // SpoofedBotDetected. Nothing changes when no one listens. See the README.
    'interop' => [
        // false stops the events; the ai_guard.verdict request attribute is set either way
        'enabled' => true,
    ],

    // AI usage preferences — tell crawlers how your content may be used.
    // Both standards are still drafts; they are opt-in and advisory (crawlers may ignore them).
    'ai_preferences' => [
        // IETF AIPREF Content-Usage, e.g. 'train-ai=n' or 'train-ai=n, search=y'.
        // Written to robots.txt by ai-guard:robots-txt, and sent as a response header
        // by the 'ai-guard.preferences' middleware.
        'content_usage' => null,

        // Cloudflare Content Signals, e.g. 'search=yes, ai-input=yes, ai-train=no'.
        // Written to robots.txt by ai-guard:robots-txt.
        'content_signal' => null,
    ],

    // Guarding your own LLM features — used by AiGuard::scanOutput(), AiGuard::withCanary(),
    // and AiGuard::scanToolCall() (MCP tool definitions, arguments, and results)
    'llm_guard' => [
        // Minimum combined score for an output to count as a threat
        'min_score' => 50,

        // Image/link hosts that are never exfiltration (your own CDN, docs site, ...)
        'allowed_domains' => [],

        // Also flag (and redact in the sanitized copy) secrets and PII in model output
        'scan_pii' => true,

        // A system-prompt sentence at least this long, repeated verbatim, counts as a leak
        'min_leak_chars' => 40,

        // Secret used to sign canary tokens (null = your APP_KEY)
        'canary_secret' => null,

        // AiGuard::redact() — mask personal data and secrets before text reaches a provider
        'redaction' => [
            // Pattern types to mask (null = every response-scanning pattern except internal IPs)
            'types' => null,

            // Types restore() puts back into the model's reply; secrets stay masked
            'restore' => ['email', 'phone'],
        ],

        // AiGuard::spotlight() — mark untrusted content so the model treats it as data
        'spotlight' => [
            // delimit | datamark | base64
            'mode' => 'datamark',

            // The character datamark mode puts in place of every space
            'marker' => "\u{02C6}",
        ],

        // Usage budgets for LLM routes ('ai-guard.llm' middleware, AiGuard::checkBudget()).
        // Budgets are quotas: they are enforced in every mode, including log_only.
        'budgets' => [
            'enabled' => true,

            // Token estimate before the call (actual usage is recorded afterwards when available)
            'chars_per_token' => 4,

            // CJK, Kana, and Hangul cost about one token per character, not four
            'chars_per_token_cjk' => 1,

            // Largest single input accepted, in estimated tokens (null = no cap)
            'max_input_tokens' => 8000,

            // Limits per tier; name a tier in the middleware: 'ai-guard.llm:premium'.
            // Any limit set to null is not enforced.
            'tiers' => [
                'default' => [
                    'requests_per_minute' => 30,
                    'tokens_per_minute' => 40000,
                    'tokens_per_day' => 1000000,
                    'cost_per_day' => 5.00,
                ],
            ],

            // Stop every LLM call for the rest of the day once total spend reaches this (USD)
            'global_cost_per_day' => null,

            // USD per 1M tokens, by model name; 'default' covers unlisted models
            'prices' => [
                'default' => ['input' => 3.00, 'output' => 15.00],
            ],

            // user (falls back to IP when nobody is signed in) | ip
            'key_by' => 'user',
        ],

        // Harm-category moderation of input ('ai-guard.llm') and output (scanOutput())
        'moderation' => [
            'enabled' => false,

            // openai (free moderation endpoint) | ollama (Llama Guard) | custom
            'driver' => 'openai',

            // Only these categories count (empty = any flagged category)
            'block_categories' => [],

            // If the provider is unreachable: false = let the text through, true = treat as flagged
            'fail_closed' => false,

            // Score given to a verdict the provider flagged, whatever its category scores say.
            // At or above confidence_threshold, so 'block' mode blocks it.
            'flagged_confidence' => 80,

            'drivers' => [
                'openai' => [
                    'api_key' => env('AI_GUARD_OPENAI_KEY'),
                    'model' => 'omni-moderation-latest',
                    'url' => 'https://api.openai.com/v1/moderations',
                    'timeout' => 3,
                ],
                // ollama pull llama-guard3:1b
                'ollama' => [
                    'url' => 'http://localhost:11434/api/chat',
                    'model' => 'llama-guard3:1b',
                    'timeout' => 5,
                ],
                // Your endpoint receives {"input": "..."} and returns {"flagged": bool, "categories": [...]}
                'custom' => [
                    'url' => env('AI_GUARD_MODERATION_URL'),
                    'api_key' => env('AI_GUARD_MODERATION_KEY'),
                    'flagged_field' => 'flagged',
                    'categories_field' => 'categories',
                    'timeout' => 3,
                ],
            ],
        ],

        // Topic policy for assistants ('ai-guard.llm', AiGuard::checkTopic())
        'topics' => [
            'enabled' => false,

            // Topics the assistant must not discuss: a keyword list, or ['keywords' => [...], 'patterns' => ['regex']]
            // Example: 'medical_advice' => ['diagnose', 'dosage', 'prescription']
            'denied' => [],

            // If set, input must match one of these topics (same format) — otherwise it is off-topic
            'allowed' => [],

            // Inputs shorter than this are never called off-topic ("hi", "thanks")
            'min_chars' => 20,

            // null = keywords only | ollama = also ask a local model to classify the topic
            'classifier' => null,
            'ollama' => [
                'url' => 'http://localhost:11434/api/generate',
                'model' => 'llama3.2:3b',
                'timeout' => 5,
            ],
        ],

        // Multi-turn escalation ('ai-guard.llm', AiGuard::observeConversation()). The conversation
        // is identified by the X-Conversation-Id header, a conversation_id input, or the session.
        'conversations' => [
            'enabled' => true,

            // Share of the previous risk carried into the next message
            'decay' => 0.6,

            // Accumulated risk that flags the conversation
            'threshold' => 120,

            // ...or this many suspicious messages (each scoring at least elevated_score)
            'elevated_messages' => 3,
            'elevated_score' => 40,

            // Conversations idle longer than this start over
            'window_minutes' => 60,
        ],

        // Tool-call firewall (AiGuard::authorizeTool(), guarded laravel/ai tools, 'ai-guard.mcp')
        'tools' => [
            'enabled' => true,

            // Tools without a policy: allow | deny (deny = strict allow-list)
            'default' => 'allow',

            // Per-tool policy. Keys: effect (read|write|egress), roles, schema (JSON Schema),
            // requires_approval, untrusted_output, deny. Register 'authorize' callbacks in code
            // with ToolFirewall::define(). Example:
            // 'send_email' => ['effect' => 'egress', 'roles' => ['support'], 'requires_approval' => true],
            'policies' => [],

            // Hosts an egress tool may send to (URLs and email addresses in its arguments); [] = any
            'egress_domains' => [],

            // Once untrusted content is in the conversation, tools with these effects...
            'restricted_when_tainted' => ['write', 'egress'],

            // ...need approval (approve) or are refused (block)
            'tainted_action' => 'approve',

            // Treat every tool result as untrusted, not only tools marked untrusted_output
            'taint_all_tool_results' => false,

            // Scan tool results for injection, and wrap untrusted results in spotlight delimiters
            'scan_results' => true,
            'spotlight_results' => true,

            // Most tool calls allowed in one conversation (null = unlimited)
            'max_calls' => 25,

            // Lifetime of a signed approval token, in seconds
            'approval_ttl' => 600,
        ],

        // MCP servers this app connects to (AiGuard::guardMcpTools())
        'mcp' => [
            // Server URLs, hosts, or prefixes ending in *; [] = any server
            'allowed_servers' => [],

            // Pin each tool definition and catch changes after approval (needs the ai_guard_mcp_pins table)
            'pinning' => true,

            // Approve every tool the first time a server is seen
            'trust_on_first_use' => true,

            // A tool whose definition changed or is new: block (drop it until approved) | log
            'on_change' => 'block',

            // Scan tool names, descriptions, and schemas for tool poisoning
            'scan_definitions' => true,
        ],

        // laravel/ai agents: add the GuardPrompt middleware to an agent, and wrap its tools with
        // AiGuard::guardTools() — see the README section "laravel/ai agents"
        'agents' => [
            // Budget tier for agent prompts
            'tier' => 'default',

            // Mask personal data and secrets before the prompt reaches the provider; restore them in the reply
            'redact' => false,

            // Scan replies for exfiltration, leaks of the agent's instructions, and secrets
            'scan_output' => true,
        ],

        // AiGuard::safeHtml() and @aiSafe — show model output as safe HTML
        'rendering' => [
            // Convert Markdown (uses league/commonmark, which ships with laravel/framework)
            'markdown' => true,

            // Raw HTML written by the model: escape (shown as text) | strip | allow (still sanitized)
            'html_input' => 'escape',

            // Images: allowed_domains (your host + llm_guard.allowed_domains) | all | none.
            // A remote image is the classic exfiltration channel: its URL can carry chat data.
            'images' => 'allowed_domains',

            // Links: all | allowed_domains (others become text followed by the URL) | none
            'links' => 'all',
            'link_rel' => 'nofollow noopener noreferrer',
            'link_target' => null,
        ],

        // 'ai-guard.csp' middleware for pages that show model output. {nonce} is AiGuard::cspNonce()
        // (@aiNonce in Blade); {allowed_domains} expands to the llm_guard.allowed_domains hosts.
        'csp' => [
            'report_only' => false,
            'report_uri' => null,

            // Merged onto the package defaults; set a directive to null to leave it out
            'directives' => [
                'default-src' => ["'self'"],
                'script-src' => ["'self'", "'nonce-{nonce}'"],
                'style-src' => ["'self'", "'unsafe-inline'"],
                'img-src' => ["'self'", 'data:', '{allowed_domains}'],
                'connect-src' => ["'self'"],
                'object-src' => ["'none'"],
                'base-uri' => ["'none'"],
                'form-action' => ["'self'"],
                'frame-ancestors' => ["'self'"],
            ],
        ],

        // AiGuard::checkSql() / runReadOnlySql() — SQL written by a model
        'sql' => [
            // Tables the model may query ([] = any table except system catalogs)
            'allowed_tables' => [],

            // Row cap added around every query by runReadOnlySql() (null = none; uses LIMIT)
            'max_rows' => 1000,

            // Functions to refuse on top of the built-in list (sleep, load_file, pg_read_file, ...)
            'deny_functions' => [],

            'allow_system_tables' => false,

            // Connection for runReadOnlySql() (null = default). Give it a SELECT-only database user.
            'connection' => null,
        ],
    ],

    // ML-based detection — optional, zero dependencies, one Http::post() call
    // Enhances regex detection with ML for borderline cases
    'ml_detection' => [
        // Enable ML detection (off by default — package stays lightweight)
        'enabled' => false,

        // ML provider: 'lakera', 'huggingface', 'pangea', 'ollama', 'custom'
        // ('llm_guard' still works but is deprecated: the LLM Guard project was archived)
        'driver' => 'lakera',

        // Only call ML when regex confidence is within this range
        // Below min = too low to bother, above max = regex is confident enough.
        // v3 scores are weighted (85-95 for a strong signal, up to 100 stacked), so a strong
        // regex detection sits above this range and is never sent to a provider.
        'trigger_range' => [40, 90],

        // Score weighting: regex_weight + ml_weight = 1.0
        'regex_weight' => 0.4,

        // Classifier-first paths: every input on these paths goes to ML, not only
        // regex-flagged ones (catches paraphrased attacks). Uses $request->is() patterns.
        // Example: ['api/chat*', 'assistant/*']
        'always_run_on' => [],

        // Cap on the text sent to the provider
        'max_input_chars' => 4000,

        // Replace emails, card numbers, keys, etc. with [REDACTED:type] before sending
        'redact_pii' => true,

        'drivers' => [
            // Lakera Guard — fastest (50-150ms), best accuracy, 10K free/month
            // Sign up: https://platform.lakera.ai/
            'lakera' => [
                'api_key' => env('AI_GUARD_LAKERA_KEY'),
                'url' => 'https://api.lakera.ai/v2/guard',
                'timeout' => 3,
            ],

            // HuggingFace — Meta Llama Prompt Guard 2 (multilingual, benign/malicious)
            // Sign up: https://huggingface.co/ (free account + API token; accept the model licence)
            // Alternative: 'protectai/deberta-v3-base-prompt-injection-v2'
            'huggingface' => [
                'api_key' => env('AI_GUARD_HF_KEY'),
                'model' => 'meta-llama/Llama-Prompt-Guard-2-86M',
                // null = https://router.huggingface.co/hf-inference/models/{model}
                'url' => null,
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

            // LLM Guard — DEPRECATED: the project was archived in July 2026 and this driver
            // will be removed in v4. Self-hosted alternatives: 'huggingface' or 'ollama'.
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
