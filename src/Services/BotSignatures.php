<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Support\Facades\Log;
use JayAnta\AiGuard\Support\SignatureFeed;

class BotSignatures
{
    /**
     * robots.txt-only tokens: they control how a vendor may *use* content
     * (e.g. training) but never appear in a User-Agent header, so they are
     * written to robots.txt and never matched against traffic.
     */
    public const CONTROL_TOKENS = [
        'Google-Extended',     // Gemini / Vertex AI training
        'Applebot-Extended',   // Apple Intelligence training
        'Webzio-Extended',     // Webz.io AI data licensing
        'YandexAdditional',    // YandexGPT
    ];

    /**
     * Tokens the vendor has retired. Still matched (old clients linger) and
     * still written to robots.txt, but flagged as legacy.
     */
    public const LEGACY_TOKENS = [
        'Claude-Web',
        'anthropic-ai',
        'Neeva',
        'NeevaBot',
    ];

    /**
     * v2's single AI assistant category is now split by purpose.
     */
    public const CATEGORY_ALIASES = [
        'ai_assistants' => ['ai_search', 'ai_agents'],
    ];

    public const AI_CATEGORIES = ['ai_training', 'ai_search', 'ai_agents'];

    private static ?array $categories = null;

    /**
     * @var array<string, array{regex: string, map: array<string, string>}>
     */
    private static array $compiled = [];

    public static function getCategories(): array
    {
        return self::$categories ??= self::definitions();
    }

    public static function getTotalCount(): int
    {
        $total = 0;
        foreach (self::getCategories() as $category) {
            $total += count($category['bots']);
        }

        return $total;
    }

    public static function getCategoryCount(): int
    {
        return count(self::getCategories());
    }

    /**
     * Expand legacy category names ("ai_assistants") to their v3 equivalents.
     *
     * @param  array<int, string>  $categories
     * @return array<int, string>
     */
    public static function expandCategories(array $categories): array
    {
        $expanded = [];

        foreach ($categories as $category) {
            array_push($expanded, ...(self::CATEGORY_ALIASES[$category] ?? [$category]));
        }

        return array_values(array_unique($expanded));
    }

    /**
     * bot_signatures.confidence overrides from config, with v2 aliases expanded and scores clamped.
     *
     * @return array<string, int>
     */
    public static function confidenceOverrides(array $config): array
    {
        $overrides = [];

        foreach ($config['bot_signatures']['confidence'] ?? [] as $category => $score) {
            foreach (self::expandCategories([(string) $category]) as $expanded) {
                $overrides[$expanded] = max(0, min(100, (int) $score));
            }
        }

        return $overrides;
    }

    public static function isLegacyToken(string $token): bool
    {
        return in_array(strtolower($token), array_map('strtolower', self::LEGACY_TOKENS), true);
    }

    /**
     * Whether the token is already covered by the signature database (or is a control token).
     */
    public static function isKnownToken(string $token): bool
    {
        $needle = strtolower(trim($token));

        foreach (self::getCategories() as $category) {
            foreach ($category['bots'] as $bot) {
                if (strtolower($bot) === $needle) {
                    return true;
                }
            }
        }

        return in_array($needle, array_map('strtolower', self::CONTROL_TOKENS), true);
    }

    /**
     * Whether the token is in the database that ships with the package (feed tokens excluded).
     */
    public static function isBuiltInToken(string $token): bool
    {
        $needle = strtolower(trim($token));

        foreach (self::definitions() as $category) {
            foreach ($category['bots'] as $bot) {
                if (strtolower($bot) === $needle) {
                    return true;
                }
            }
        }

        return in_array($needle, array_map('strtolower', self::CONTROL_TOKENS), true);
    }

    /**
     * Add tokens (e.g. from the ai.robots.txt feed) to their categories. Tokens the
     * database already has are skipped. Returns how many were added.
     *
     * @param  array<string, array<int, string>>  $tokensByCategory
     */
    public static function extend(array $tokensByCategory): int
    {
        $categories = self::getCategories();
        $known = array_fill_keys(array_map('strtolower', self::CONTROL_TOKENS), true);
        foreach ($categories as $category) {
            foreach ($category['bots'] as $bot) {
                $known[strtolower($bot)] = true;
            }
        }

        $added = 0;
        foreach ($tokensByCategory as $key => $tokens) {
            if (! isset($categories[$key])) {
                continue;
            }

            $before = $added;
            foreach ((array) $tokens as $token) {
                $token = trim((string) $token);
                if ($token === '' || isset($known[strtolower($token)])) {
                    continue;
                }

                $categories[$key]['bots'][] = $token;
                $known[strtolower($token)] = true;
                $added++;
            }

            if ($added > $before) {
                unset(self::$compiled[$key]);
            }
        }

        self::$categories = $categories;

        return $added;
    }

    /**
     * Load the tokens saved by ai-guard:update-signatures.
     */
    public static function loadFeed(string $path): int
    {
        return is_file($path) ? self::extend(SignatureFeed::load($path)) : 0;
    }

    /**
     * Back to the built-in database (drops tokens added with extend()).
     */
    public static function reset(): void
    {
        self::$categories = null;
        self::$compiled = [];
    }

    /**
     * Every category that matches the user-agent (the most specific token per category).
     *
     * Tokens match on word boundaries — "Vega" no longer matches "Vegas", and
     * "curl" no longer matches inside "libcurl" (which has its own entry).
     *
     * @return array<int, array{category: string, label: string, confidence: int, matched_bot: string}>
     */
    public static function findAllBots(string $userAgent): array
    {
        if ($userAgent === '') {
            return [];
        }

        $matches = [];

        foreach (self::getCategories() as $categoryKey => $category) {
            $compiled = self::compiled($categoryKey, $category['bots']);

            foreach ($compiled['regexes'] as $regex) {
                if (preg_match($regex, $userAgent, $match) === 1) {
                    $matches[] = [
                        'category' => $categoryKey,
                        'label' => $category['label'],
                        'confidence' => $category['confidence'],
                        'matched_bot' => $compiled['map'][strtolower($match[0])] ?? $match[0],
                    ];

                    break;
                }
            }
        }

        return $matches;
    }

    /**
     * The highest-confidence match outside the excluded categories. Taking the
     * first match instead would let "sqlmap … Googlebot" hide behind the
     * (disabled-by-default) search engine category.
     *
     * @param  array<int, string>  $excludeCategories
     * @param  array<string, int>  $confidenceOverrides  category => confidence
     * @return array{category: string, label: string, confidence: int, matched_bot: string}|null
     */
    public static function findBot(string $userAgent, array $excludeCategories = [], array $confidenceOverrides = []): ?array
    {
        $excludeCategories = self::expandCategories($excludeCategories);
        $best = null;

        foreach (self::findAllBots($userAgent) as $match) {
            if (in_array($match['category'], $excludeCategories, true)) {
                continue;
            }

            if (isset($confidenceOverrides[$match['category']])) {
                $match['confidence'] = $confidenceOverrides[$match['category']];
            }

            if ($best === null || $match['confidence'] > $best['confidence']) {
                $best = $match;
            }
        }

        return $best;
    }

    // Alternatives per compiled pattern: PCRE has limits on pattern size, and a pattern that
    // fails to compile makes preg_match() return false — a category that silently never matches
    private const TOKENS_PER_PATTERN = 400;

    /**
     * @param  array<int, string>  $bots
     * @return array{regexes: array<int, string>, map: array<string, string>}
     */
    private static function compiled(string $category, array $bots): array
    {
        if (! isset(self::$compiled[$category])) {
            // Longest first, so "SemrushBot-BA" wins over "SemrushBot" at the same offset
            $tokens = $bots;
            usort($tokens, fn (string $a, string $b) => strlen($b) <=> strlen($a));

            $map = [];
            foreach ($bots as $bot) {
                $map[strtolower($bot)] = $bot;
            }

            $regexes = [];
            foreach (array_chunk($tokens, self::TOKENS_PER_PATTERN) as $chunk) {
                $regex = '/(?<![a-z0-9])(?:'.implode('|', array_map(fn (string $t) => preg_quote($t, '/'), $chunk)).')(?![a-z])/i';

                if (@preg_match($regex, '') === false) {
                    Log::warning('AI Guard: a bot signature pattern did not compile and was skipped.', ['category' => $category]);

                    continue;
                }

                $regexes[] = $regex;
            }

            self::$compiled[$category] = ['regexes' => $regexes, 'map' => $map];
        }

        return self::$compiled[$category];
    }

    private static function definitions(): array
    {
        return [
            // Crawlers that collect content to train models
            'ai_training' => [
                'label' => 'AI Training Crawler',
                'confidence' => 95,
                'bots' => [
                    'GPTBot', 'ClaudeBot', 'Claude-Web', 'anthropic-ai',
                    'CCBot', 'Bytespider', 'Diffbot', 'FacebookBot',
                    'cohere-ai', 'cohere-training-data-crawler',
                    'AI2Bot', 'Ai2Bot-Dolma', 'ImagesiftBot', 'Omgilibot',
                    'Timpibot', 'Kangaroo Bot', 'meta-externalagent',
                    'webz.io', 'Amazonbot', 'ISSCyberRiskCrawler',
                    'FriendlyCrawler', 'Nicecrawler', 'Sidetrade indexer',
                    'Velenpublicwebcrawler', 'img2dataset', 'ICC-Crawler',
                    'GoogleOther',                 // Google generic R&D crawling (feeds Gemini)
                    'DeepSeekBot',                 // DeepSeek LLM training
                    'TikTokSpider',                // ByteDance
                    'ToutiaoSpider',               // ByteDance news spider
                    'PanguBot',                    // Huawei multimodal LLM
                    'Spawning-AI',                 // Spawning AI data provenance
                    'LAIONDownloader',             // LAION datasets
                    'MaCoCu',                      // EU multilingual corpus
                    'Cotoyogi',                    // ROIS Japanese LLM
                    'TerraCotta',                  // Ceramic AI
                    'Brightbot',                   // Bright Data LLM training
                    'Crawl4AI',                    // Open-source AI scraping framework
                    'FirecrawlAgent',              // Firecrawl LLM data prep
                    'Factset_spyderbot',           // FactSet AI
                    'SBIntuitionsBot',             // SB Intuitions
                    'imageSpider',                 // AI image datasets
                    'WARDBot',                     // WEBSPARK AI data
                    'KunatoCrawler',               // Kunato AI data
                    'MyCentralAIScraperBot',       // AI data scraper
                    'Poseidon Research Crawler',   // AI research crawler
                    'ChatGLM-Spider',              // ChatGLM training
                    'Datenbank Crawler',           // AI data scraper
                    'ApifyWebsiteContentCrawler',  // Apify AI scraping
                    'Crawlspace',                  // Crawlspace scraping service
                    'WRTNBot',                     // WRTN AI
                ],
            ],

            // Crawlers that build retrieval indexes for AI answers (not training)
            'ai_search' => [
                'label' => 'AI Search Crawler',
                'confidence' => 65,
                'bots' => [
                    'OAI-SearchBot',               // ChatGPT search index
                    'Claude-SearchBot',            // Claude search index
                    'PerplexityBot',               // Perplexity index
                    'YouBot', 'PhindBot', 'KagiBot', 'BraveSearch',
                    'Neeva', 'NeevaBot',           // legacy — Neeva shut down
                    'DuckAssistBot',               // DuckDuckGo AI answers
                    'AzureAI-SearchBot',           // Azure AI Search
                    'Amzn-SearchBot',              // Amazon AI search
                    'meta-webindexer',             // Meta AI search index
                    'Google-CloudVertexBot',       // Vertex AI Agent Builder (owner-requested crawl)
                    'iaskspider',                  // iAsk AI search
                    'TavilyBot',                   // Tavily search API
                    'LinerBot',                    // Liner research assistant
                    'Andibot',                     // Andi AI search
                    'Poggio-Citations',            // AI citation fetcher
                    'bigsur.ai',                   // Big Sur AI
                    'Cloudflare-AutoRAG',          // Cloudflare RAG indexing
                ],
            ],

            // Fetches made live on behalf of a user (chat browsing, agents, previews)
            'ai_agents' => [
                'label' => 'AI Agent (user-triggered)',
                'confidence' => 60,
                'bots' => [
                    'ChatGPT-User',                // ChatGPT live fetch
                    'ChatGPT Agent',               // ChatGPT agentic browsing
                    'ChatGPT-Browser',             // ChatGPT browsing mode
                    'Operator',                    // OpenAI Operator
                    'Claude-User',                 // Claude live fetch
                    'Perplexity-User',             // Perplexity live fetch
                    'MistralAI-User',              // Le Chat live fetch
                    'Gemini-Deep-Research',        // Gemini Deep Research
                    'Google-NotebookLM', 'NotebookLM',
                    'Google-Agent',                // Google agents browsing for a user
                    'GoogleAgent-Mariner',         // Google browser agent
                    'GoogleAgent-Search',          // Google search agent
                    'Bard-AI', 'Gemini-AI', 'MetaAI',
                    'meta-externalfetcher',        // Meta AI user-initiated fetch
                    'facebookexternalhit',         // Link previews when a user shares a URL
                    'kagi-fetcher',                // Kagi query resolver
                    'Amzn-User',                   // Amazon AI user fetch
                    'NovaAct',                     // Amazon web automation agent
                    'AmazonBuyForMe',              // Amazon shopping agent
                    'Manus-User',                  // Manus browser agent
                    'TwinAgent', 'Devin', 'Siri', 'Copilot', 'Thinkbot',
                    'bedrockbot',                  // Amazon Bedrock apps
                    'QualifiedBot', 'KlaviyoAIBot',
                ],
            ],

            'search_engines' => [
                'label' => 'Search Engine',
                'confidence' => 30,
                'bots' => [
                    'Googlebot', 'bingbot', 'YandexBot', 'Baiduspider',
                    'DuckDuckBot', 'Sogou', 'Exabot', 'facebot',
                    'ia_archiver', 'Slurp', 'Applebot', 'Qwantify',
                    'Seznam', 'Naver',
                    'Storebot-Google', 'Google-InspectionTool', 'AdsBot-Google',
                    'Mediapartners-Google', 'Feedfetcher-Google', 'BingPreview',
                    'MojeekBot', 'Qwantbot', 'SeznamBot', 'Yeti', 'coccoc',
                    '360Spider', 'mail.ru', 'YisouSpider', 'Daum', 'ZumBot',
                    'Bravebot', 'IbouBot', 'ZanistaBot', 'LinkupBot', 'Anomura',
                    'archive.org_bot',
                ],
            ],

            'seo_tools' => [
                'label' => 'SEO Tool',
                'confidence' => 60,
                'bots' => [
                    'AhrefsBot', 'SemrushBot', 'MJ12bot', 'DotBot', 'BLEXBot',
                    'DataForSeoBot', 'serpstatbot', 'Screaming Frog SEO',
                    'MozBot', 'Moz/', 'rogerbot', 'LinkpadBot', 'MegaIndex',
                    'BacklinkCrawler', 'SEOkicks', 'Sistrix', 'ContentKingApp',
                    'DeepCrawl/', 'OnCrawl', 'Cognitiveseo', 'Xenu Link',
                    'MajesticSEO', 'spbot/', 'BomboraBot', 'PetalBot',
                    'AhrefsSiteAudit', 'SemrushBot-BA', 'SemrushBot-SI',
                    'SemrushBot-SWA', 'SemrushBot-OCOB', 'SplitSignalBot',
                    'SiteAuditBot', 'SerpReputationManagementAgent',
                    'BacklinksExtendedBot', 'Seobility', 'XoviBot', 'SeolytBot',
                    'Seekport', 'keys-so-bot', 'Morningscore', 'BrightEdge Crawler',
                    'RankActive', 'RankActiveLinkBot', 'HEADMasterSEO', 'SEOENGBot',
                    'Cocolyzebot', 'woorankreview', 'woobot', 'LetsearchBot',
                    'Siteimprove', 'Sitebulb/', 'botify', 'SEOlyticsCrawler',
                    'Konturbot', 'SenutoBot', 'URLinspectorBot',
                ],
            ],

            'scrapers' => [
                'label' => 'Web Scraper',
                'confidence' => 85,
                'bots' => [
                    'Scrapy/', 'colly -', 'Colly/', 'HeadlessChrome', 'PhantomJS',
                    'Puppeteer', 'Playwright/', 'Selenium/', 'WebDriver',
                    'CasperJS', 'Splash/', 'Mechanize/', 'Nightmare/',
                    'SimplePie/', 'Guzzle/', 'CrawlerBot', 'SpiderBot',
                    'htmlparser/', 'WebHarvest', 'WebExtract', 'WebGrab',
                    'HTTrack', 'SiteSucker', 'WebCopier', 'WebReaper', 'WebZIP',
                    'WebStripper', 'WebLeacher', 'Offline Explorer', 'PageGrabber',
                    'SiteSnagger', 'TeleportPro', 'FlashGet', 'GetRight',
                    'GrabNet', 'NetZIP', 'WWW-Mechanize', 'LWP::Simple',
                    'crawler4j', 'Nutch', 'heritrix', 'newspaper/', 'Embedly',
                    'CherryPicker', 'EmailWolf', 'ExtractorPro', 'Xaldon WebSpider',
                    // Scraping-as-a-Service platforms
                    'ZenRows', 'ScrapingBee', 'ScraperAPI', 'Oxylabs', 'Crawlbase',
                    'WebScrapingAPI', 'ProxyCrawl', 'ScrapFly', 'ScrapeOps', 'Zyte',
                    'AutoScraper',
                ],
            ],

            'bad_bots' => [
                'label' => 'Malicious Bot',
                'confidence' => 95,
                'bots' => [
                    'Nikto', 'sqlmap', 'Nessus', 'Nmap', 'Masscan', 'ZmEu',
                    'w3af', 'Havij', 'Acunetix', 'OpenVAS', 'Burp', 'dirbuster',
                    'gobuster', 'wpscan', 'Jorgee', 'Morfeus', 'Zgrab',
                    // 'httpx' deliberately not listed here: it would also match the
                    // legitimate python-httpx client library (data_harvesters, 80)
                    'nuclei', 'subfinder', 'jaeles', 'OWASP', 'Arachni',
                    'Skipfish', 'Wapiti', 'Vega', 'AppScan', 'NetSparker',
                    'Shodan', 'CensysInspect', 'masscan-ng', 'Fuzz Faster U Fool',
                    'Wfuzz', 'FHscan', 'Jbrofuzz', 'l9scan', 'l9explore',
                    'l9tcpid', 'leakix', 'Webshag', 'Nimbostratus', 'muhstik-scan',
                    'T0PHackTeam', 'scan.lol', 'probely.com', 'cyberscan.io',
                    'Hardenize', 'NetSystemsResearch', 'InternetMeasurement',
                    'DomainCrawler', 'DomainStatsBot', 'BackDoorBot', 'Black Hole',
                    'Zeus', 'Siphon', 'Vacuum',
                ],
            ],

            'data_harvesters' => [
                'label' => 'Data Harvester',
                'confidence' => 80,
                'bots' => [
                    'curl', 'python-requests', 'Go-http-client', 'Java/',
                    'libwww-perl', 'Wget', 'HTTPie', 'axios', 'node-fetch',
                    'http_request2', 'pycurl', 'aiohttp', 'httpx', 'urllib',
                    'requests/', 'python-httpx', 'Python-httplib2', 'okhttp',
                    'Apache-HttpClient', 'Apache-HttpAsyncClient', 'RestSharp',
                    'Typhoeus', 'Faraday', 'hackney', 'reqwest', 'fasthttp',
                    'lua-resty-http', 'Zend_Http_Client', 'GuzzleHttp',
                    'PostmanRuntime', 'insomnia/', 'http.rb', 'libcurl',
                    'node-superagent', 'node-urllib', 'php-requests', 'http-kit',
                    'Mojolicious', 'lwp-request', 'Dispatch/', 'unirest-java',
                    'UniversalFeedParser', 'phpcrawl', 'Symfony BrowserKit',
                    'colly',
                ],
            ],
        ];
    }
}
