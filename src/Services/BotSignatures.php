<?php

namespace JayAnta\AiGuard\Services;

class BotSignatures
{
    public static function getCategories(): array
    {
        return [
            'ai_training' => [
                'label' => 'AI Training Bot',
                'confidence' => 95,
                'bots' => [
                    // --- Original ---
                    'GPTBot', 'ChatGPT-User', 'OAI-SearchBot',
                    'Claude-Web', 'ClaudeBot', 'anthropic-ai',
                    'CCBot', 'Google-Extended', 'Googlebot-Extended',
                    'Bytespider', 'Diffbot', 'FacebookBot',
                    'cohere-ai', 'AI2Bot', 'Applebot-Extended',
                    'ImagesiftBot', 'Omgilibot', 'Timpibot',
                    'Kangaroo Bot', 'meta-externalagent',
                    'webz.io', 'iaskspider', 'Amazonbot',
                    'ISSCyberRiskCrawler', 'FriendlyCrawler',
                    'Nicecrawler', 'Sidetrade indexer',
                    'Velenpublicwebcrawler', 'Webzio-Extended',
                    'img2dataset', 'ICC-Crawler',
                    'facebookexternalhit',
                    // --- Added: AI training/data scrapers seen 2024-2025 ---
                    'Google-CloudVertexBot',       // Google Vertex AI model training
                    'GoogleOther',                 // Google generic scraping (feeds Gemini)
                    'DeepSeekBot',                 // DeepSeek LLM training crawler
                    'TikTokSpider',                // ByteDance (same org as Bytespider)
                    'ToutiaoSpider',               // ByteDance news spider
                    'PanguBot',                    // Huawei multimodal LLM training
                    'cohere-training-data-crawler', // Cohere explicit training crawler
                    'Ai2Bot-Dolma',                // AI2 Dolma dataset builder
                    'Spawning-AI',                 // Spawning AI data provenance
                    'LAIONDownloader',             // LAION ML research datasets
                    'MaCoCu',                      // EU multilingual corpus crawler
                    'Cotoyogi',                    // ROIS Japanese language LLM
                    'TerraCotta',                  // Ceramic AI LLM training
                    'Brightbot',                   // Bright Data LLM training
                    'Crawl4AI',                    // Open-source AI scraping framework
                    'FirecrawlAgent',              // Firecrawl AI scraping/LLM prep
                    'Factset_spyderbot',           // FactSet AI model training
                    'SBIntuitionsBot',             // SB Intuitions AI development
                    'imageSpider',                 // AI image dataset collection
                    'WARDBot',                     // WEBSPARK AI data scraper
                    'KunatoCrawler',               // Kunato AI data collection
                    'MyCentralAIScraperBot',       // AI data scraper
                    'Poseidon Research Crawler',   // AI research crawler
                    'meta-externalfetcher',        // Meta AI content fetcher
                    'meta-webindexer',             // Meta AI search indexer
                    'ChatGLM-Spider',              // ChatGLM Chinese LLM training
                    'YandexAdditional',            // YandexGPT LLM training
                    'Datenbank Crawler',           // Datenbank AI data scraper
                    'ApifyWebsiteContentCrawler',  // Apify AI scraping service
                    'Crawlspace',                  // Crawlspace data scraping service
                    'WRTNBot',                     // WRTN AI bot
                ],
            ],

            'ai_assistants' => [
                'label' => 'AI Assistant',
                'confidence' => 90,
                'bots' => [
                    // --- Original ---
                    'PerplexityBot', 'YouBot', 'PhindBot',
                    'KagiBot', 'BraveSearch', 'Neeva',
                    'MetaAI', 'Siri', 'Copilot',
                    'NeevaBot',
                    // --- Added: AI assistants and agent bots seen 2024-2025 ---
                    'Claude-SearchBot',            // Anthropic search quality bot
                    'Claude-User',                 // Anthropic Claude user-initiated fetch
                    'ChatGPT-Browser',             // OpenAI browsing mode
                    'Perplexity-User',             // Perplexity user-initiated fetch
                    'Gemini-Deep-Research',         // Google Gemini deep research
                    'Google-NotebookLM',           // Google NotebookLM assistant
                    'NotebookLM',                  // Google NotebookLM variant
                    'GoogleAgent-Mariner',         // Google browser automation agent
                    'GoogleAgent-Search',          // Google search agent
                    'Bard-AI',                     // Google Bard AI assistant
                    'Gemini-AI',                   // Google Gemini AI assistant
                    'DuckAssistBot',               // DuckDuckGo AI-powered answers
                    'MistralAI-User',              // Mistral AI assistant fetch
                    'Andibot',                     // Andi AI search assistant
                    'kagi-fetcher',                // Kagi AI query resolver
                    'AzureAI-SearchBot',           // Microsoft Azure AI search
                    'Amzn-SearchBot',              // Amazon AI search bot
                    'Amzn-User',                   // Amazon AI user-initiated
                    'ChatGPT Agent',               // OpenAI agentic browsing
                    'NovaAct',                     // Amazon web automation agent
                    'AmazonBuyForMe',              // Amazon AI shopping agent
                    'Manus-User',                  // Butterfly Effect browser agent
                    'Operator',                    // OpenAI Operator agent
                    'TwinAgent',                   // Twin workflow automation agent
                    'Devin',                       // Devin AI coding assistant
                    'TavilyBot',                   // Tavily AI search assistant
                    'LinerBot',                    // Liner AI research assistant
                    'Poggio-Citations',            // AI citation fetcher
                    'bigsur.ai',                   // Big Sur AI assistant
                    'Cloudflare-AutoRAG',          // Cloudflare AI RAG solution
                    'Thinkbot',                    // Thinkbot AI integration
                    'bedrockbot',                  // Amazon Bedrock AI applications
                    'QualifiedBot',                // Qualified AI sales agent
                    'KlaviyoAIBot',                // Klaviyo AI content bot
                ],
            ],

            'search_engines' => [
                'label' => 'Search Engine',
                'confidence' => 30,
                'bots' => [
                    // --- Original ---
                    'Googlebot', 'Bingbot', 'bingbot',
                    'YandexBot', 'Baiduspider', 'DuckDuckBot',
                    'Sogou', 'Exabot', 'facebot',
                    'ia_archiver', 'Slurp', 'Applebot',
                    'Qwantify', 'Seznam', 'Naver',
                    // --- Added: Search engines and their variants seen 2024-2025 ---
                    'Storebot-Google',             // Google store/product search
                    'Google-InspectionTool',       // Google Search Console crawler
                    'AdsBot-Google',               // Google Ads landing page checker
                    'Mediapartners-Google',         // Google AdSense content match
                    'Feedfetcher-Google',           // Google RSS/feed processor
                    'BingPreview',                 // Bing link preview renderer
                    'MojeekBot',                   // Mojeek independent search engine
                    'Qwantbot',                    // Qwant search engine bot
                    'SeznamBot',                   // Czech Seznam search engine
                    'Yeti',                        // Naver search crawler (Korea)
                    'coccoc',                      // Coc Coc Vietnamese search engine
                    '360Spider',                   // 360 Search (China)
                    'mail.ru',                     // Mail.Ru search engine (Russia)
                    'YisouSpider',                 // Yisou Chinese search
                    'Daum',                        // Daum Korean search engine
                    'ZumBot',                      // Zum Korean search engine
                    'Bravebot',                    // Brave Search crawler
                    'IbouBot',                     // Ibou search indexer
                    'ZanistaBot',                  // Zanista AI search
                    'LinkupBot',                   // Linkup enterprise search
                    'Anomura',                     // Direqt AI search crawler
                    'archive.org_bot',             // Internet Archive
                ],
            ],

            'seo_tools' => [
                'label' => 'SEO Tool',
                'confidence' => 60,
                'bots' => [
                    // --- Original ---
                    'AhrefsBot', 'SemrushBot', 'MJ12bot',
                    'DotBot', 'BLEXBot', 'DataForSeoBot',
                    'serpstatbot', 'Screaming Frog SEO',
                    'MozBot', 'Moz/', 'rogerbot',
                    'RogerBot', 'LinkpadBot', 'MegaIndex',
                    'BacklinkCrawler', 'SEOkicks', 'Sistrix',
                    'ContentKingApp', 'DeepCrawl/', 'OnCrawl',
                    'Cognitiveseo', 'Xenu Link', 'MajesticSEO',
                    'spbot/', 'BomboraBot', 'SEMrushBot',
                    'PetalBot',
                    // --- Added: SEO and marketing bots seen 2024-2025 ---
                    'AhrefsSiteAudit',             // Ahrefs site audit crawler
                    'SemrushBot-BA',               // Semrush Backlink Audit
                    'SemrushBot-SI',               // Semrush Site Index
                    'SemrushBot-SWA',              // Semrush SEO Writing Assistant
                    'SemrushBot-OCOB',             // Semrush ContentShake AI
                    'SplitSignalBot',              // Semrush A/B testing
                    'SiteAuditBot',                // Semrush Site Audit
                    'SerpReputationManagementAgent', // Semrush reputation management
                    'BacklinksExtendedBot',         // Semrush backlinks extended
                    'Seobility',                   // Seobility SEO checker
                    'XoviBot',                     // XOVI SEO suite crawler
                    'SeolytBot',                   // Seolyt SEO tool
                    'Seekport',                    // Seekport search/SEO crawler
                    'keys-so-bot',                 // Keys.so SEO analysis
                    'Morningscore',                // Morningscore SEO tool
                    'BrightEdge Crawler',          // BrightEdge SEO platform
                    'RankActive',                  // RankActive SEO tracker
                    'RankActiveLinkBot',           // RankActive link analysis
                    'HEADMasterSEO',               // HEAD Master SEO tool
                    'SEOENGBot',                   // SEOENG SEO tool
                    'Cocolyzebot',                 // Cocolyze SEO analyzer
                    'woorankreview',               // WooRank SEO review
                    'woobot',                      // WooRank bot variant
                    'LetsearchBot',                // Letsearch SEO bot
                    'Siteimprove',                 // Siteimprove accessibility/SEO
                    'Sitebulb/',                   // Sitebulb SEO audit tool
                    'botify',                      // Botify SEO crawler
                    'SEOlyticsCrawler',            // SEOlytics SEO tool
                    'Konturbot',                   // Kontur SEO bot
                    'SenutoBot',                   // Senuto SEO platform
                    'URLinspectorBot',             // URLinspector SEO bot
                ],
            ],

            'scrapers' => [
                'label' => 'Web Scraper',
                'confidence' => 85,
                'bots' => [
                    // --- Original ---
                    'Scrapy/', 'colly -', 'Colly/',
                    'HeadlessChrome', 'PhantomJS', 'Puppeteer',
                    'Playwright/', 'Selenium/', 'WebDriver',
                    'CasperJS', 'Splash/', 'Mechanize/',
                    'Nightmare/', 'SimplePie/', 'Guzzle/',
                    'CrawlerBot', 'SpiderBot', 'htmlparser/',
                    'WebHarvest', 'WebExtract', 'WebGrab',
                    // --- Added: Scrapers, headless tools, content extractors 2024-2025 ---
                    'HTTrack',                     // Website copier/mirror tool
                    'SiteSucker',                  // macOS website downloader
                    'WebCopier',                   // Web page copier
                    'WebReaper',                   // Web scraping tool
                    'WebZIP',                      // Offline browser/scraper
                    'WebStripper',                 // Web content stripper
                    'WebLeacher',                  // Content leeching tool
                    'Offline Explorer',            // Offline browsing tool
                    'PageGrabber',                 // Page content grabber
                    'SiteSnagger',                 // Website snagger
                    'TeleportPro',                 // Website copy tool
                    'FlashGet',                    // Download manager/scraper
                    'GetRight',                    // Download manager
                    'GrabNet',                     // Web scraping tool
                    'NetZIP',                      // Content downloader
                    'WWW-Mechanize',               // Perl web scraping library
                    'LWP::Simple',                 // Perl web client
                    'crawler4j',                   // Java crawling framework
                    'Nutch',                       // Apache Nutch crawler framework
                    'heritrix',                    // Internet Archive crawler engine
                    'newspaper/',                  // Python news scraping library
                    'Embedly',                     // Content embedding/extraction
                    'CherryPicker',                // Selective content scraper
                    'EmailWolf',                   // Email harvesting scraper
                    'ExtractorPro',                // Web data extraction tool
                    'Xaldon WebSpider',            // Web spider tool
                ],
            ],

            'bad_bots' => [
                'label' => 'Malicious Bot',
                'confidence' => 95,
                'bots' => [
                    // --- Original ---
                    'Nikto', 'sqlmap', 'Nessus',
                    'Nmap', 'Masscan', 'ZmEu',
                    'w3af', 'Havij', 'Acunetix',
                    'OpenVAS', 'Burp', 'dirbuster',
                    'gobuster', 'wpscan', 'Jorgee',
                    'Morfeus', 'Zgrab', 'masscan',
                    'nuclei', 'httpx', 'subfinder',
                    'jaeles', 'OWASP', 'Arachni',
                    'Skipfish', 'Wapiti', 'Vega',
                    'AppScan', 'NetSparker',
                    // --- Added: Vuln scanners, attack tools, bad bots 2024-2025 ---
                    'Shodan',                      // Shodan internet scanner
                    'CensysInspect',               // Censys attack surface scanner
                    'masscan-ng',                  // Next-gen masscan fork
                    'Fuzz Faster U Fool',          // ffuf fuzzing tool
                    'Wfuzz',                       // Web fuzzer
                    'FHscan',                      // Fast HTTP scanner
                    'Jbrofuzz',                    // OWASP fuzzer
                    'l9scan',                      // LeakIX scanner
                    'l9explore',                   // LeakIX exploration
                    'l9tcpid',                     // LeakIX TCP identifier
                    'leakix',                      // LeakIX vulnerability scanner
                    'Webshag',                     // Web server audit tool
                    'Nimbostratus',                // Cloud attack tool
                    'muhstik-scan',                // Muhstik botnet scanner
                    'T0PHackTeam',                 // Hacking group scanner
                    'Joomla',                      // Joomla vulnerability scanner
                    'phpMyAdmin',                  // phpMyAdmin exploit scanner
                    'scan.lol',                    // Vulnerability scanning service
                    'probely.com',                 // Security testing scanner
                    'cyberscan.io',                // Cyber vulnerability scanner
                    'Hardenize',                   // TLS/security assessment
                    'NetSystemsResearch',          // Network research scanner
                    'InternetMeasurement',         // Internet-wide measurement scan
                    'DomainCrawler',               // Domain intelligence scraper
                    'DomainStatsBot',              // Domain stats collector
                    'BackDoorBot',                 // Known malicious crawler
                    'Black Hole',                  // Content theft bot
                    'Zeus',                        // Zeus botnet variant
                    'Siphon',                      // Data siphoning tool
                    'Vacuum',                      // Data vacuuming tool
                ],
            ],

            'data_harvesters' => [
                'label' => 'Data Harvester',
                'confidence' => 80,
                'bots' => [
                    // --- Original ---
                    'curl', 'python-requests', 'Go-http-client',
                    'Java/', 'libwww-perl', 'Wget',
                    'HTTPie', 'axios', 'node-fetch',
                    'http_request2', 'pycurl', 'aiohttp',
                    'httpx', 'urllib', 'requests/',
                    // --- Added: HTTP clients, libraries, and data collection tools 2024-2025 ---
                    'python-httpx',                // Modern Python HTTP client
                    'Python-httplib2',             // Python httplib2 library
                    'Python-urllib',               // Python urllib (capitalized variant)
                    'okhttp',                      // OkHttp Java/Android client
                    'Apache-HttpClient',           // Apache Java HTTP client
                    'Apache-HttpAsyncClient',      // Apache async Java HTTP client
                    'RestSharp',                   // .NET REST client library
                    'Typhoeus',                    // Ruby HTTP client
                    'Faraday',                     // Ruby HTTP client library
                    'hackney',                     // Elixir HTTP client
                    'reqwest',                     // Rust HTTP client
                    'fasthttp',                    // Go high-perf HTTP client
                    'lua-resty-http',              // Lua/OpenResty HTTP client
                    'Zend_Http_Client',            // PHP Zend HTTP client
                    'GuzzleHttp',                  // PHP Guzzle (full name variant)
                    'PostmanRuntime',              // Postman API testing client
                    'insomnia/',                   // Insomnia API client
                    'http.rb',                     // Ruby HTTP library
                    'libcurl',                     // cURL library identifier
                    'node-superagent',             // Node.js HTTP client
                    'node-urllib',                 // Node.js urllib client
                    'php-requests',                // PHP Requests library
                    'http-kit',                    // Clojure HTTP client
                    'Mojolicious',                 // Perl web framework client
                    'lwp-request',                 // Perl LWP request
                    'Dispatch/',                   // Scala HTTP client
                    'unirest-java',                // Unirest Java HTTP client
                    'UniversalFeedParser',         // Python RSS/Atom feed parser
                    'phpcrawl',                    // PHP crawling library
                    'Symfony BrowserKit',          // Symfony testing client
                    'colly',                       // Go scraping framework (variant)
                ],
            ],
        ];
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

    public static function findBot(string $userAgent): ?array
    {
        foreach (self::getCategories() as $categoryKey => $category) {
            foreach ($category['bots'] as $bot) {
                if (stripos($userAgent, $bot) !== false) {
                    return [
                        'category' => $categoryKey,
                        'label' => $category['label'],
                        'confidence' => $category['confidence'],
                        'matched_bot' => $bot,
                    ];
                }
            }
        }
        return null;
    }
}
