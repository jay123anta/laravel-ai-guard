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
                ],
            ],

            'ai_assistants' => [
                'label' => 'AI Assistant',
                'confidence' => 90,
                'bots' => [
                    'PerplexityBot', 'YouBot', 'PhindBot',
                    'KagiBot', 'BraveSearch', 'Neeva',
                    'MetaAI', 'Siri', 'Copilot',
                    'NeevaBot',
                ],
            ],

            'search_engines' => [
                'label' => 'Search Engine',
                'confidence' => 30,
                'bots' => [
                    'Googlebot', 'Bingbot', 'bingbot',
                    'YandexBot', 'Baiduspider', 'DuckDuckBot',
                    'Sogou', 'Exabot', 'facebot',
                    'ia_archiver', 'Slurp', 'Applebot',
                    'Qwantify', 'Seznam', 'Naver',
                ],
            ],

            'seo_tools' => [
                'label' => 'SEO Tool',
                'confidence' => 60,
                'bots' => [
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
                ],
            ],

            'scrapers' => [
                'label' => 'Web Scraper',
                'confidence' => 85,
                'bots' => [
                    'Scrapy/', 'colly -', 'Colly/',
                    'HeadlessChrome', 'PhantomJS', 'Puppeteer',
                    'Playwright/', 'Selenium/', 'WebDriver',
                    'CasperJS', 'Splash/', 'Mechanize/',
                    'Nightmare/', 'SimplePie/', 'Guzzle/',
                    'CrawlerBot', 'SpiderBot', 'htmlparser/',
                    'WebHarvest', 'WebExtract', 'WebGrab',
                ],
            ],

            'bad_bots' => [
                'label' => 'Malicious Bot',
                'confidence' => 95,
                'bots' => [
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
                ],
            ],

            'data_harvesters' => [
                'label' => 'Data Harvester',
                'confidence' => 80,
                'bots' => [
                    'curl', 'python-requests', 'Go-http-client',
                    'Java/', 'libwww-perl', 'Wget',
                    'HTTPie', 'axios', 'node-fetch',
                    'http_request2', 'pycurl', 'aiohttp',
                    'httpx', 'urllib', 'requests/',
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
