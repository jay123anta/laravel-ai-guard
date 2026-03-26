<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;

class HoneypotService
{
    private array $config;
    private array $trapPaths;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->trapPaths = $config['honeypot']['trap_paths'] ?? self::getDefaultTrapPaths();
    }

    public function detect(Request $request): array
    {
        if (!($this->config['honeypot']['enabled'] ?? false)) {
            return $this->buildEmptyResult();
        }

        $path = '/' . ltrim($request->path(), '/');

        foreach ($this->trapPaths as $trapPath) {
            if (strcasecmp($path, $trapPath) === 0) {
                return [
                    'detected' => true,
                    'threat_type' => 'honeypot_trap',
                    'threat_source' => 'honeypot',
                    'confidence_score' => 100,
                    'matched_pattern' => $trapPath,
                ];
            }
        }

        return $this->buildEmptyResult();
    }

    public function isEnabled(): bool
    {
        return $this->config['honeypot']['enabled'] ?? false;
    }

    public function getTrapPaths(): array
    {
        return $this->trapPaths;
    }

    public static function getDefaultTrapPaths(): array
    {
        return [
            // Admin panels that don't exist
            '/admin-backup',
            '/wp-admin',
            '/wp-login.php',
            '/administrator',
            '/admin.php',

            // Fake API endpoints
            '/api/v1/users.json',
            '/api/v1/config.json',
            '/api/internal/debug',
            '/api/v2/export',

            // Common exploit paths
            '/.env',
            '/.git/config',
            '/.aws/credentials',
            '/phpinfo.php',
            '/server-status',
            '/debug/vars',

            // Fake data endpoints
            '/backup.sql',
            '/database.sql',
            '/dump.sql',
            '/users.csv',
            '/data/export.json',

            // Version control
            '/.svn/entries',
            '/.hg/store',
            '/.git/HEAD',
            '/.gitignore.bak',

            // Config files
            '/config.php.bak',
            '/web.config',
            '/crossdomain.xml',
            '/elmah.axd',
        ];
    }

    private function buildEmptyResult(): array
    {
        return [
            'detected' => false,
            'threat_type' => null,
            'threat_source' => null,
            'confidence_score' => 0,
            'matched_pattern' => null,
        ];
    }
}
