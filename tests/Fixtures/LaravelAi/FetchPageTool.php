<?php

namespace JayAnta\AiGuard\Tests\Fixtures\LaravelAi;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Ai\Contracts\Tool;
use Laravel\Ai\Tools\Request;

class FetchPageTool implements Tool
{
    public static string $page = 'Opening hours: 9 to 5.';

    public function description(): string
    {
        return 'Fetch a web page.';
    }

    public function handle(Request $request): string
    {
        return self::$page;
    }

    public function schema(JsonSchema $schema): array
    {
        return [];
    }
}
