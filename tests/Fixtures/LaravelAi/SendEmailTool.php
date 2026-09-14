<?php

namespace JayAnta\AiGuard\Tests\Fixtures\LaravelAi;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Ai\Contracts\Tool;
use Laravel\Ai\Tools\Request;

class SendEmailTool implements Tool
{
    /** @var array<int, array<string, mixed>> */
    public static array $sent = [];

    public function description(): string
    {
        return 'Send an email to a customer.';
    }

    public function handle(Request $request): string
    {
        self::$sent[] = $request->all();

        return 'sent';
    }

    public function schema(JsonSchema $schema): array
    {
        return [];
    }
}
