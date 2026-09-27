<?php

namespace JayAnta\AiGuard\Events;

use Illuminate\Http\Request;

/**
 * Shared shape of the ai-guard.verdict/1 events. The contract is the three concrete class
 * names, their public properties, and the SCHEMA string — not this base class. Listeners
 * subscribe by class-name string and read the properties; nothing needs to import it.
 *
 * Scalars only, so a listener can be queued and a payload logged or forwarded. The path has
 * no query string, so nothing a visitor typed into a URL reaches listeners.
 *
 * @internal
 */
abstract class BotVerdictEvent
{
    public const SCHEMA = 'ai-guard.verdict/1';

    public readonly string $schema;

    public readonly ?string $category;

    public readonly ?string $token;

    public readonly ?string $identity;

    public readonly ?string $status;

    public readonly ?string $method;

    public readonly string $ip;

    public readonly string $requestMethod;

    public readonly string $path;

    public readonly string $evaluatedAt;

    /**
     * @param  array{schema: string, bot: array{category: string|null, token: string|null, identity: string|null}, verification: array{status: string|null, method: string|null}, evaluated_at: string}  $verdict
     */
    public function __construct(array $verdict, Request $request)
    {
        $this->schema = self::SCHEMA;
        $this->category = $verdict['bot']['category'];
        $this->token = $verdict['bot']['token'];
        $this->identity = $verdict['bot']['identity'];
        $this->status = $verdict['verification']['status'];
        $this->method = $verdict['verification']['method'];
        $this->ip = (string) $request->ip();
        $this->requestMethod = $request->getMethod();
        $this->path = $request->path();
        $this->evaluatedAt = $verdict['evaluated_at'];
    }

    /**
     * The request attribute's array, plus where the request came from and went.
     *
     * @return array{schema: string, bot: array{category: string|null, token: string|null, identity: string|null}, verification: array{status: string|null, method: string|null}, evaluated_at: string, request: array{ip: string, method: string, path: string}}
     */
    public function toArray(): array
    {
        return [
            'schema' => $this->schema,
            'bot' => ['category' => $this->category, 'token' => $this->token, 'identity' => $this->identity],
            'verification' => ['status' => $this->status, 'method' => $this->method],
            'evaluated_at' => $this->evaluatedAt,
            'request' => ['ip' => $this->ip, 'method' => $this->requestMethod, 'path' => $this->path],
        ];
    }
}
