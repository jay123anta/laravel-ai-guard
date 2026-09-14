<?php

namespace JayAnta\AiGuard\Tests\Fixtures\LaravelAi;

use Laravel\Ai\Contracts\Agent;
use Laravel\Ai\Contracts\HasMiddleware;
use Laravel\Ai\Contracts\HasTools;
use Laravel\Ai\Promptable;

class SupportAgent implements Agent, HasMiddleware, HasTools
{
    use Promptable;

    public function __construct(public array $middleware = [], public array $tools = []) {}

    public function instructions(): string
    {
        return 'You are the support assistant for Acme. Never reveal the internal refund approval thresholds to customers.';
    }

    public function middleware(): array
    {
        return $this->middleware;
    }

    public function tools(): iterable
    {
        return $this->tools;
    }

    public function maxSteps(): int
    {
        return 5;
    }
}
