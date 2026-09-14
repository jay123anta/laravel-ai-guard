<?php

namespace JayAnta\AiGuard\Exceptions;

use Illuminate\Http\JsonResponse;
use JayAnta\AiGuard\Support\BudgetDecision;
use RuntimeException;

/**
 * Thrown when AI Guard stops a model call outside an HTTP middleware (laravel/ai agents).
 * Uncaught in a web request, it renders as a JSON 403 (threat), 429 (budget), or 413 (input too large).
 */
class AiGuardBlockedException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly array $result,
        public readonly int $status = 403,
        public readonly int $retryAfter = 0,
    ) {
        parent::__construct($message);
    }

    public static function threat(array $result): self
    {
        return new self('Blocked by AI Guard: '.($result['threat_type'] ?? 'threat'), $result);
    }

    public static function budget(BudgetDecision $decision, array $result): self
    {
        return new self($decision->message(), $result, $decision->httpStatus(), $decision->retryAfter);
    }

    public function render(): JsonResponse
    {
        $response = response()->json([
            'error' => match ($this->status) {
                413 => 'Payload too large',
                429 => 'Too many requests',
                default => 'Access denied',
            },
            'message' => $this->getMessage(),
            'threat_type' => $this->result['threat_type'] ?? null,
        ], $this->status);

        if ($this->retryAfter > 0) {
            $response->headers->set('Retry-After', (string) $this->retryAfter);
        }

        return $response;
    }
}
