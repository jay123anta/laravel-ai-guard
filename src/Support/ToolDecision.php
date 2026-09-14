<?php

namespace JayAnta\AiGuard\Support;

/**
 * The firewall's verdict on one tool call: allow, deny, or hold for human approval.
 */
final class ToolDecision
{
    public const ALLOW = 'allow';

    public const DENY = 'deny';

    public const APPROVE = 'approve';

    public function __construct(
        public readonly string $status,
        public readonly string $tool,
        public readonly ?string $reason = null,
    ) {}

    public static function allow(string $tool): self
    {
        return new self(self::ALLOW, $tool);
    }

    public static function deny(string $tool, string $reason): self
    {
        return new self(self::DENY, $tool, $reason);
    }

    public static function requireApproval(string $tool, string $reason): self
    {
        return new self(self::APPROVE, $tool, $reason);
    }

    public function allowed(): bool
    {
        return $this->status === self::ALLOW;
    }

    public function denied(): bool
    {
        return $this->status === self::DENY;
    }

    public function requiresApproval(): bool
    {
        return $this->status === self::APPROVE;
    }

    /**
     * The verdict as a threat result for logging.
     */
    public function toThreat(): array
    {
        return [
            'detected' => ! $this->allowed(),
            'threat_type' => $this->denied() ? 'tool_call_blocked' : 'tool_call_held',
            'threat_source' => mb_substr('tool:'.$this->tool, 0, 100),
            'confidence_score' => $this->denied() ? 90 : 70,
            'matched_pattern' => mb_substr((string) $this->reason, 0, 255),
        ];
    }
}
