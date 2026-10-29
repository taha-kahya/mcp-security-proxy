"""The Approval contract, declared ahead of its implementation (V5).

Consent binds one exact proposed action. Any change to the binding (other
arguments, another tool version or policy version, a later time) makes the
approval inapplicable, and each approval can be consumed once. Approval can
never override a hard block.

Nothing implements or calls this yet: until it is implemented, every
`require_approval` decision is enforced as a block (see `Decision`).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from mcp_security_proxy.sdk import ToolId


@dataclass(frozen=True)
class ActionBinding:
    """Everything an approval is bound to. `arguments_digest` is the
    `canonical_digest` of the call's arguments."""

    principal_id: str
    task_id: str
    tool_id: ToolId
    arguments_digest: str
    tool_version: str
    policy_version: str
    expires_at: datetime
    nonce: str


@dataclass(frozen=True)
class ApprovalHandle:
    approval_id: str


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    MISMATCHED = "mismatched"
    CONSUMED = "consumed"


@dataclass(frozen=True)
class ApprovalResult:
    status: ApprovalStatus

    @property
    def granted(self) -> bool:
        return self.status is ApprovalStatus.GRANTED


class Approval(Protocol):
    async def request(self, binding: ActionBinding) -> ApprovalHandle: ...

    async def validate_and_consume(
        self, handle: ApprovalHandle, binding: ActionBinding
    ) -> ApprovalResult:
        """Atomically check that `binding` matches what was approved and mark the
        approval consumed. Only a `granted` result authorizes one dispatch."""
        ...
