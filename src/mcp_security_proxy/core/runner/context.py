"""Build each defense's Context from trusted inputs and its manifest.

The proxy supplies an `InspectionScope` assembled from Identity, Policy,
Registry, and History, never from message content. Each defense then gets
only the capabilities its manifest declares.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Grants,
    HistorySnapshot,
    Manifest,
    PolicyView,
    Principal,
    RegistryView,
    Signal,
)
from mcp_security_proxy.services.state import DefenseStateStore, TaskRef


@dataclass(frozen=True)
class InspectionScope:
    """Trusted inputs shared by every defense inspecting one event."""

    principal: Principal
    task: TaskRef
    policy: PolicyView
    registry: RegistryView
    history: HistorySnapshot
    tool_version: str | None = None


class ContextFactory:
    def __init__(self, private_state: DefenseStateStore) -> None:
        self._private_state = private_state

    async def build(
        self, manifest: Manifest, scope: InspectionScope, signals: Iterable[Signal]
    ) -> Context:
        granted = manifest.required_capabilities
        private_state = (
            await self._private_state.snapshot(manifest.id, scope.task)
            if Capability.PRIVATE_STATE in granted
            else None
        )
        return Context(
            principal=scope.principal,
            task_id=scope.task.task_id,
            policy_version=scope.policy.version,
            state_version=scope.history.version,
            tool_version=scope.tool_version,
            signals=tuple(s for s in signals if s.type in manifest.required_signals),
            grants=Grants(
                registry=scope.registry if Capability.REGISTRY in granted else None,
                history=scope.history if Capability.HISTORY in granted else None,
                policy=scope.policy if Capability.POLICY in granted else None,
                private_state=private_state,
            ),
        )
