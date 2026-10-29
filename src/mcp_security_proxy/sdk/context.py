"""The trusted context a defense evaluates an event in.

Created by the core, never from message content: identity, task, and policy
fields cannot be supplied by an MCP server. A defense gets only the
capabilities its manifest declares; using any other raises
`CapabilityNotGrantedError`, which the Runner reports as a failed inspection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeVar

from mcp_security_proxy.sdk.capabilities import (
    HistorySnapshot,
    PolicyView,
    PrivateState,
    RegistryView,
)
from mcp_security_proxy.sdk.manifest import Capability
from mcp_security_proxy.sdk.results import Signal
from mcp_security_proxy.sdk.types import Principal

_T = TypeVar("_T")


class CapabilityNotGrantedError(PermissionError):
    """A defense used a capability its manifest did not declare."""


@dataclass(frozen=True)
class Grants:
    """The capabilities handed to one defense; `None` means not granted."""

    registry: RegistryView | None = None
    history: HistorySnapshot | None = None
    policy: PolicyView | None = None
    private_state: PrivateState | None = None


@dataclass(frozen=True)
class Context:
    """`state_version` is the version of the task history the decision is
    based on. `signals` holds the signals produced earlier in this same
    inspection, limited to the types the manifest requires."""

    principal: Principal
    task_id: str
    policy_version: str
    state_version: int
    tool_version: str | None = None
    signals: tuple[Signal, ...] = ()
    grants: Grants = field(default_factory=Grants, repr=False)

    @property
    def registry(self) -> RegistryView:
        return _granted(self.grants.registry, Capability.REGISTRY)

    @property
    def history(self) -> HistorySnapshot:
        return _granted(self.grants.history, Capability.HISTORY)

    @property
    def policy(self) -> PolicyView:
        return _granted(self.grants.policy, Capability.POLICY)

    @property
    def private_state(self) -> PrivateState:
        return _granted(self.grants.private_state, Capability.PRIVATE_STATE)

    def signals_of(self, signal_type: str) -> tuple[Signal, ...]:
        return tuple(signal for signal in self.signals if signal.type == signal_type)


def _granted(capability: _T | None, name: Capability) -> _T:
    if capability is None:
        raise CapabilityNotGrantedError(f"capability {name!r} was not declared in the manifest")
    return capability
