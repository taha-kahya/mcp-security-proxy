"""The interface every defense implements.

A defense inspects; it never forwards, blocks, or approves anything itself.
It reports a `Result`, and Guard turns results into a decision using policy.
Exceptions and deadline overruns are turned into `failed` results by the
Runner, so a defense does not need to catch everything itself.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from mcp_security_proxy.sdk.context import Context
from mcp_security_proxy.sdk.events import Event
from mcp_security_proxy.sdk.manifest import Manifest
from mcp_security_proxy.sdk.results import Result


class Defense(Protocol):
    def manifest(self) -> Manifest: ...

    async def evaluate(self, event: Event, context: Context) -> Result: ...


DefenseFactory = Callable[[Mapping[str, Any]], Defense]
"""Builds a defense from its operator-configured settings. This is what a
defense package registers under the `mcp_security_proxy.defenses` entry-point
group. It raises `ValueError` for invalid settings."""

DEFENSE_ENTRY_POINT_GROUP = "mcp_security_proxy.defenses"
