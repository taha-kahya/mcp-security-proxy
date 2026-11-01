"""What a defense declares about itself, checked by the Runner at startup."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from mcp_security_proxy.sdk.events import Stage

_DEFENSE_ID = re.compile(r"^[a-z][a-z0-9_]*$")


class Capability(StrEnum):
    """Shared capabilities a defense may ask for in its context."""

    REGISTRY = "registry"
    HISTORY = "history"
    POLICY = "policy"
    PRIVATE_STATE = "private_state"


@dataclass(frozen=True)
class Manifest:
    """`sdk_version_range` is a PEP 440 specifier such as `>=1.0,<2`.

    `produced_signals` and `required_signals` are signal types. The Runner runs
    every producer of a required type before the defense that requires it.
    """

    id: str
    version: str
    sdk_version_range: str
    stages: frozenset[Stage]
    required_capabilities: frozenset[Capability] = field(default_factory=frozenset)
    required_signals: frozenset[str] = field(default_factory=frozenset)
    produced_signals: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        for name in ("stages", "required_capabilities", "required_signals", "produced_signals"):
            object.__setattr__(self, name, frozenset(getattr(self, name)))
        if not _DEFENSE_ID.match(self.id):
            raise ValueError(f"defense id must be lowercase snake_case: {self.id!r}")
        if not self.stages:
            raise ValueError(f"defense {self.id!r} declares no stages")
