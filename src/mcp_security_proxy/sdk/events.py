"""The event a defense inspects: one protocol message at one lifecycle stage."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from mcp_security_proxy.sdk.actions import Action
from mcp_security_proxy.sdk.frozen import freeze
from mcp_security_proxy.sdk.types import ToolId
from mcp_security_proxy.sdk.version import CONTRACT_VERSION


class Stage(StrEnum):
    """`discovery` inspects one tool definition, `before_execution` one call's
    arguments, `before_delivery` one call's result. `lifecycle` is reserved
    for notifications and is not emitted yet."""

    DISCOVERY = "discovery"
    BEFORE_EXECUTION = "before_execution"
    BEFORE_DELIVERY = "before_delivery"
    LIFECYCLE = "lifecycle"


class Direction(StrEnum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"
    INTERNAL = "internal"


class ContentSource(StrEnum):
    TOOL_DEFINITION = "tool_definition"
    TOOL_ARGUMENTS = "tool_arguments"
    TOOL_RESULT = "tool_result"


@dataclass(frozen=True)
class Provenance:
    """Where a content block came from. Content from a server is untrusted."""

    server_id: str
    tool_id: ToolId | None
    source: ContentSource


@dataclass(frozen=True)
class ContentBlock:
    """One typed content block, kept whole rather than flattened to text.

    `type` is the protocol's own block type (`text`, `image`, `resource`, ...,
    or `structured` for a result's structured content). Types a defense does
    not understand are still delivered; the defense reports `unsupported`.
    """

    type: str
    data: Mapping[str, Any]
    provenance: Provenance

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", freeze(self.data))


@dataclass(frozen=True)
class Event:
    event_id: str
    correlation_id: str
    stage: Stage
    direction: Direction
    method: str
    server_id: str
    payload: Mapping[str, Any]
    timestamp: datetime
    content: tuple[ContentBlock, ...] = ()
    tool_id: ToolId | None = None
    action: Action | None = None
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", freeze(self.payload))
        object.__setattr__(self, "content", tuple(self.content))
