"""Build SDK `Event`s from the protocol messages the proxy handles.

Content blocks keep their protocol type and full structure; nothing is
flattened to text, and block types the proxy does not know are passed along
unchanged for defenses to report as unsupported.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mcp import types

from mcp_security_proxy.sdk import (
    Action,
    ContentBlock,
    ContentSource,
    Direction,
    Event,
    Provenance,
    Stage,
    ToolDefinition,
    ToolId,
)

STRUCTURED_CONTENT_TYPE = "structured"


def discovery_event(definition: ToolDefinition) -> Event:
    return _event(
        stage=Stage.DISCOVERY,
        direction=Direction.SERVER_TO_CLIENT,
        method="tools/list",
        correlation_id=uuid4().hex,
        tool_id=definition.tool_id,
        payload=definition.definition,
    )


def execution_event(
    correlation_id: str, tool_id: ToolId, arguments: Mapping[str, Any], action: Action
) -> Event:
    return _event(
        stage=Stage.BEFORE_EXECUTION,
        direction=Direction.CLIENT_TO_SERVER,
        method="tools/call",
        correlation_id=correlation_id,
        tool_id=tool_id,
        payload={"name": tool_id.name, "arguments": arguments},
        action=action,
    )


def delivery_event(
    correlation_id: str, tool_id: ToolId, result: types.CallToolResult, action: Action
) -> Event:
    return _event(
        stage=Stage.BEFORE_DELIVERY,
        direction=Direction.SERVER_TO_CLIENT,
        method="tools/call",
        correlation_id=correlation_id,
        tool_id=tool_id,
        payload=result.model_dump(mode="json", by_alias=True, exclude_none=True),
        content=result_content(tool_id, result),
        action=action,
    )


def result_content(tool_id: ToolId, result: types.CallToolResult) -> tuple[ContentBlock, ...]:
    provenance = Provenance(tool_id.server_id, tool_id, ContentSource.TOOL_RESULT)
    blocks = [
        ContentBlock(
            type=block.type,
            data=block.model_dump(mode="json", by_alias=True, exclude_none=True),
            provenance=provenance,
        )
        for block in result.content
    ]
    if result.structured_content is not None:
        blocks.append(ContentBlock(STRUCTURED_CONTENT_TYPE, result.structured_content, provenance))
    return tuple(blocks)


def _event(
    *,
    stage: Stage,
    direction: Direction,
    method: str,
    correlation_id: str,
    tool_id: ToolId,
    payload: Mapping[str, Any],
    content: tuple[ContentBlock, ...] = (),
    action: Action | None = None,
) -> Event:
    return Event(
        event_id=uuid4().hex,
        correlation_id=correlation_id,
        stage=stage,
        direction=direction,
        method=method,
        server_id=tool_id.server_id,
        payload=payload,
        timestamp=datetime.now(UTC),
        content=content,
        tool_id=tool_id,
        action=action,
    )
