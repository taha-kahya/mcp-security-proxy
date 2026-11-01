"""Tool adapters: derive an `Action` from a known tool and its arguments.

Semantics come from operator configuration only. A tool's name, description,
and annotations are server claims and are never used to classify it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from mcp_security_proxy.sdk import Action, Operation, ToolId, canonical_digest

CONFIGURED_ADAPTER_ID = "configured"


class ToolSemanticsError(ValueError):
    """The tool semantics file is missing, malformed, or inconsistent."""


class ToolAdapter(Protocol):
    @property
    def adapter_id(self) -> str: ...

    @property
    def adapter_version(self) -> str: ...

    def action(self, tool_id: ToolId, arguments: Mapping[str, Any]) -> Action: ...


class _ToolEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: Operation


class _SemanticsDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    tools: dict[str, _ToolEntry]

    @field_validator("tools")
    @classmethod
    def _keys_are_tool_ids(cls, tools: dict[str, _ToolEntry]) -> dict[str, _ToolEntry]:
        for text in tools:
            ToolId.parse(text)
        return tools

    def version(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


class ConfiguredToolAdapter:
    """Maps exact tool ids to an operation. Unlisted tools are `unknown`.

    Arguments are not inspected yet, so `resource` and `destination` stay
    unset; argument-aware adapters arrive with the defenses that need them.
    """

    def __init__(self, operations: Mapping[ToolId, Operation], version: str) -> None:
        self._operations = dict(operations)
        self._version = version

    @classmethod
    def empty(cls) -> ConfiguredToolAdapter:
        """No tool is classified: every action is `unknown`."""
        return cls({}, version="none")

    @property
    def adapter_id(self) -> str:
        return CONFIGURED_ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        return self._version

    def action(self, tool_id: ToolId, arguments: Mapping[str, Any]) -> Action:
        operation = self._operations.get(tool_id, Operation.UNKNOWN)
        return Action(operation, adapter_id=self.adapter_id, adapter_version=self._version)

    def unmatched(self, known_tools: Iterable[ToolId]) -> list[ToolId]:
        """Configured tool ids that match no known tool: typos or missing servers."""
        known = set(known_tools)
        return sorted((t for t in self._operations if t not in known), key=str)


def parse_tool_semantics(data: object) -> ConfiguredToolAdapter:
    try:
        document = _SemanticsDocument.model_validate(data)
    except ValidationError as exc:
        raise ToolSemanticsError(f"invalid tool semantics: {exc}") from exc
    operations = {ToolId.parse(text): entry.operation for text, entry in document.tools.items()}
    return ConfiguredToolAdapter(operations, document.version())


def load_tool_semantics(path: Path) -> ConfiguredToolAdapter:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ToolSemanticsError(f"cannot read tool semantics file {path}: {exc}") from exc
    return parse_tool_semantics(data)
