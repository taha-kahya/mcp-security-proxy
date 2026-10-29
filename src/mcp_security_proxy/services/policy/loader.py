"""Parse and validate a policy file into a `PolicySnapshot`.

Policy comes only from operator-controlled configuration, never from server
content. Its version is a hash of the parsed document, so formatting-only
edits keep the version while any change in meaning produces a new one.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from mcp_security_proxy.sdk import canonical_digest
from mcp_security_proxy.services.policy.rules import Effect, ToolPattern, ToolRule
from mcp_security_proxy.services.policy.snapshot import PolicySnapshot


class PolicyError(ValueError):
    """The policy file is missing, malformed, or inconsistent."""


class _RuleEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str
    effect: Effect

    @field_validator("tool")
    @classmethod
    def _tool_must_be_a_valid_pattern(cls, value: str) -> str:
        ToolPattern.parse(value)
        return value


class _PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    principals: dict[str, list[_RuleEntry]]

    @model_validator(mode="after")
    def _no_duplicate_patterns_per_principal(self) -> _PolicyDocument:
        for principal_id, entries in self.principals.items():
            duplicates = [tool for tool, n in Counter(e.tool for e in entries).items() if n > 1]
            if duplicates:
                raise ValueError(f"principal {principal_id!r} lists {duplicates} more than once")
        return self

    def version(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))

    def rules_by_principal(self) -> dict[str, tuple[ToolRule, ...]]:
        return {
            principal_id: tuple(
                ToolRule(principal_id, ToolPattern.parse(entry.tool), entry.effect)
                for entry in entries
            )
            for principal_id, entries in self.principals.items()
        }


def parse_policy(data: object) -> PolicySnapshot:
    try:
        document = _PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"invalid policy: {exc}") from exc
    return PolicySnapshot(document.version(), document.rules_by_principal())


def load_policy(path: Path) -> PolicySnapshot:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    return parse_policy(data)
