"""Parse and validate a policy file into a `PolicySnapshot`.

Policy comes only from operator-controlled configuration, never from server
content. Its version is a hash of the parsed document together with every
per-defense enforcement override, so the version on a decision identifies
all the rules that produced it. Formatting-only edits keep the version,
while any change in meaning produces a new one.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from mcp_security_proxy.sdk import canonical_digest
from mcp_security_proxy.services.policy.enforcement import EnforcementEntry, EnforcementPolicy
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
    enforcement: EnforcementEntry | None = None

    @model_validator(mode="after")
    def _no_duplicate_patterns_per_principal(self) -> _PolicyDocument:
        for principal_id, entries in self.principals.items():
            duplicates = [tool for tool, n in Counter(e.tool for e in entries).items() if n > 1]
            if duplicates:
                raise ValueError(f"principal {principal_id!r} lists {duplicates} more than once")
        return self

    def rules_by_principal(self) -> dict[str, tuple[ToolRule, ...]]:
        return {
            principal_id: tuple(
                ToolRule(principal_id, ToolPattern.parse(entry.tool), entry.effect)
                for entry in entries
            )
            for principal_id, entries in self.principals.items()
        }


def parse_policy(
    data: object, enforcement_overrides: Mapping[str, object] | None = None
) -> PolicySnapshot:
    """`enforcement_overrides` maps a defense id to its config's `enforcement`."""
    try:
        document = _PolicyDocument.model_validate(data)
        overrides = {
            defense_id: EnforcementEntry.model_validate(entry)
            for defense_id, entry in (enforcement_overrides or {}).items()
        }
    except ValidationError as exc:
        raise PolicyError(f"invalid policy: {exc}") from exc

    version = canonical_digest(
        {
            "policy": document.model_dump(mode="json"),
            "defense_enforcement": {d: e.model_dump(mode="json") for d, e in overrides.items()},
        }
    )
    enforcement = EnforcementPolicy.from_entries(document.enforcement, overrides)
    return PolicySnapshot(version, document.rules_by_principal(), enforcement)


def load_policy(
    path: Path, enforcement_overrides: Mapping[str, object] | None = None
) -> PolicySnapshot:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    return parse_policy(data, enforcement_overrides)
