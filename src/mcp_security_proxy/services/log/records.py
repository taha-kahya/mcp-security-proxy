"""Audit record schemas.

Records hold only sanitized data: tool arguments are reduced to a digest and
their top-level key names, so audit files never contain raw argument values
such as secrets or message bodies. A request's `_meta` is masked the same way,
except for keys the operator allowlists (0023).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer


class ArgumentDigest(BaseModel):
    model_config = ConfigDict(frozen=True)

    sha256: str
    keys: tuple[str, ...]

    @classmethod
    def of(cls, arguments: Mapping[str, Any]) -> ArgumentDigest:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
        return cls(
            sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            keys=tuple(sorted(arguments)),
        )


class MetaDigest(ArgumentDigest):
    """A request's `_meta`, masked like arguments, plus allowlisted values.

    `values` holds the value of each allowlisted key that is present, but only
    when it is a string, number, or boolean. A null, list, or object value is
    never recorded raw, even for an allowlisted key: it is masked like the rest.
    """

    values: Mapping[str, str | int | float | bool] = Field(default_factory=dict)

    @classmethod
    def masked(cls, meta: Mapping[str, Any], unmasked_keys: Collection[str] = ()) -> MetaDigest:
        digest = ArgumentDigest.of(meta)
        values = {
            key: value
            for key, value in meta.items()
            if key in unmasked_keys and isinstance(value, str | int | float | bool)
        }
        return cls(sha256=digest.sha256, keys=digest.keys, values=values)


class InspectionSummary(BaseModel):
    """One defense's inspection, without its evidence or any inspected content."""

    model_config = ConfigDict(frozen=True)

    defense_id: str
    defense_version: str
    status: str
    finding_rule_ids: tuple[str, ...] = ()
    detail: str | None = None


class AuditRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    principal_id: str
    authenticated_by: str


class DiscoveryRecord(AuditRecord):
    kind: Literal["discovery"] = "discovery"
    policy_version: str
    visible_tool_count: int
    hidden_by_inspection: tuple[str, ...] = ()


class InstructionsRecord(AuditRecord):
    """Whether a server's `initialize` instructions were forwarded (I4)."""

    kind: Literal["instructions"] = "instructions"
    server_id: str
    forwarded: bool
    inspections: tuple[InspectionSummary, ...] = ()


class DecisionRecord(AuditRecord):
    kind: Literal["decision"] = "decision"
    correlation_id: str
    requested_tool: str
    tool_id: str | None
    decision_id: str
    outcome: str
    rule_refs: tuple[str, ...]
    reason: str
    policy_version: str
    arguments: ArgumentDigest
    operation: str | None = None
    inspections: tuple[InspectionSummary, ...] = ()
    # Only present when the request carried `_meta` in transparent mode, so
    # every other record serializes exactly as before.
    meta: MetaDigest | None = None

    @model_serializer(mode="wrap")
    def _omit_absent_meta(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if self.meta is None:
            data.pop("meta", None)
        return data


class DeliveryRecord(AuditRecord):
    """Whether a dispatched call's result was released to the agent.

    A withheld result does not undo the call: it already ran upstream.
    """

    kind: Literal["delivery"] = "delivery"
    correlation_id: str
    tool_id: str
    decision_id: str
    outcome: str
    rule_refs: tuple[str, ...]
    reason: str
    policy_version: str
    inspections: tuple[InspectionSummary, ...] = ()


class OutcomeRecord(AuditRecord):
    """What happened upstream after a dispatched call.

    `status` is `completed`, `failed`, or `unknown`; `unknown` means the call
    may have taken effect upstream but no definitive response arrived.
    """

    kind: Literal["outcome"] = "outcome"
    correlation_id: str
    decision_id: str
    tool_id: str
    status: str
    tool_error: bool | None
