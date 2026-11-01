"""JSON form of history records, as persisted through State.

Kept separate so the persisted shape is defined in one place and History
itself deals only in SDK types.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from mcp_security_proxy.sdk import (
    Action,
    Operation,
    OperationRecord,
    OperationStatus,
    Sensitivity,
    Signal,
    ToolId,
    thaw,
)


def action_to_json(action: Action) -> dict[str, Any]:
    return {
        "operation": action.operation.value,
        "adapter_id": action.adapter_id,
        "adapter_version": action.adapter_version,
        "resource": action.resource,
        "destination": action.destination,
        "sensitivity": action.sensitivity.value,
    }


def action_from_json(data: Mapping[str, Any]) -> Action:
    return Action(
        operation=Operation(data["operation"]),
        adapter_id=data["adapter_id"],
        adapter_version=data["adapter_version"],
        resource=data["resource"],
        destination=data["destination"],
        sensitivity=Sensitivity(data["sensitivity"]),
    )


def operation_to_json(record: OperationRecord) -> dict[str, Any]:
    return {
        "operation_id": record.operation_id,
        "correlation_id": record.correlation_id,
        "tool_id": str(record.tool_id),
        "action": action_to_json(record.action),
        "status": record.status.value,
        "started_at": record.started_at.isoformat(),
    }


def operation_from_json(data: Mapping[str, Any]) -> OperationRecord:
    return OperationRecord(
        operation_id=data["operation_id"],
        correlation_id=data["correlation_id"],
        tool_id=ToolId.parse(data["tool_id"]),
        action=action_from_json(data["action"]),
        status=OperationStatus(data["status"]),
        started_at=datetime.fromisoformat(data["started_at"]),
    )


def signal_to_json(signal: Signal) -> dict[str, Any]:
    return {
        "type": signal.type,
        "schema_version": signal.schema_version,
        "producer": signal.producer,
        "value": thaw(signal.value),
        "evidence_refs": list(signal.evidence_refs),
    }


def signal_from_json(data: Mapping[str, Any]) -> Signal:
    return Signal(
        type=data["type"],
        schema_version=data["schema_version"],
        producer=data["producer"],
        value=data["value"],
        evidence_refs=tuple(data["evidence_refs"]),
    )
