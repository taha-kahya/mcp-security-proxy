"""In-flight call bookkeeping, independent of any single upstream connection.

The MCP SDK already correlates JSON-RPC request/response ids and propagates
cancellation and connection-closed errors within a single connection. This
module adds a layer on top, scoped to the whole proxy process: it tracks
which upstream server each in-flight call belongs to, so that if a server's
connection drops while calls are in flight, those calls can be reported as
outcome-unknown rather than silently dropped or misattributed to another
server.

Correlation ids are created before a call is decided (`new_correlation_id`),
so the decision record, the in-flight entry, and the outcome record of one
request all share the same id. `mark_server_unknown` is still not called
anywhere: an interrupted call is ended as `UNKNOWN` by the orchestrator
itself (see 0013), but a dropped connection does not yet proactively mark
other in-flight calls against that server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic
from uuid import uuid4


class CallStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class InFlightCall:
    correlation_id: str
    server_id: str
    external_tool_name: str
    started_at: float
    status: CallStatus = field(default=CallStatus.PENDING)


def new_correlation_id() -> str:
    return uuid4().hex


class CorrelationTracker:
    def __init__(self) -> None:
        self._in_flight: dict[str, InFlightCall] = {}

    def begin(self, correlation_id: str, server_id: str, external_tool_name: str) -> None:
        self._in_flight[correlation_id] = InFlightCall(
            correlation_id=correlation_id,
            server_id=server_id,
            external_tool_name=external_tool_name,
            started_at=monotonic(),
        )

    def end(self, correlation_id: str, status: CallStatus) -> None:
        call = self._in_flight.pop(correlation_id, None)
        if call is not None:
            call.status = status

    def in_flight_for_server(self, server_id: str) -> list[InFlightCall]:
        return [call for call in self._in_flight.values() if call.server_id == server_id]

    def mark_server_unknown(self, server_id: str) -> list[InFlightCall]:
        affected = self.in_flight_for_server(server_id)
        for call in affected:
            call.status = CallStatus.UNKNOWN
            self._in_flight.pop(call.correlation_id, None)
        return affected
