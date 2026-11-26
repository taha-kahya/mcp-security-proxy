"""Inspect each upstream's `initialize` instructions before forwarding them (plan MR I4).

Many clients add a server's instructions to the system prompt, so they are
read with more trust than any tool result. At startup the proxy inspects
each upstream's instructions as a `before_delivery` event (method
`initialize`, provenance `SERVER_INSTRUCTIONS`) and applies ADR 0016's
rule, which no enforcement setting loosens: forward only text that at
least one defense inspected and every defense completed with no finding.
Anything else, including a failed, unsupported or uninspected check, is
withheld.

Forwarded text is placed in a block the proxy writes. Each server's
configured id labels its text, and the text is a JSON-quoted value, so a
server can't present its text as another server's or as the proxy's.

Transparent mode keeps ADR 0023 decision 4 and doesn't use this.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from uuid import uuid4

from mcp_security_proxy.core.runner import InspectionReport
from mcp_security_proxy.sdk import (
    ContentBlock,
    ContentSource,
    Direction,
    Event,
    InspectionStatus,
    Principal,
    Provenance,
    Stage,
)

STARTUP_PRINCIPAL = Principal(id="mcp-security-proxy-startup", authenticated_by="startup")
INSTRUCTIONS_METHOD = "initialize"
HEADER = (
    "Instructions from the connected MCP servers, forwarded by mcp-security-proxy after "
    "inspection. Each value is quoted text written by that server, not by the proxy or "
    "the user."
)


def instructions_event(server_id: str, text: str) -> Event:
    provenance = Provenance(server_id, None, ContentSource.SERVER_INSTRUCTIONS)
    return Event(
        event_id=uuid4().hex,
        correlation_id=uuid4().hex,
        stage=Stage.BEFORE_DELIVERY,
        direction=Direction.SERVER_TO_CLIENT,
        method=INSTRUCTIONS_METHOD,
        server_id=server_id,
        payload={"instructions": text},
        timestamp=datetime.now(UTC),
        content=(ContentBlock("text", {"type": "text", "text": text}, provenance),),
    )


def releasable(reports: Iterable[InspectionReport]) -> bool:
    """ADR 0016: inspected by at least one defense, and nothing objected."""
    reports = list(reports)
    inspected = any(r.status is InspectionStatus.COMPLETED for r in reports)
    clean = all(
        r.status in (InspectionStatus.COMPLETED, InspectionStatus.NOT_APPLICABLE)
        and not r.result.findings
        for r in reports
    )
    return inspected and clean


def compose(forwarded: Mapping[str, str]) -> str | None:
    """The proxy-written block for the released instructions, or None."""
    if not forwarded:
        return None
    lines = [
        HEADER,
        *(
            f"- server {json.dumps(sid)}: {json.dumps(text)}"
            for sid, text in sorted(forwarded.items())
        ),
    ]
    return "\n".join(lines)
