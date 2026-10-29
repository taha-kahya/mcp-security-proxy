"""Resolve the task a verified principal's operational state is kept under.

There is still no trusted source of task ids (see 0011 and 0016): the MCP
session belongs to the connection, and anything in the payload is
agent-controlled. The configured isolation boundary is therefore the
principal itself: every session of one principal shares one task, so
history-based rules apply across all of them. A trusted client integration
can later supply a real task boundary behind this same interface.
"""

from __future__ import annotations

from typing import Protocol

from mcp_security_proxy.sdk import Principal
from mcp_security_proxy.services.state import TaskRef


class TaskResolver(Protocol):
    def task_for(self, principal: Principal) -> TaskRef: ...


class PrincipalTaskResolver:
    def task_for(self, principal: Principal) -> TaskRef:
        return TaskRef(principal_id=principal.id, task_id=principal.id)
