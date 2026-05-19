import dataclasses
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mcp_security_tester.reports.models import Finding


@dataclass
class ToolCall:
    tool_name: str
    arguments: dict
    response_text: str
    duration_ms: float
    findings: list[Finding] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    flagged: bool = False

    def __post_init__(self):
        self.flagged = len(self.findings) > 0


class CallLogger:
    def __init__(self, log_path: str | None = None, max_recent: int = 50):
        self._calls: deque[ToolCall] = deque(maxlen=max_recent)
        self._log_path = Path(log_path) if log_path else None
        self._log_file = open(self._log_path, "a") if self._log_path else None

    def log(self, call: ToolCall) -> None:
        self._calls.append(call)
        if self._log_file:
            self._log_file.write(json.dumps(_serialize(call)) + "\n")
            self._log_file.flush()

    def recent(self, n: int = 10) -> list[ToolCall]:
        calls = list(self._calls)
        return calls[-n:] if n else calls

    def all_calls(self) -> list[ToolCall]:
        return list(self._calls)

    def close(self) -> None:               
        if self._log_file:
            self._log_file.close()

def _serialize(call: ToolCall) -> dict:
    d = dataclasses.asdict(call)
    d["findings"] = [dataclasses.asdict(f) for f in call.findings]
    return d
