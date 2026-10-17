"""Append-only JSONL audit log for mock servers.

This is the independent ground truth used by tests to verify which server
actually executed a call, rather than trusting a client's or proxy's own
claims about where a request was routed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, server_id: str, tool_name: str, arguments: dict[str, Any]) -> None:
        entry = {
            "server_id": server_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "timestamp": time.time(),
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def read_entries(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
