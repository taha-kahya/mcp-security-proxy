"""Serialize a Report to JSON, findings sorted by severity (CRITICAL first)."""

import dataclasses
import json

from mcp_security_tester.reports.models import Report


def to_json(report: Report, indent: int = 2) -> str:
    data = {
        "target": report.target,
        "timestamp": report.timestamp,
        "summary": report.summary,
        "findings": [dataclasses.asdict(f) for f in report.sorted_findings()],
    }
    return json.dumps(data, indent=indent)


def write_json(report: Report, path: str) -> None:
    with open(path, "w") as f:
        f.write(to_json(report))
