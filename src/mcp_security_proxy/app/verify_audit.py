"""Check an audit log's hash chain (plan MR S5).

    python -m mcp_security_proxy.app.verify_audit proxy_audit.jsonl

Exits 0 when every link verifies and 1 at the first break, naming its line.
It prints the last line's hash: store it where the proxy can't write, and a
later run that reports a different hash for the same records, or fewer
records, shows the log was cut short.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp_security_proxy.services.log import verify_chain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an audit log's hash chain")
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify_chain(args.path)
    except OSError as exc:
        print(f"cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    summary = f"{report.records} chained records"
    if report.unchained_prefix:
        summary += f" after {report.unchained_prefix} unchained (pre-chain) records"
    if not report.ok:
        print(f"BROKEN at line {report.break_line}: {report.reason} ({summary} before it)")
        return 1
    print(f"OK: {summary}; last sha256 {report.last_sha256}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
