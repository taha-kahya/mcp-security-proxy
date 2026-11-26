"""Hash chain over the JSON Lines audit log (plan MR S5).

Every line the sink writes carries two fields besides the record:

- `seq`: 0 for the first chained record, then one more per line;
- `prev_sha256`: the SHA-256 of the previous line's text (UTF-8, without
  its line terminator), or `GENESIS` for the first line of the file.

Editing, inserting, deleting or reordering any record breaks the link from
the line after it, and `verify` reports the first break. Line terminators
are not hashed, so converting the file between LF and CRLF is not reported.

Lines written before chaining existed (no `prev_sha256`) are accepted only
as a prefix: the first chained line links to the last of them, and once a
chained line appears, every later line must be chained.

Removing records from the end leaves a valid, shorter chain, which no check
of the file alone can detect. An operator who needs that guarantee stores
the last hash `verify` reports somewhere the proxy can't write, and compares
it later.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
SEQ_FIELD = "seq"
PREV_FIELD = "prev_sha256"
_TAIL_CHUNK = 64 * 1024


class AuditChainError(Exception):
    """The audit log can't be extended safely, for example after a partial write."""


def line_hash(line: str) -> str:
    """The hash the next line stores: of this line's text, without its terminator."""
    return hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainHead:
    """Where the next record continues the chain."""

    next_seq: int
    prev_sha256: str

    @classmethod
    def start(cls) -> ChainHead:
        return cls(0, GENESIS)

    def after(self, line: str) -> ChainHead:
        return ChainHead(self.next_seq + 1, line_hash(line))


def chained_line(record: dict[str, Any], head: ChainHead) -> str:
    """The record as one JSON line (no terminator), linked to `head`."""
    if SEQ_FIELD in record or PREV_FIELD in record:
        raise ValueError(f"audit records must not define {SEQ_FIELD!r} or {PREV_FIELD!r}")
    linked = {**record, SEQ_FIELD: head.next_seq, PREV_FIELD: head.prev_sha256}
    return json.dumps(linked, ensure_ascii=False, separators=(",", ":"))


def read_head(path: Path) -> ChainHead:
    """The head after the file's last line, for a sink that appends to it.

    Raises `AuditChainError` if the file doesn't end with a line terminator
    (a write was cut off) or its last line isn't a JSON object, since
    appending after either would hide the damage.
    """
    last = _last_line(path)
    if last is None:
        return ChainHead.start()
    entry = _parse(last)
    if entry is None:
        raise AuditChainError(f"audit log {path} ends with a line that is not a JSON object")
    seq = entry.get(SEQ_FIELD)
    next_seq = seq + 1 if PREV_FIELD in entry and isinstance(seq, int) else 0
    return ChainHead(next_seq, line_hash(last))


def _last_line(path: Path) -> str | None:
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return None
        f.seek(size - 1)
        if f.read(1) != b"\n":
            raise AuditChainError(f"audit log {path} ends with a partial line")
        tail = b""
        position = size
        while True:
            step = min(_TAIL_CHUNK, position)
            position -= step
            f.seek(position)
            tail = f.read(step) + tail
            body = tail[:-1]  # without the final terminator
            newline = body.rfind(b"\n")
            if newline != -1:
                return body[newline + 1 :].decode("utf-8")
            if position == 0:
                return body.decode("utf-8")


def _parse(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


@dataclass(frozen=True)
class VerifyReport:
    """`break_line` is 1-based; `None` means the whole file verified."""

    records: int
    unchained_prefix: int
    last_sha256: str
    break_line: int | None = None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.break_line is None


def verify(path: Path) -> VerifyReport:
    """Check every link in the file and report the first break, if any."""
    prev = GENESIS
    expected_seq = 0
    chained = 0
    unchained = 0
    with path.open("rb") as f:
        for number, raw in enumerate(f, start=1):
            if not raw.endswith(b"\n"):
                return _broken(chained, unchained, prev, number, "the last line is incomplete")
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError:
                return _broken(chained, unchained, prev, number, "the line is not UTF-8")
            entry = _parse(line)
            if entry is None:
                return _broken(chained, unchained, prev, number, "the line is not a JSON object")
            if PREV_FIELD not in entry:
                if chained:
                    reason = "an unchained line after chaining began"
                    return _broken(chained, unchained, prev, number, reason)
                unchained += 1
                prev = line_hash(line)
                continue
            if entry[PREV_FIELD] != prev:
                reason = "it does not link to the previous line"
                return _broken(chained, unchained, prev, number, reason)
            if entry.get(SEQ_FIELD) != expected_seq:
                return _broken(chained, unchained, prev, number, f"expected seq {expected_seq}")
            chained += 1
            expected_seq += 1
            prev = line_hash(line)
    return VerifyReport(chained, unchained, prev)


def _broken(chained: int, unchained: int, prev: str, line: int, reason: str) -> VerifyReport:
    return VerifyReport(chained, unchained, prev, break_line=line, reason=reason)
