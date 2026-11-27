"""The audit log's hash chain (plan MR S5): each line links to the one before,
so edits, insertions, deletions and reordering are detected, a restarted
sink continues the chain, and damage at the end of the file fails closed."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from mcp_security_proxy.app.verify_audit import main as verify_main
from mcp_security_proxy.services.log import (
    GENESIS,
    AuditWriteError,
    DiscoveryRecord,
    JsonlAuditSink,
    verify_chain,
)
from mcp_security_proxy.services.log.chain import PREV_FIELD, SEQ_FIELD, line_hash, read_head


def _record(principal: str = "alice") -> DiscoveryRecord:
    return DiscoveryRecord(
        principal_id=principal,
        authenticated_by="test",
        policy_version="sha256:x",
        visible_tool_count=3,
    )


async def _log(path: Path, count: int) -> list[str]:
    sink = JsonlAuditSink.create(path)
    for i in range(count):
        await sink.write(_record(f"p{i}"))
    return path.read_text(encoding="utf-8").splitlines()


def _rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8", newline="\n")


async def test_each_line_links_to_the_previous_one(tmp_path: Path) -> None:
    lines = await _log(tmp_path / "audit.jsonl", 3)
    entries = [json.loads(line) for line in lines]
    assert [e[SEQ_FIELD] for e in entries] == [0, 1, 2]
    assert entries[0][PREV_FIELD] == GENESIS
    assert entries[1][PREV_FIELD] == line_hash(lines[0])
    assert entries[2][PREV_FIELD] == line_hash(lines[1])


async def test_an_untouched_log_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 5)
    report = verify_chain(path)
    assert report.ok and report.records == 5 and report.unchained_prefix == 0
    assert report.last_sha256 == line_hash(lines[-1])


def test_an_empty_log_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.touch()
    report = verify_chain(path)
    assert report.ok and report.records == 0 and report.last_sha256 == GENESIS


async def test_concurrent_writes_still_form_one_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink.create(path)
    await asyncio.gather(*(sink.write(_record(f"p{i}")) for i in range(50)))
    assert verify_chain(path).ok and verify_chain(path).records == 50


async def test_an_edited_record_breaks_the_next_link(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 4)
    lines[1] = lines[1].replace('"p1"', '"mallory"')
    _rewrite(path, lines)
    report = verify_chain(path)
    assert not report.ok and report.break_line == 3


async def test_a_deleted_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 4)
    _rewrite(path, lines[:1] + lines[2:])
    assert verify_chain(path).break_line == 2


async def test_swapped_records_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 4)
    lines[1], lines[2] = lines[2], lines[1]
    _rewrite(path, lines)
    assert verify_chain(path).break_line == 2


async def test_an_inserted_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 3)
    forged = json.loads(lines[1])
    forged["principal_id"] = "mallory"
    _rewrite(path, [lines[0], lines[1], json.dumps(forged), lines[2]])
    assert verify_chain(path).break_line == 3


async def test_a_relinked_forgery_still_breaks_the_seq(tmp_path: Path) -> None:
    """Recomputing `prev_sha256` for an inserted line still leaves seq wrong."""
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 2)
    forged = json.loads(lines[1])
    forged[PREV_FIELD] = line_hash(lines[1])
    _rewrite(path, [*lines, json.dumps(forged)])
    report = verify_chain(path)
    assert report.break_line == 3 and "seq" in (report.reason or "")


async def test_converting_line_endings_is_not_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 3)
    path.write_bytes("".join(line + "\r\n" for line in lines).encode("utf-8"))
    assert verify_chain(path).ok


async def test_truncating_the_tail_leaves_a_valid_shorter_chain(tmp_path: Path) -> None:
    """Documented limit: only an externally stored last hash detects this."""
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 4)
    full = verify_chain(path)
    _rewrite(path, lines[:2])
    cut = verify_chain(path)
    assert cut.ok and cut.records == 2 and cut.last_sha256 != full.last_sha256


async def test_a_restarted_sink_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    await _log(path, 2)
    second = JsonlAuditSink.create(path)
    await second.write(_record("after-restart"))
    report = verify_chain(path)
    assert report.ok and report.records == 3
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[-1])[SEQ_FIELD] == 2


async def test_a_pre_chain_log_is_kept_as_an_unchained_prefix(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    legacy = [_record("old1").model_dump_json(), _record("old2").model_dump_json()]
    _rewrite(path, legacy)
    sink = JsonlAuditSink.create(path)
    await sink.write(_record("new"))
    first_chained = json.loads(path.read_text(encoding="utf-8").splitlines()[2])
    assert first_chained[SEQ_FIELD] == 0 and first_chained[PREV_FIELD] == line_hash(legacy[1])
    report = verify_chain(path)
    assert report.ok and report.records == 1 and report.unchained_prefix == 2


async def test_an_unchained_line_after_chaining_began_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 2)
    _rewrite(path, [*lines, _record("sneaky").model_dump_json()])
    assert verify_chain(path).break_line == 3


def test_a_partial_last_line_stops_startup(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"principal_id": "alice"}\n{"principal_', encoding="utf-8")
    with pytest.raises(AuditWriteError, match="partial line"):
        JsonlAuditSink.create(path)
    assert verify_chain(path).break_line == 2


def test_a_last_line_that_is_not_json_stops_startup(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    with pytest.raises(AuditWriteError):
        JsonlAuditSink.create(path)


def test_the_head_is_found_past_a_long_last_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    long_line = json.dumps({SEQ_FIELD: 7, PREV_FIELD: GENESIS, "pad": "x" * 200_000})
    _rewrite(path, ['{"first": 1}', long_line])
    head = read_head(path)
    assert head.next_seq == 8 and head.prev_sha256 == line_hash(long_line)


async def test_writes_fail_closed_after_a_failed_write(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink.create(path)
    path.unlink()
    path.mkdir()
    with pytest.raises(AuditWriteError):
        await sink.write(_record())
    path.rmdir()
    with pytest.raises(AuditWriteError, match="unusable"):
        await sink.write(_record())


async def test_verify_command_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    lines = await _log(path, 3)
    assert verify_main([str(path)]) == 0
    assert line_hash(lines[-1]) in capsys.readouterr().out
    _rewrite(path, lines[1:])
    assert verify_main([str(path)]) == 1
    assert "line 1" in capsys.readouterr().out
    assert verify_main([str(tmp_path / "missing.jsonl")]) == 2
