"""Tests for audit record sanitization and the JSONL audit sink."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from mcp_security_proxy.services.log import (
    ArgumentDigest,
    AuditWriteError,
    DiscoveryRecord,
    JsonlAuditSink,
)

SYNTHETIC_SECRET = "sk-test-0000-synthetic-secret"


def _discovery(principal_id: str = "alice") -> DiscoveryRecord:
    return DiscoveryRecord(
        principal_id=principal_id,
        authenticated_by="test",
        policy_version="sha256:x",
        visible_tool_count=3,
    )


def test_argument_digest_keeps_key_names_but_never_values() -> None:
    digest = ArgumentDigest.of({"recipient": "bob", "message": SYNTHETIC_SECRET})

    assert digest.keys == ("message", "recipient")
    assert SYNTHETIC_SECRET not in digest.model_dump_json()


def test_argument_digest_is_independent_of_key_order_but_not_of_values() -> None:
    first = ArgumentDigest.of({"a": 1, "b": 2})
    assert first == ArgumentDigest.of({"b": 2, "a": 1})
    assert first != ArgumentDigest.of({"a": 1, "b": 3})


async def test_sink_appends_one_json_object_per_record(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "audit.jsonl"
    sink = JsonlAuditSink.create(path)

    await sink.write(_discovery("alice"))
    await sink.write(_discovery("bob"))

    entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [e["principal_id"] for e in entries] == ["alice", "bob"]
    assert all(e["kind"] == "discovery" for e in entries)


async def test_concurrent_writes_never_interleave(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink.create(path)

    await asyncio.gather(*(sink.write(_discovery(f"p{i}")) for i in range(50)))

    lines = path.read_text(encoding="utf-8").splitlines()
    assert sorted(json.loads(line)["principal_id"] for line in lines) == sorted(
        f"p{i}" for i in range(50)
    )


def test_create_fails_fast_when_the_path_is_not_writable(tmp_path: Path) -> None:
    with pytest.raises(AuditWriteError):
        JsonlAuditSink.create(tmp_path)  # a directory, not a file


async def test_write_failure_raises_instead_of_being_swallowed(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink.create(path)
    path.unlink()
    path.mkdir()  # the file is replaced by something that cannot be appended to

    with pytest.raises(AuditWriteError):
        await sink.write(_discovery())
