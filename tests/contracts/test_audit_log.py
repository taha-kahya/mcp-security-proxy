"""Tests for audit record sanitization and the JSONL audit sink."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from mcp_security_proxy.services.log import (
    ArgumentDigest,
    AuditWriteError,
    DecisionRecord,
    DiscoveryRecord,
    JsonlAuditSink,
    MetaDigest,
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


def _decision(meta: MetaDigest | None = None) -> DecisionRecord:
    return DecisionRecord(
        principal_id="alice",
        authenticated_by="test",
        correlation_id="c1",
        requested_tool="read_record",
        tool_id="server_a/read_record",
        decision_id="d1",
        outcome="allow",
        rule_refs=(),
        reason="allowed",
        policy_version="sha256:x",
        arguments=ArgumentDigest.of({}),
        meta=meta,
    )


def test_meta_digest_masks_every_value_by_default() -> None:
    digest = MetaDigest.masked({"eval_id": "run-7", "token": SYNTHETIC_SECRET})

    assert digest.keys == ("eval_id", "token")
    assert digest.values == {}
    dumped = _decision(digest).model_dump_json()
    assert SYNTHETIC_SECRET not in dumped
    assert "run-7" not in dumped


def test_meta_digest_records_an_allowlisted_value_and_masks_its_neighbours() -> None:
    digest = MetaDigest.masked({"eval_id": "run-7", "token": SYNTHETIC_SECRET}, {"eval_id"})

    assert digest.values == {"eval_id": "run-7"}
    assert digest.keys == ("eval_id", "token")
    dumped = _decision(digest).model_dump_json()
    assert "run-7" in dumped
    assert SYNTHETIC_SECRET not in dumped


def test_meta_digest_records_only_scalar_allowlisted_values() -> None:
    meta = {"s": "x", "n": 1.5, "b": True, "none": None, "list": [1], "obj": {"k": "secret"}}
    digest = MetaDigest.masked(meta, set(meta))

    assert digest.values == {"s": "x", "n": 1.5, "b": True}
    assert "secret" not in _decision(digest).model_dump_json()


def test_meta_digest_ignores_allowlisted_keys_the_request_did_not_send() -> None:
    assert MetaDigest.masked({"a": 1}, {"missing"}).values == {}


def test_a_decision_without_meta_serializes_without_a_meta_field() -> None:
    assert "meta" not in json.loads(_decision().model_dump_json())
    assert json.loads(_decision(MetaDigest.masked({"a": 1})).model_dump_json())["meta"]["keys"] == [
        "a"
    ]
