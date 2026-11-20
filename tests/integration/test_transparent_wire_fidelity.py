"""Wire-level fidelity of transparent mode (0023).

The proxy runs as a real process in front of a raw JSON-RPC upstream whose
tool definitions are written as JSON text. The tests read the proxy's raw
response lines and compare ordered key/value pairs, so a reordered key or a
dropped field fails even when the parsed content is equal.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from tests.harness.client import PROXY_MODULE_ARGS, REPO_ROOT, build_proxy_config
from tests.integration.raw_upstream_script import TOOLS_JSON

SCRIPT = Path(__file__).with_name("raw_upstream_script.py")
Pairs = list[tuple[str, Any]]


def _ordered(text: str) -> Any:
    """Parse JSON keeping every object as an ordered list of pairs."""
    return json.loads(text, object_pairs_hook=lambda pairs: ("obj", list(pairs)))


def _exchange(tmp_path: Path, requests: list[dict[str, Any]], **options: Any) -> dict[int, str]:
    """Run the proxy over stdio, send the requests, and return raw response lines by id.
    `upstream_args` are extra arguments for the raw upstream script. Messages
    without an id (notifications) are appended to `notifications`, when given,
    and reading continues until `await_notifications` of them have arrived."""
    notifications: list[dict[str, Any]] | None = options.pop("notifications", None)
    await_notifications: int = options.pop("await_notifications", 0)
    upstream_args: list[str] = options.pop("upstream_args", [])
    config = build_proxy_config(
        [{"id": "raw", "command": sys.executable, "args": [str(SCRIPT), *upstream_args]}],
        "stdio",
        tmp_path,
        **options,
    )
    config["transparent"] = True
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "1"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    stdin = "".join(json.dumps(m) + "\n" for m in [init, initialized, *requests])
    expected_ids = {1, *(r["id"] for r in requests)}

    process = subprocess.Popen(
        [sys.executable, *PROXY_MODULE_ARGS, str(config_path)],
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(stdin)
    process.stdin.flush()
    lines: dict[int, str] = {}
    try:
        while expected_ids - lines.keys() or len(notifications or []) < await_notifications:
            line = process.stdout.readline()
            assert line, "proxy closed stdout before answering every request"
            message = json.loads(line)
            if "id" in message:
                lines[message["id"]] = line.strip()
            elif notifications is not None:
                notifications.append(message)
    finally:
        process.kill()
        process.wait()
    return lines


def _upstream_tools() -> list[Any]:
    return list(_ordered(TOOLS_JSON))


def _listed_tools(tmp_path: Path, **options: Any) -> tuple[str, list[Any]]:
    lines = _exchange(tmp_path, [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}], **options)
    result = dict(_ordered(lines[2])[1])["result"]
    return lines[2], list(dict(result[1])["tools"])


def _keys(obj: Any) -> list[str]:
    return [k for k, _ in obj[1]]


def test_tool_definitions_keep_content_and_key_order_at_every_level(tmp_path: Path) -> None:
    _, listed = _listed_tools(tmp_path)
    assert listed == _upstream_tools()


def test_top_level_tool_keys_keep_their_order(tmp_path: Path) -> None:
    _, listed = _listed_tools(tmp_path)
    assert _keys(listed[0]) == [
        "name",
        "description",
        "inputSchema",
        "annotations",
        "vendorField",
        "_meta",
    ]
    assert _keys(listed[1]) == ["name", "description", "inputSchema"]


def test_input_schema_keeps_key_order_with_nested_objects(tmp_path: Path) -> None:
    _, listed = _listed_tools(tmp_path)
    schema = dict(listed[0][1])["inputSchema"]
    assert _keys(schema) == ["type", "properties", "required", "additionalProperties"]
    properties = dict(schema[1])["properties"]
    assert _keys(properties) == ["query", "options"]
    options = dict(properties[1])["options"]
    assert _keys(options) == ["type", "properties", "additionalProperties"]
    assert _keys(dict(options[1])["properties"]) == ["limit", "cursor"]
    # An empty-schema tool keeps its own, different order.
    assert _keys(dict(listed[1][1])["inputSchema"]) == [
        "type",
        "additionalProperties",
        "required",
        "properties",
    ]


def test_fields_the_spec_model_does_not_declare_are_kept(tmp_path: Path) -> None:
    raw_line, listed = _listed_tools(tmp_path)
    first = dict(listed[0][1])
    assert first["vendorField"] == ("obj", [("z", 1), ("a", 2)])
    assert first["_meta"] == ("obj", [("b", 1), ("a", 2)])
    assert '"vendorField":{"z":1,"a":2}' in raw_line.replace(" ", "")


def test_tools_stay_in_the_upstream_order(tmp_path: Path) -> None:
    _, listed = _listed_tools(tmp_path)
    assert [dict(t[1])["name"] for t in listed] == ["zeta", "alpha"]


def test_policy_filtering_still_applies_to_the_verbatim_list(tmp_path: Path) -> None:
    policy = {
        "schema_version": 1,
        "principals": {"test-agent": [{"tool": "raw/alpha", "effect": "allow"}]},
    }
    _, listed = _listed_tools(tmp_path, policy=policy)
    assert listed == [_upstream_tools()[1]]


def test_tools_call_works_beside_the_verbatim_list(tmp_path: Path) -> None:
    lines = _exchange(
        tmp_path,
        [
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "alpha", "arguments": {}},
            },
        ],
    )
    response = json.loads(lines[3])
    assert "error" not in response
    assert response["result"]["content"][0]["text"] == "alpha"


def test_every_page_of_the_upstream_list_is_sent_verbatim(tmp_path: Path) -> None:
    _, listed = _listed_tools(tmp_path, upstream_args=["--paginate"])
    assert listed == _upstream_tools()


def test_the_agent_gets_the_definitions_from_the_one_startup_fetch(tmp_path: Path) -> None:
    """The upstream answers any later `tools/list` differently. A second fetch
    would put its text in front of the agent, not the text that was inspected."""
    _, listed = _listed_tools(tmp_path, upstream_args=["--drift"])
    assert listed == _upstream_tools()
    assert "DRIFTED" not in json.dumps(listed)


def test_initialize_passes_every_upstream_identity_field_through(tmp_path: Path) -> None:
    lines = _exchange(tmp_path, [], upstream_args=["--identity"])
    result = json.loads(lines[1])["result"]
    assert result["serverInfo"] == {
        "name": "Raw",
        "version": "1",
        "title": "Raw Server",
        "description": "d",
        "websiteUrl": "https://example.com/raw",
        "icons": [{"src": "https://example.com/i.png", "mimeType": "image/png"}],
    }
    assert result["instructions"] == "Use the raw tools."


def test_initialize_without_extra_identity_fields_adds_none(tmp_path: Path) -> None:
    result = json.loads(_exchange(tmp_path, [])[1])["result"]
    assert result["serverInfo"] == {"name": "Raw", "version": "1"}
    assert "instructions" not in result


def test_upstream_progress_reaches_the_agent_under_its_own_token(tmp_path: Path) -> None:
    notifications: list[dict[str, Any]] = []
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "alpha", "arguments": {}, "_meta": {"progressToken": "agent-token"}},
    }
    lines = _exchange(
        tmp_path,
        [call],
        upstream_args=["--progress"],
        notifications=notifications,
        await_notifications=2,
    )

    progress = [n["params"] for n in notifications if n["method"] == "notifications/progress"]
    assert progress == [
        {"progressToken": "agent-token", "progress": 1, "total": 2, "message": "step 1"},
        {"progressToken": "agent-token", "progress": 2, "total": 2, "message": "step 2"},
    ]
    assert "error" not in json.loads(lines[2])


def test_no_progress_is_sent_to_an_agent_that_did_not_ask_for_it(tmp_path: Path) -> None:
    notifications: list[dict[str, Any]] = []
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "alpha", "arguments": {}},
    }
    _exchange(tmp_path, [call], upstream_args=["--progress"], notifications=notifications)
    assert not [n for n in notifications if n["method"] == "notifications/progress"]
