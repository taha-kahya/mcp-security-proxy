# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A transparent MCP security proxy that sits between an AI agent (Cursor, Claude Desktop, Copilot) and real MCP servers. It intercepts every tool call and response, scanning for rug pulls, prompt injection, credential leakage, and behavioral anomalies in real time.

Team: Ahmet Taha Kahya, Yunus Emre Ulusoy, Emirhan Oguz, Semih Dogan, Burak Ala. Supervisor: Cemal Yilmaz — Sabanci University 2026.

## Commands

```bash
pip install -e ".[dev]"          # install with dev deps
pytest                           # run all tests
pytest tests/unit/               # unit tests only

# Start the proxy (point your MCP client at this instead of the real server)
mcp-tester monitor --name filesystem --server "npx -y @modelcontextprotocol/server-filesystem ."

# Offline static scan of a saved manifest
mcp-tester scan --manifest corpus/manifests/mcp-server-filesystem.json
```

## Architecture

The proxy runs two MCP sessions in the same asyncio event loop:
- **Downstream** (to agent): `stdio_server()` — uses the proxy process's own stdin/stdout
- **Upstream** (to real server): `stdio_client()` — spawns the real server as a subprocess

Every `list_tools` and `call_tool` is intercepted, scanned, logged, then forwarded unmodified. Alerts go to stderr (never interfere with MCP protocol on stdout).

## Module layout

```
proxy/              → server.py — MCP bridge, thin orchestrator
detection/
  attacks/          → base.py + build_registry(); one subfolder per attack type
    tool_poisoning/ → signals.py, detectors.py, analyzer.py, attack.py
    rug_pull/       → watcher.py (SHA-256 manifest diff), attack.py
    credential_leak/→ patterns.py (regexes), attack.py
  anomaly/          → patterns.py (declarative SequencePattern rules), detector.py
core/               → shared primitives, no internal deps
  models.py         → Finding + Report dataclasses
  reporter.py       → JSON serializer
  logger.py         → ToolCall dataclass + JSONL writer
  collector.py      → stdio/SSE client, save/load corpus
```

## Key design decisions

**Observe-only by default.** The proxy never blocks or modifies responses — it only alerts. This means it can't break legitimate tools.

**stderr for alerts, stdout for MCP protocol.** Alerts are JSON lines to stderr. Never write alerts to stdout — that's the MCP wire protocol.

**Static analyzer runs twice.** At connect time on the manifest, and at runtime on every tool output via `output_scanner.py`. The same detectors serve both purposes.

**Rug pull detection uses SHA-256 per tool.** `manifest_watcher.py` hashes each tool's full canonical JSON at first connect and diffs on re-fetch. Any change triggers a Finding before the updated manifest reaches the agent.

**Anomaly patterns are declarative.** `anomaly_detector/patterns.py` contains a list of `SequencePattern` dataclasses with glob-style tool name matching. Add new patterns there without touching detector logic.

## Finding severity

- CRITICAL: credential leak, unapproved tool called, rug pull adds sensitive paths, read→create_message sequence
- HIGH: secrecy directive in output, manifest description changed, suspicious exfiltration sequence
- MEDIUM: imperative verb signal, rapid tool repeat, tool removed from manifest
- LOW: unusual schema patterns

## What this tool does NOT do

- Block tool calls (observe-only)
- Attack servers you do not own
- Replace runtime security at the infrastructure level (containers, network isolation)
