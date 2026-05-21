# Architecture

The tool is a transparent MCP proxy. It sits between the agent and real MCP servers, intercepting every message in both directions without modifying the protocol.

---

## Proxy model

```
Agent (Cursor / Claude Desktop / Copilot)
              ↓  MCP protocol (stdio)
    ┌─────────────────────────────────────┐
    │          mcp-security-proxy         │
    │                                     │
    │  detection/                         │
    │    attacks/  ← per-attack detectors │
    │    anomaly/  ← sequence patterns    │
    │                                     │
    │  core/       ← call log, models     │
    └─────────────────────────────────────┘
              ↓  MCP protocol (stdio, subprocess)
      Real MCP Server
```

The proxy is simultaneously an MCP server (facing the agent) and an MCP client (facing the real server). The agent's MCP config points to the proxy command instead of the real server command.

---

## Module hierarchy

```
mcp_security_tester/
├── cli.py                        ← entry point (monitor / scan commands)
├── proxy/
│   └── server.py                 ← MCP bridge (runtime orchestrator)
├── detection/                    ← all detection logic
│   ├── attacks/
│   │   ├── __init__.py           ← build_registry(server_name)
│   │   ├── base.py               ← AttackDetector base class
│   │   ├── tool_poisoning/       ← manifest & output injection detection
│   │   ├── rug_pull/             ← manifest diff / silent redefinition
│   │   └── credential_leak/      ← API keys, tokens, private key headers
│   └── anomaly/
│       ├── detector.py           ← sequence, rapid-repeat, unapproved-tool checks
│       └── patterns.py           ← declarative SequencePattern rules
└── core/                         ← shared primitives (no internal deps)
    ├── models.py                 ← Finding, Report dataclasses
    ├── reporter.py               ← JSON serializer for Report
    ├── logger.py                 ← ToolCall dataclass + JSONL writer
    └── collector.py              ← save/load manifests for offline scanning
```

**Dependency direction is strictly downward:** `proxy → detection → core`. Adding a new attack only touches `detection/attacks/`.

---

## Adding a new attack

1. Create `detection/attacks/<attack_name>/` with `signals.py`, `detector.py`, `attack.py`
2. Implement `AttackDetector` from `detection/attacks/base.py` — override only the methods you need:
   - `scan_manifest(tools)` — called on every `list_tools`
   - `scan_output(tool_name, text)` — called on every tool response
   - `check_sequence(recent_calls)` — called after every `call_tool`
3. Add the new detector to the list in `detection/attacks/__init__.py`

Nothing else needs to change.

---

## Components

### `proxy/server.py` — core bridge

Runs two MCP sessions in the same asyncio event loop:
- **Downstream** (to agent): MCP server using `stdio_server()`, capturing the process's stdin/stdout
- **Upstream** (to real server): MCP client using `stdio_client()`, spawning the real server as a subprocess

Every `list_tools` and `call_tool` request is intercepted, delegated to the detection registry, then forwarded unmodified.

### `detection/attacks/` — per-attack detectors

Each subdirectory is a self-contained attack module. The registry (`build_registry`) instantiates one detector per attack and the proxy calls each detector's three methods on every intercept point.

**tool_poisoning** — scans every string field in the manifest for imperative verbs, secrecy directives, sensitive path references, hidden Unicode, and cross-tool references. At runtime, re-runs a subset of these detectors on every tool response.

**rug_pull** — on first `list_tools`, snapshots the full manifest (SHA-256 per tool). On every subsequent `list_tools`, diffs against the snapshot. Any change triggers a Finding before the updated manifest reaches the agent.

**credential_leak** — regex patterns applied to every tool response: GitHub tokens, OpenAI keys, AWS access keys, private key headers, and a generic `key=value` pattern.

### `detection/anomaly/` — behavioral pattern detection

Checks the recent call history against known suspicious sequences:
- Destructive sequence: `read_*` immediately followed by an outbound call (`send_*`, `*http*`, `create_message`)
- Rapid repetition: same tool called ≥4 times in 5 calls
- Unapproved tool: a tool that was never in the approved manifest gets called

Patterns live in `anomaly/patterns.py` as a declarative list of `SequencePattern` dataclasses — extend by appending, no logic changes needed.

### `core/logger.py` — structured call log

Every tool call is recorded as a `ToolCall` entry: timestamp, tool name, arguments, truncated response, duration (ms), and any findings from the output scan. Written to `mcp-security.jsonl` (newline-delimited JSON, appendable). Last 50 calls kept in memory for sequence analysis.

### `core/models.py` — shared data types

`Finding` carries: `attack_type`, `severity`, `tool_name`, `field`, `evidence`, `signal`, `reproduction_steps`. Every detector returns this same shape. `Report` wraps a list of findings with a target name and timestamp.

### `core/collector.py` — offline manifest utility

Connects to a server via stdio or SSE transport, fetches its tool list, and saves it to `corpus/manifests/`. Used by the `mcp-tester scan` command to run static analysis without a live proxy session.

---

## Data flow

```
Agent sends list_tools()
        ↓
proxy/server.py receives it
        ↓
each detector in registry → scan_manifest(tools_raw)
        ↓
anomaly_detector.set_approved_tools(...)
        ↓
findings → alert to stderr

Agent sends call_tool("read_file", {"path": "..."})
        ↓
proxy/server.py receives it, forwards upstream, awaits response
        ↓
each detector in registry → scan_output(name, response_text)
        ↓
core/logger.py records the full call + findings
        ↓
anomaly_detector.check(recent_calls) → sequence findings
        ↓
all findings → alert to stderr + log file
        ↓
response returned to agent (unmodified)
```

---

## Configuration

The user adds one entry to their MCP client config per server they want to monitor:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-tester",
      "args": ["monitor", "--name", "filesystem", "--server", "npx -y @modelcontextprotocol/server-filesystem ."]
    }
  }
}
```

The proxy starts when the agent connects, spawns the real server, and runs until the agent disconnects.

---

## Alert format

Alerts are written to stderr (so they don't interfere with the MCP protocol on stdout) and to the log file:

```json
{"level": "CRITICAL", "signal": "rug_pull_changed", "tool": "read_file", "detail": "description changed after approval", "timestamp": "..."}
{"level": "HIGH", "signal": "secrecy_directive", "tool": "fetch_issue", "detail": "do not inform found in tool_output", "timestamp": "..."}
{"level": "CRITICAL", "signal": "credential_leak_github_token", "tool": "get_secret", "detail": "Credential pattern 'github_token' found: ghp_...", "timestamp": "..."}
```
