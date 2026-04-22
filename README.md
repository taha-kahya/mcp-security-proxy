# MCP Security Proxy

A transparent security proxy that sits between your AI agent and MCP servers — watching every tool call, scanning every response, and alerting when something goes wrong.

---

## The problem

MCP servers can behave maliciously in ways that are invisible to the user:
- A server changes its tool definitions after you approved it (**rug pull**)
- A tool returns a response containing hidden instructions that hijack the agent (**prompt injection**)
- A passive tool description silently alters how the agent uses another server (**tool shadowing**)
- An agent starts calling tools it was never asked to call (**behavioral anomaly**)

None of these are detectable by reading the manifest once at install time. They require continuous runtime observation.

---

## How it works

```
Agent (Cursor / Claude Desktop / Copilot)
              ↓
    mcp-security-proxy          ← intercepts every message
              ↓
      Real MCP Server(s)
```

The agent thinks it's talking directly to the real server. Every tool call flows through the proxy, which:

1. **Snapshots the manifest** on connect — diffs on every re-fetch to detect rug pulls
2. **Scans every tool output** before the agent sees it — detects injection payloads and credential leakage
3. **Logs every tool call** with full context — tool name, arguments, response, timing
4. **Flags anomalous sequences** — agent calling tools it shouldn't given the conversation context

Alerts go to stderr in real time. The proxy never modifies or blocks responses — observe-only by default.

---

## Prerequisites

- Python 3.11+
- Node.js 18+ (needed to run MCP servers via `npx`)
- Claude Desktop or Cursor

---

## Setup

### 1. Clone and install

```bash
git clone <repo-url>
cd mcp-security-proxy
pip install -e ".[dev]"
```

### 2. Verify

```bash
mcp-tester --help
```

### 3. Find the full path to `mcp-tester`

```bash
which mcp-tester
# e.g. /opt/anaconda3/bin/mcp-tester
```

Claude Desktop does not inherit your shell PATH, so you must use the absolute path in the config.

### 4. Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/opt/anaconda3/bin/mcp-tester",
      "args": [
        "monitor",
        "--name", "filesystem",
        "--server", "npx -y @modelcontextprotocol/server-filesystem /path/to/your/directory",
        "--log", "/path/to/mcp-security.jsonl"
      ]
    }
  }
}
```

Replace the command path with your output from step 3.

### 5. Restart Claude Desktop

The proxy starts automatically when Claude connects to the server. You should see on stderr:

```
[mcp-security-proxy] Starting proxy for 'filesystem' → npx ...
[mcp-security-proxy] Logging calls to /path/to/mcp-security.jsonl
```

When a threat is detected, an alert line appears:

```json
{"alert": true, "level": "HIGH", "signal": "secrecy_directive", "tool": "read_file", "detail": "...", "timestamp": "..."}
```

---

## Reading the call log

Every tool call is written as a JSON line to the `--log` file:

```bash
cat /path/to/mcp-security.jsonl | python3 -m json.tool
```

If `flagged` is `true` in an entry, the `findings` array contains the full detail of what was detected.

---

## Offline static scan

Scan a saved manifest without a live proxy:

```bash
mcp-tester scan --manifest corpus/manifests/mcp-server-filesystem.json
```

Save a full JSON report:

```bash
mcp-tester scan --manifest corpus/manifests/mcp-server-filesystem.json --output report.json
```

Exit code is `2` for CRITICAL findings, `1` for HIGH, `0` otherwise — useful in CI.

---

## Attack coverage

| Attack | How it's caught |
|--------|----------------|
| Tool poisoning | Static scan of manifest at connect time |
| Rug pull | Manifest diff on every re-fetch |
| Indirect prompt injection | Output scanner on every tool response |
| Tool shadowing | Cross-tool reference detection in manifest |
| Behavioral anomaly | Suspicious tool call sequence detection |

See [docs/attacks.md](docs/attacks.md) for payloads and detection logic.

## Known limitations

- **Tool arguments are not scanned.** An injected instruction that passes a sensitive path as an argument (e.g. `read_file("/etc/passwd")`) is logged but not flagged.
- **Credential detection is partial.** GitHub, OpenAI, AWS, and private keys are covered. Azure, Google Cloud, and Slack tokens are not yet matched.
- **Tool shadowing is connect-time only.** Shadowing introduced via a runtime tool output is caught as generic prompt injection, not classified as shadowing.
- **Sequence patterns are limited.** Only 4 rules are defined. Coverage improves as patterns are tuned against real captured sessions.

---

## Development

```bash
pytest                 # run all tests
pytest tests/unit/     # unit tests only
```

New detectors go in `static_analyzer/detectors.py`, wired into `static_analyzer/analyzer.py`. New anomaly sequence rules go in `anomaly_detector/patterns.py` as `SequencePattern` dataclasses.

---

## Project structure

```
mcp_security_tester/
├── proxy/                  # core proxy — bridges agent ↔ real server
│   ├── server.py           # MCP server + client bridge
│   ├── manifest_watcher.py # snapshot manifest, diff on re-fetch
│   └── output_scanner.py   # scan tool responses before agent sees them
├── call_logger/            # structured log of every tool call
├── anomaly_detector/       # flag suspicious tool call sequences
├── static_analyzer/        # poisoning signal detectors (used at runtime)
└── reports/                # Finding + Report dataclasses, JSON output
```

See [docs/architecture.md](docs/architecture.md) for detail.

---

## Team

Ahmet Taha Kahya, Yunus Emre Ulusoy, Emirhan Oguz, Semih Dogan, Burak Ala.
Supervisor: Cemal Yilmaz — Sabanci University 2026.
