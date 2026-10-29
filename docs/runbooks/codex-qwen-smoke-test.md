# Manual smoke test: Codex CLI + local Qwen-3.5 9B against the proxy

Status: manual, exploratory verification only. **Not part of CI** — see
[0004](../decisions/0004-scripted-harness-over-llm-agent.md) and
[0005](../decisions/0005-codex-qwen-smoke-test-isolated-mr.md) for why this is
kept separate from the automated acceptance tests. Nothing here is asserted
by pytest; "done" means a human followed these steps and read the output.

## What this proves (and what it doesn't)

This exercises the full real-world chain:

```
Qwen-3.5 9B (local, via Ollama)
   ↓ tool-use decisions
Codex CLI (MCP host)
   ↓ MCP client protocol
Proxy (Config A: stdio)
   ↓
Mock server A / Mock server B
```

It demonstrates that a real MCP host backed by a real local model can
discover the proxy's disambiguated tool list and successfully drive a
read/write/send call end-to-end. It does **not** replace the automated
integration suite (`tests/integration/test_proxy_e2e.py`) — an LLM's tool-call
choices aren't reproducible enough to assert exact routing/error/cancellation
behavior, which is why that suite uses a scripted harness instead (0004).

## Prerequisites

- [Ollama](https://ollama.com) installed and running.
- [Codex CLI](https://github.com/openai/codex) installed (`codex --version`).
- This repo set up per the root `README.md` (`uv sync --all-extras --dev`).

## 1. Serve Qwen-3.5 9B locally via Ollama

```sh
ollama pull qwen3.5:9b
ollama serve   # usually already running as a background service; harmless if so
```

Ollama exposes an OpenAI-compatible API at `http://localhost:11434/v1`,
including a `/v1/responses` endpoint — which matters because Codex CLI's
custom model providers only support `wire_api = "responses"` (confirmed
below), so Ollama's `/v1/responses` support is exactly what's needed here.

Sanity-check it's reachable:

```sh
curl -s http://localhost:11434/v1/models | grep -i qwen3.5
```

## 2. Point Codex CLI at the local Qwen-3.5 9B model

Codex CLI supports custom, non-OpenAI model providers via
`~/.codex/config.toml`. Add:

```toml
[model_providers.ollama-qwen]
name = "Ollama (local Qwen-3.5 9B)"
base_url = "http://localhost:11434/v1"
env_key = "OLLAMA_API_KEY"
wire_api = "responses"

model = "qwen3.5:9b"
model_provider = "ollama-qwen"
```

`env_key` names an environment variable Codex reads for the API key. Ollama
ignores its value but Codex still requires it to be set to something
non-empty:

```sh
export OLLAMA_API_KEY=ollama
```

## 3. Point Codex CLI at the proxy as an MCP server

Start the proxy first (Config A — stdio), from the repo root:

```sh
uv run python -m mcp_security_proxy.app.main --config config/config.stdio.yaml
```

Leave that running in one terminal. In another terminal, either run:

```sh
codex mcp add security-proxy -- uv run python -m mcp_security_proxy.app.main --config /absolute/path/to/mcp-security-proxy/config/config.stdio.yaml
```

or add it to `~/.codex/config.toml` directly:

```toml
[mcp_servers.security_proxy]
command = "uv"
args = [
  "run", "python", "-m", "mcp_security_proxy.app.main",
  "--config", "/absolute/path/to/mcp-security-proxy/config/config.stdio.yaml",
]
cwd = "/absolute/path/to/mcp-security-proxy"
```

Note: Codex CLI's MCP client supports Streamable HTTP servers too (a plain
`url = "..."` entry instead of `command`/`args`), so Config B works here as
well if you'd rather smoke-test that configuration — Config A is the default
recommendation here only because it needs no separate port/process
bookkeeping for this manual step, not because of any known limitation in
Codex's HTTP support. Config B requires every request to carry
`Authorization: Bearer <token>` (the reference config's development token is
`dev-token-change-me`), so configure Codex's bearer-token option for that
server if you use it.

If you used `codex mcp add`, Codex manages spawning the proxy itself (don't
also run it manually in that case — pick one).

## 4. Run the smoke test

Start Codex CLI:

```sh
codex
```

In the Codex session:

1. Ask it to list available tools, or just ask a question that requires one,
   e.g.: *"Using the security-proxy MCP server, write the value 'hello' under
   the key 'greeting' on server_a, then read it back."*
2. Confirm the tool list Codex sees includes the disambiguated names —
   `server_a__write_record`, `server_a__read_record`,
   `server_b__send_message`, etc. With the reference policy
   (`config/policies/default.yaml`) that is seven tools: all four on
   `server_a`, and every `server_b` tool except the hidden `slow_write`.
3. Confirm Codex successfully calls `server_a__write_record` and then
   `server_a__read_record`, and that the model reports back the correct
   value it just wrote.
4. Optionally, check the mock server's audit log (path set in
   `config/config.stdio.yaml`) to independently confirm the call actually
   reached `server_a` and not `server_b`, and the proxy's own
   `proxy_audit.jsonl` to see the `decision` and `outcome` records.
5. Ask Codex to send a message via `server_b`. The call to
   `server_b__send_message` should come back as a tool error saying it
   requires approval, and `server_b`'s audit log should stay empty.

## Done when

- Codex CLI, driven by the locally-served Qwen-3.5 9B model, discovers the
  full disambiguated tool list from both mock servers through the proxy.
- The visible tool list matches the reference policy.
- At least one read, one write, and one send call (`server_a__send_message`)
  complete successfully end-to-end with a real model making the tool-call
  decisions, and `server_b__send_message` is blocked.

If something fails, note whether the failure is in Codex/Ollama setup (not a
proxy issue) versus the proxy itself misbehaving — only the latter is
relevant to the proxy's correctness.
