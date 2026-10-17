# mcp-security-proxy

A proxy tool that stands between a client and MCP servers, providing transparency and security.

See [`docs/architecture.md`](docs/architecture.md) for the overall design and the
V1-V5 phased build plan. See [`docs/decisions/`](docs/decisions/README.md) for why
specific V1 implementation choices were made, and
[`docs/design/tool-identity-and-routing.md`](docs/design/tool-identity-and-routing.md)
for how tool routing works.

V1 scope: `Agent <-> Proxy <-> Two mock MCP servers`. There is no attack
detection yet — V1 is just correct protocol handling, discovery, routing, and
correlation across two configurations, stdio and Streamable HTTP.

## Setup

Requires [`uv`](https://docs.astral.sh/uv/).

```sh
uv sync --all-extras --dev
```

## Running the checks

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy src mock_servers tests/harness
uv run pytest
```

## Running the proxy manually

Two independent, self-contained configurations are supported. Each one runs
the proxy, server_a, and server_b entirely over one transport.

**Config A — stdio:**

```sh
uv run python -m mcp_security_proxy.app.main --config config/config.stdio.yaml
```

The proxy spawns both mock servers as subprocesses and speaks MCP over its
own stdin/stdout, so any stdio-capable MCP client/host can connect to it by
running the command above.

**Config B — Streamable HTTP:**

```sh
uv run python -m mcp_security_proxy.app.main --config config/config.http.yaml
```

The proxy spawns both mock servers (also over Streamable HTTP) and listens
itself on `http://127.0.0.1:9000/mcp` (per `config/config.http.yaml`).
Connect with any Streamable HTTP MCP client at that URL.

In both configs, tools are exposed to the client under disambiguated names
(`server_a__read_record`, `server_b__send_message`, etc.) — see
[`docs/design/tool-identity-and-routing.md`](docs/design/tool-identity-and-routing.md)
for why.

## Running a mock server standalone

Useful for poking at a server directly without the proxy in front of it:

```sh
uv run python -m mock_servers.server_a --audit-log /tmp/a.jsonl
uv run python -m mock_servers.server_a --transport streamable-http --port 8001 --audit-log /tmp/a.jsonl
```

Every `write_record`/`send_message`/`slow_write` call appends an entry to the
given audit log — the independent ground truth used throughout the test
suite to check which server actually handled a call, rather than trusting a
client's or the proxy's own claims.

## Adding a new mock tool

Mock tools live in `mock_servers/common/tools.py` and are shared by both
`server_a` and `server_b` via `register_mock_tools`. To add one:

1. Add a new `@server.tool()`-decorated function inside `register_mock_tools`.
   Keep it harmless (no real filesystem/network access) — these servers exist
   to exercise proxy behavior, not to do real work.
2. If the tool has a side effect worth verifying, call
   `audit_log.record(server_id, "<tool_name>", {...})` so tests can assert on
   it independently of the proxy's response.
3. Update the tool-count/name assertions in
   `tests/contracts/test_mock_servers.py` (`test_discovery_lists_expected_tools`)
   and, if relevant, `tests/integration/test_proxy_e2e.py`'s discovery test.
4. Run `uv run pytest` — both servers and both transports are exercised by
   the existing parametrized tests automatically.

## Repository layout

```text
src/mcp_security_proxy/   # the proxy itself (app wiring, core/proxy routing+transport+codec)
mock_servers/             # two harmless mock MCP servers, reused by tests and manual runs
config/                   # reference configs for Config A (stdio) and Config B (HTTP)
tests/
  contracts/               # fast, no-subprocess unit tests + mock server contract tests
  integration/             # full proxy end-to-end tests, parametrized over both configs
  harness/                 # the scripted, deterministic MCP client used to drive integration tests
docs/
  architecture.md          # the overall design and phased build plan
  decisions/                # ADRs for V1 implementation choices
  design/                   # permanent reference docs promoted from settled ADRs
  runbooks/                 # manual verification procedures (e.g. the Codex+Qwen smoke test)
```
