# mcp-security-proxy

A proxy tool that stands between a client and MCP servers, providing transparency and security.

See [`docs/architecture.md`](docs/architecture.md) for the overall design and the
V1-V5 phased build plan. See [`docs/decisions/`](docs/decisions/README.md) for why
specific implementation choices were made,
[`docs/design/tool-identity-and-routing.md`](docs/design/tool-identity-and-routing.md)
for how tool routing works, and
[`docs/design/request-lifecycle-and-control.md`](docs/design/request-lifecycle-and-control.md)
for how calls are authenticated, authorized, and audited.

Current scope (V1 + V2): `Agent <-> Proxy <-> Two mock MCP servers`, with
correct protocol handling, discovery, routing, and correlation over stdio and
Streamable HTTP (V1), plus control (V2):

- **Identity:** a principal fixed in config for stdio; static bearer tokens
  (stored as SHA-256 digests) for Streamable HTTP.
- **Policy:** a per-principal allowlist of server-scoped tools. Anything not
  listed is hidden from discovery and rejected on call, exactly like a tool
  that doesn't exist.
- **Guard:** one decision per call (`allow`, `block`, or `require_approval`,
  which stays blocked until Approval exists in V5).
- **Log:** every decision and upstream outcome is appended to a JSONL audit
  log with arguments masked. If a decision can't be recorded, the call is not
  dispatched.

There is no attack detection yet; that starts with V3/V4.

## Setup

Requires [`uv`](https://docs.astral.sh/uv/).

```sh
uv sync --locked --all-extras --dev
```

## Running the checks

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy src fixtures/mock_servers tests/harness
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
running the command above. The caller is the configured
`identity.stdio_principal`.

**Config B — Streamable HTTP:**

```sh
uv run python -m mcp_security_proxy.app.main --config config/config.http.yaml
```

The proxy spawns both mock servers (also over Streamable HTTP) and listens
itself on `http://127.0.0.1:9000/mcp` (per `config/config.http.yaml`).
Connect with any Streamable HTTP MCP client at that URL, sending
`Authorization: Bearer dev-token-change-me` (the reference config's
development token). Requests without a valid token get HTTP 401. For any real
use, replace it with a random token of at least 256 bits and put its digest in
`identity.bearer_tokens`. This prints a new token, then its digest:

```sh
python3 -c 'import hashlib, secrets; t = secrets.token_urlsafe(32); print(t); print(hashlib.sha256(t.encode()).hexdigest())'
```

The listener speaks plain HTTP, so keep `agent_host` on loopback
(`127.0.0.1`) or put a TLS-terminating reverse proxy in front; the proxy logs
a warning at startup otherwise. See
[`docs/decisions/0014`](docs/decisions/0014-http-listener-exposure-and-token-strength.md).

In both configs, tools are exposed to the client under disambiguated names
(`server_a__read_record`, `server_b__send_message`, etc.) — see
[`docs/design/tool-identity-and-routing.md`](docs/design/tool-identity-and-routing.md)
for why.

Both reference configs use the policy in
[`config/policies/default.yaml`](config/policies/default.yaml): all of
`server_a`, most of `server_b`, `server_b__send_message` visible but
requiring approval, and `server_b__slow_write` hidden. The proxy writes its
audit log to `proxy_audit.jsonl` in the working directory.

## Changing policy

Edit the policy file (or point `policy_path` at another one) and restart the
proxy. Each principal lists rules with a `tool` pattern (`server_id/tool_name`
or `server_id/*`) and an `effect` (`allow` or `require_approval`). An exact rule
overrides a wildcard for the same server. The proxy refuses to start if the
file is invalid or a rule matches no discovered tool. It logs a warning, but
still starts, when a policy principal has no configured identity (a likely
typo: those rules apply to nobody) or a configured principal has no policy
entry (it is denied every tool). See
[ADR 0010](docs/decisions/0010-policy-model-and-default-deny.md) for the
full model.

## Running a mock server standalone

Useful for poking at a server directly without the proxy in front of it:

```sh
uv run python -m fixtures.mock_servers.server_a --audit-log /tmp/a.jsonl
uv run python -m fixtures.mock_servers.server_a --transport streamable-http --port 8001 --audit-log /tmp/a.jsonl
```

Every `write_record`/`send_message`/`slow_write` call appends an entry to the
given audit log — the independent ground truth used throughout the test
suite to check which server actually handled a call, rather than trusting a
client's or the proxy's own claims.

## Adding a new mock tool

Mock tools live in `fixtures/mock_servers/common/tools.py` and are shared by both
`server_a` and `server_b` via `register_mock_tools`. To add one:

1. Add a new `@server.tool()`-decorated function inside `register_mock_tools`.
   Keep it harmless (no real filesystem/network access) — these servers exist
   to exercise proxy behavior, not to do real work.
2. If the tool has a side effect worth verifying, call
   `audit_log.record(server_id, "<tool_name>", {...})` so tests can assert on
   it independently of the proxy's response.
3. Update the tool-count/name assertions in
   `tests/contracts/test_mock_servers.py` (`test_discovery_lists_expected_tools`)
   and, if relevant, the discovery tests in `tests/integration/`. The test
   harness allows every tool by default. In manual runs, the reference
   policy's `server_a/*` rule covers the new tool automatically; on
   `server_b` it stays hidden until you add a rule for it to
   `config/policies/default.yaml`.
4. Run `uv run pytest` — both servers and both transports are exercised by
   the existing parametrized tests automatically.

## Repository layout

```text
src/mcp_security_proxy/
  app/                    # config, startup wiring, transport/identity pairing
  core/
    proxy/                # orchestrator, SDK server adapter, routing/transport/codec
    identity/             # principal resolution and bearer-token verification
    guard/                # authorization decisions
  services/
    policy/               # policy loading, validation, versioning, matching
    log/                  # audit records, argument masking, JSONL sink
  sdk/                    # contract types shared by core, services, and later defenses
fixtures/
  mock_servers/            # two harmless mock MCP servers, reused by tests and manual runs
config/                   # reference configs for Config A (stdio) and Config B (HTTP)
  policies/               # reference policy files
tests/
  contracts/               # fast, no-subprocess unit tests + mock server contract tests
  integration/             # full proxy end-to-end tests, parametrized over both configs
  harness/                 # the scripted, deterministic MCP client used to drive integration tests
docs/
  architecture.md          # the overall design and phased build plan
  decisions/                # ADRs for implementation choices, per phase
  design/                   # permanent reference docs promoted from settled ADRs
  runbooks/                 # manual verification procedures (e.g. the Codex+Qwen smoke test)
```
