# Mock MCP servers

Two independent, deliberately harmless MCP servers (`server_a`, `server_b`)
used to exercise the proxy during development, testing, and manual runs.
They are not part of the proxy's product code.

They live outside `tests/` because they're more than test fixtures in the
pytest sense: `mcp_security_proxy.app.wiring` spawns them as real
subprocesses at runtime (per `config/config.stdio.yaml` and
`config/config.http.yaml`), and the manual Codex+Qwen smoke-test runbook
(`docs/runbooks/codex-qwen-smoke-test.md`) invokes them directly, outside of
pytest entirely. `fixtures/` groups this kind of "supporting, not-the-real-
product" runnable code so it doesn't read as a second core component of the
repo.

Both servers expose the identical tool set — `read_record`, `write_record`,
`send_message`, `slow_write` — and deliberately share the exact same bare
tool name (`send_message`) on both servers, to exercise the proxy's
server-scoped identity disambiguation (see
`docs/design/tool-identity-and-routing.md`). Every `write_record`/
`send_message`/`slow_write` call is appended to an append-only JSONL audit
log (`common/audit_log.py`) — the independent ground truth tests check
against, instead of trusting the proxy's or a client's own claims about
where a call landed.

Run one standalone:

```sh
uv run python -m fixtures.mock_servers.server_a --audit-log /tmp/a.jsonl
uv run python -m fixtures.mock_servers.server_a --transport streamable-http --port 8001 --audit-log /tmp/a.jsonl
```

See the root `README.md` for how to add a new tool here.
