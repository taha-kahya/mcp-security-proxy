# 0008 — Streamable HTTP session/resumability scope and multi-process port allocation

Status: Accepted

## Context

MR5 extends the proxy to Config B (Streamable HTTP end-to-end): the agent's
connection to the proxy, and the proxy's connections to both mock servers,
all run over Streamable HTTP instead of stdio. This introduces concerns that
don't exist for stdio: per-connection session identity, SSE vs single-JSON
response shapes, an optional resumption mechanism, and three independent
listeners (the proxy's own, plus each mock server's) needing non-conflicting
ports when run simultaneously.

## Decision

**Session resumption is out of scope for V1.** Streamable HTTP supports
resuming a dropped connection via a `Last-Event-ID`-style mechanism. This is
not implemented. Nothing in the V1 acceptance text
(`docs/architecture.md`'s V1 section) requires it, and building it now would
be infrastructure ahead of an actual requirement. A dropped HTTP connection in
V1 simply fails the in-flight call, the same observable behavior as any other
protocol error — it does not try to resume.

**Port allocation.** `UpstreamServerConfig` carries explicit `host`/`port`/`url`
fields per server (validated as required when `transport: streamable-http`,
see `app/config.py`), and `ProxyConfig` carries its own `agent_host`/
`agent_port` for the proxy's own listener. Reference configs
(`config/config.http.yaml`) use fixed ports (9000 for the proxy, 8001/8002 for
the mock servers, matching 0006's manual-run defaults) for readability.
**Tests never reuse these fixed ports**: `tests/harness/client.py` allocates
an OS-assigned ephemeral port for every listener it starts (the proxy's own
and each mock server's), reusing the same ephemeral-port pattern established
for the mock servers' own contract tests in 0006, now centralized in
`core/proxy/transport/streamable_http_client.wait_until_listening` and reused
by both production wiring code and the test harness rather than duplicated a
third time.

## Alternatives considered

- Implementing `Last-Event-ID` resumption now — deferred; no acceptance
  criterion needs it, and it would be unused infrastructure until a phase
  that actually depends on reconnect behavior exists.
- Hardcoding fixed ports in tests — rejected; three simultaneous HTTP
  listeners (proxy + two mock servers) per test, potentially running
  concurrently across parametrized test cases, would collide under fixed
  ports.

## Consequences

A later phase that wants to test or rely on mid-session reconnect behavior
over Streamable HTTP needs to design and implement that explicitly; nothing
in V1 provides it even incidentally.
