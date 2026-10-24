# 0006 — Mock server default ports and test port allocation for Streamable HTTP

Status: Accepted

## Context

The mock servers now support Streamable HTTP (see 0002 for the dual-transport
scope decision). Running them standalone needs a port convention; running them
in parallel inside the test suite needs to avoid port collisions, including
across concurrently-run test processes.

## Decision

- **Standalone/manual defaults:** `server_a` defaults to port 8001, `server_b`
  to port 8002, overridable via `--port`. These are just convenient defaults
  for manually running a server; nothing downstream depends on these specific
  numbers.
- **Tests:** always bind an OS-assigned ephemeral port (bind to port 0, read
  back the assigned port, close the socket, then pass that port to the
  spawned server) rather than reusing the manual defaults. This avoids
  collisions between parallel test runs and doesn't hardcode availability
  assumptions about 8001/8002.
- Readiness is detected by polling a raw TCP connect to the assigned port
  (bounded retry loop with a timeout), not a fixed sleep, since server startup
  time isn't guaranteed constant.

## Consequences

MR4/MR5's Proxy-spawned subprocess configs will need their own port allocation
story once two mock servers must run simultaneously under one Proxy process;
this ADR's ephemeral-port approach is the pattern to reuse there rather than
hardcoding 8001/8002 into `config/config.http.yaml`.
