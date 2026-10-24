# 0003 — Proxy spawns mock servers as local subprocesses

Status: Accepted

## Context

`docs/architecture.md` asks for local-versus-remote server scope to be confirmed
before implementation. V1 needs two mock MCP servers for the Proxy to route
between.

## Decision

For V1, the Proxy spawns both mock servers as local subprocesses it owns and
manages the lifecycle of, mirroring how common MCP host applications launch
stdio-based servers from a client-side config. This keeps V1 fully local with no
network/auth design questions yet, and lets the same spawning model work for the
stdio config (MR4) with a straightforward extension to the HTTP config (MR5,
where the Proxy still spawns the servers as subprocesses but connects to them over
HTTP instead of stdio pipes).

## Alternatives considered — deferred, not implemented

A **separately-run** hosting model was considered, where the two mock servers run
as independent long-lived processes (or services) and the Proxy connects *out* to
them rather than owning their lifecycle. This is closer to a genuine "remote
server" scope even when both happen to run on localhost, and would surface
connection-lifecycle questions (reconnect behavior, server restart handling,
server availability at Proxy startup) earlier than V1 needs to address them.

This alternative is deliberately **deferred, not implemented**, and is recorded
here so it isn't silently lost: a later phase that wants to exercise genuinely
remote or independently-operated servers should revisit this model rather than
assuming subprocess-spawning generalizes to that case unchanged.

## Consequences

Crash/restart behavior for Proxy-managed subprocesses is in scope for V1's error
handling (a dead child process must fail in-flight requests against it, see the
MR4 ADR on stdio connection-failure semantics); crash/restart behavior for
independently-operated remote servers is explicitly not addressed by this phase.
