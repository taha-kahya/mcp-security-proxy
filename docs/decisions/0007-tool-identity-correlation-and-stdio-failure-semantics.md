# 0007 — Tool identity disambiguation, correlation scope, and stdio connection-failure semantics

Status: Accepted

## Context

V1's Proxy must satisfy three specific requirements from `docs/architecture.md`:
keep each upstream server's original identity when tool names collide; link
request/response/lifecycle records ("correlation"); and behave correctly on
errors and cancellations for the selected transport. MR4 implements these for
Config A (stdio).

## Decision

**Tool identity disambiguation.** The proxy advertises each upstream tool
under an external name of `{server_id}__{bare_name}` (double underscore).
`core/proxy/routing/identity.py` owns this encode/decode; `server_id` is
rejected at registration time if it contains the delimiter, so the split is
always unambiguous. `core/proxy/routing/table.py`'s `RoutingTable` builds this
mapping once at startup from each upstream's own `list_tools()` result (V1
does not yet re-discover per request — see Consequences) and exposes tools to
the agent via `Tool.model_copy(update={"name": ...})`, preserving every other
field (description, input schema) from the original definition untouched.

This was built explicitly against the low-level `mcp.server.lowlevel.Server`'s
`on_list_tools`/`on_call_tool` hooks rather than via `MCPServer`'s (formerly
FastMCP's) built-in sub-server "mount" composition feature, which also
auto-prefixes names: the proxy needs its own interception point here so a
later phase can insert Guard/Policy decisions between discovery/dispatch and
the upstream call, which a canned composition feature wouldn't preserve.

**Correlation scope.** The MCP SDK already correlates JSON-RPC request/response
ids and propagates cancellation within a single connection (confirmed
empirically: cancelling the inbound awaitable for a `tools/call` causes the
SDK's client-side dispatcher to send `notifications/cancelled` upstream on its
own, via its default `cancel_on_abandon=True` behavior). `routing/correlation.py`'s
`CorrelationTracker` does not reimplement this. It adds a layer scoped to the
whole proxy process: tracking which upstream server each in-flight call
belongs to, so that if a server's connection drops while other calls are
in-flight against it, those calls can be reported as outcome-unknown rather
than silently misattributed. `on_call_tool` calls `begin()`/`end()` around
every dispatched call.

**stdio connection-failure semantics.** Confirmed empirically with a
test-only crashing server fixture (`tests/integration/flaky_server_script.py`):
when an upstream stdio child process exits mid-session, the *next* call
against that connection raises `MCPError(code=CONNECTION_CLOSED, ...)`
automatically — the SDK's own dispatcher detects the closed pipe and fails
the pending request cleanly, without the proxy needing special handling.
This propagates through `on_call_tool` as a normal protocol error to the
agent. Critically, this failure is scoped to that one connection: the proxy
process itself does not crash, and other upstream connections continue to
work normally (verified in
`test_dead_upstream_connection_fails_cleanly_without_affecting_other_server`).

**Unknown-tool and result-type errors.** `core/proxy/codec/jsonrpc.py` raises
`MCPError(code=METHOD_NOT_FOUND, ...)` for an unresolvable external tool name
— a protocol-level error, distinct from a tool-level failure
(`CallToolResult(is_error=True)`), which is reserved for "the tool ran but
failed" (e.g. reading a missing key) and is passed through from the upstream
server unchanged.

## Alternatives considered

- Re-discovering tools from each upstream on every `tools/call`/`tools/list`,
  instead of once at startup — deferred; nothing in V1's scope needs live
  re-discovery, and it isn't implemented speculatively. A Registry-aware later
  phase will need to revisit this.
- Manually re-implementing cancellation propagation (tracking request ids and
  explicitly sending `notifications/cancelled` upstream) — rejected after
  confirming empirically that the SDK already does this correctly; duplicating
  it would risk diverging from the SDK's own semantics for no benefit.

## Consequences

Because discovery happens once at startup, a tool definition that changes on
an upstream server mid-session is not reflected until the proxy restarts —
an explicit, documented V1 limitation, not an oversight. Detecting and
re-validating changed upstream definitions is in scope for the Temporal
defense category in a much later phase (V4), not V1.
