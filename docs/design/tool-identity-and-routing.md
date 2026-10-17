# Tool identity and routing (V1)

Permanent reference for how the proxy discovers, disambiguates, and routes
tools across upstream servers. Promoted from the ADRs that settled this
design ([0007](../decisions/0007-tool-identity-correlation-and-stdio-failure-semantics.md),
[0008](../decisions/0008-streamable-http-scope-and-port-allocation.md)) —
read those for the *why* and the alternatives considered; this doc is the
*what*, kept up to date as the design evolves in later phases.

## Why disambiguation is needed

Two upstream servers can each expose a tool with the identical bare name
(the mock servers deliberately both expose `send_message`, for exactly this
reason). MCP dispatches `tools/call` by a single externally-visible name, so
the proxy cannot expose both servers' `send_message` unmodified — it must
rewrite the externally-advertised name while preserving which server and
which original tool it actually refers to.

## The scheme

- **External name format:** `{server_id}__{bare_name}` (double underscore).
  Defined in `src/mcp_security_proxy/core/proxy/routing/identity.py`
  (`external_tool_name` / `parse_external_tool_name`). `server_id` is
  rejected at registration if it contains the delimiter, so parsing by
  splitting on the first occurrence is always unambiguous.
- **Routing table:** `src/mcp_security_proxy/core/proxy/routing/table.py`'s
  `RoutingTable` is built once, at proxy startup, from each upstream
  server's own `list_tools()` result. It is not re-built per request in V1
  (see Limitations below).
  - `register_server_tools(server_id, tools)` registers one upstream's
    tools, keyed internally by `(server_id, bare_name)`.
  - `all_tools()` returns the tools exposed to the agent: each original
    `Tool` object copied with only its `name` field replaced by the
    external disambiguated name — every other field (description, input
    schema) is preserved exactly as the upstream server defined it.
  - `resolve(external_name)` maps back to the `(server_id, bare_name)` pair
    used to dispatch the call upstream.
- **Dispatch:** `src/mcp_security_proxy/app/wiring.py`'s `on_call_tool`
  resolves the external name, looks up the matching upstream `ClientSession`
  by `server_id`, and calls the *bare* name on it. An external name that
  doesn't resolve raises a protocol-level `MCPError(METHOD_NOT_FOUND)`
  (`core/proxy/codec/jsonrpc.py`) before any upstream server is touched.

## Why the low-level `Server`, not `MCPServer`'s mount/composition feature

The `mcp` SDK's `MCPServer` (formerly FastMCP) has a built-in sub-server
"mount" feature that also auto-prefixes names. The proxy is built directly
on `mcp.server.lowlevel.Server`'s `on_list_tools`/`on_call_tool` hooks
instead, because a canned composition feature wouldn't give the proxy an
explicit interception point for the Guard/Policy decisions a later phase
needs to insert between discovery/dispatch and the upstream call.

## Correlation (separate from identity)

`core/proxy/routing/correlation.py`'s `CorrelationTracker` is unrelated to
name disambiguation; it tracks in-flight calls per upstream server so a
dropped connection can be reported as outcome-unknown for any other calls
still in flight against that same server. It does not re-implement the
SDK's own per-connection JSON-RPC id correlation or cancellation
propagation — see 0007 for what's confirmed to already be handled by the
SDK itself.

## Limitations (deliberate, V1 scope)

- **No live re-discovery.** If an upstream tool definition changes mid
  session, the proxy does not notice until restarted. Detecting and
  re-validating changed definitions belongs to the Temporal defense
  category, much later (V4) — not V1.
- **Transport-agnostic by construction, not by accident.** Both Config A
  (stdio) and Config B (Streamable HTTP) reuse this exact routing/identity/
  correlation code unchanged; only the transport adapters differ. This was
  verified, not assumed — MR5 shipped with zero diff in `routing/`, `codec/`,
  or `correlation.py`.
