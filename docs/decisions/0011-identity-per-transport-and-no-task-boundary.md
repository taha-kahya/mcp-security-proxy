# 0011 — Identity per transport, and no task boundary in V2

Status: Accepted

## Context

V2 requires verified context: a principal established by the proxy, never
taken from an agent or server payload. `docs/architecture.md` warns that
authentication depends on transport ("do not assume an HTTP authorization
design applies unchanged to local stdio"), and that task ids must come from
a trusted integration, since a transport connection is not automatically a
user task.

## Decision

**stdio — static configured principal.** stdio carries no per-connection
credentials. Whoever can launch the proxy process is the caller, so the
principal is `identity.stdio_principal` from the config. The trust boundary
is the OS account that can start the process. `Principal.authenticated_by`
is `static_config`, so audit records show the weaker claim.

**Streamable HTTP — static bearer tokens via the SDK.** The config lists
`identity.bearer_tokens` entries of `{principal, token_sha256}`; only digests
are stored. `StaticTokenVerifier` implements the SDK's `TokenVerifier`
protocol and is passed to `Server.streamable_http_app(token_verifier=...)`,
so the SDK's own `BearerAuthBackend` and `RequireAuthMiddleware` parse the
header and reject missing or invalid tokens with HTTP 401 before any handler
runs. The SDK also binds each MCP session to the credential that created it,
so one principal cannot reuse another's session id.

The SDK installs that middleware only when an `AuthSettings` is also passed.
The proxy passes `AuthSettings(issuer_url=<its own URL>,
resource_server_url=None)`: `issuer_url` is a required field but is used
only to advertise an OAuth authorization server, which happens only when
`resource_server_url` or an auth-server provider is set — neither is here.
No OAuth metadata routes are exposed.

Handlers resolve the principal per message from `ctx.request.scope["user"]`
(the request that carried that message), not from a context variable, so a
long-lived session task cannot carry a stale identity.

**No task boundary.** V2 has no trusted source of task ids: the MCP session
id belongs to the connection, and anything the agent sends (headers,
`_meta`) is agent-controlled. Policy, decisions, and audit records are
therefore keyed by principal only, and V2 makes no task-scoped claims.

## Alternatives considered

- **OAuth** via the SDK's authorization-server support — rejected for V2;
  far more infrastructure than static tokens, with no V2 requirement for it.
- **A hand-written Starlette auth middleware** — unnecessary once the SDK's
  `TokenVerifier` hook was confirmed to work without OAuth.
- **Treating the session as the task** — rejected; it would be a weaker
  claim dressed up as task isolation.

## Consequences

A principal's permissions apply across all of its sessions. Task-scoped
history and approvals (V3/V5) need a trusted task source, which must be
designed then. Tokens are static: rotating one means editing the config and
restarting.
