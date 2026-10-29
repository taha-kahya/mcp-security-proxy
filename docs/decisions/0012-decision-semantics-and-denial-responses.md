# 0012 — Decision semantics and what the agent sees on denial

Status: Accepted

## Context

V2's acceptance criteria require that a denied call never reaches an upstream
server and that hidden tools cannot be called by guessing their names. Both
the decision and the response shape matter: a distinguishable "forbidden"
error would confirm that a hidden tool exists.

## Decision

**One decision per request, made by Guard.** `Guard.decide(tool_id, policy)`
returns a `Decision` (`outcome`, `rule_refs`, `reason`, `policy_version`,
`decision_id`) for every `tools/call`, including calls to names that resolve
to no tool. Outcomes:

| Situation | Outcome | Rule ref |
| --- | --- | --- |
| Name resolves to no tool | `block` | `routing:unknown_tool` |
| No policy rule matches | `block` | `policy:default_deny` |
| Rule effect `allow` | `allow` | `policy:<principal>:<pattern>` |
| Rule effect `require_approval` | `require_approval` | `policy:<principal>:<pattern>` |

Only `allow` dispatches (`Decision.permits_dispatch`). `require_approval` is
recorded as such, so audit records show what policy asked for, but is
treated as a block until Approval exists (V5).

**Response shapes:**

- **Tool the principal cannot discover** (unknown, or no matching rule): the
  same `MCPError(INVALID_PARAMS, "Unknown tool: <name>")` that V1 returned
  for a nonexistent tool, byte for byte. A hidden tool is indistinguishable
  from one that doesn't exist.
- **Tool the principal can discover, but not call yet** (`require_approval`):
  `CallToolResult(is_error=True)` naming the fixed Guard reason and the
  decision id, so an operator can find the audit record. The reason is one of
  Guard's fixed strings, never server- or agent-supplied text.
- **No verified principal** (defense in depth; HTTP middleware normally
  rejects first): `MCPError(INVALID_REQUEST, "Unauthenticated request")`.

Discovery (`tools/list`) uses the same `PrincipalPolicy.can_discover` check,
so the visible tool list and the callable set always agree.

## Alternatives considered

- **Every denial as "unknown tool"** — rejected; an agent shown a tool in
  `tools/list` but then told it doesn't exist has no way to recover or explain.
- **A distinct JSON-RPC error code for policy denials** — rejected; it
  reveals the existence of hidden tools.

## Consequences

Guard's signature takes only policy in V2. Inspection results join in V3,
when Runner exists, rather than as an always-empty parameter now.
