# 0010 — V2 policy model: per-principal tool allowlist, default deny

Status: Accepted

## Context

V2 (`docs/architecture.md`, "V2 — Control") adds central permissions. Its
acceptance criteria require that a denied call never reaches an upstream
server and that hidden tools cannot be called by guessing their names. No
content classifier exists yet, so policy is the only input to a decision.

## Decision

- **Shape:** a separate YAML file (`config/policies/*.yaml`, referenced by
  `policy_path` in the proxy config) mapping each principal id to a list of
  rules. Each rule has a `tool` pattern and an `effect`.
- **Patterns** are server-scoped: `server_id/tool_name` for one tool, or
  `server_id/*` for every tool on one server. Server ids cannot be
  wildcarded, so access never silently extends to servers added later.
  Patterns match `ToolId(server_id, name)`, never the agent-facing
  `server__tool` string.
- **Effects:** `allow` and `require_approval`. There is no `deny` effect:
  anything not listed is denied, and that one default is the only deny path.
  `require_approval` is enforced as a block until Approval exists (V5), as the
  architecture requires.
- **Precedence:** an exact rule beats a server wildcard, so a wildcard grant
  can be narrowed per tool. Listing the same pattern twice for one principal
  is a load error, so there is never a tie to break.
- **Visibility = callability:** a tool with any matching rule is
  discoverable; with none, it is filtered from `tools/list` *and* rejected on
  `tools/call`. Both paths ask the same `PrincipalPolicy`.
- **Version:** `sha256:` + hash of the canonical JSON form of the parsed
  document. Formatting and comments do not change it; any change in meaning
  does. Every decision records it.
- **Validation at startup:** the proxy refuses to start when the file is
  malformed, uses an unknown schema version or effect, has unknown fields, or
  has a pattern that matches no discovered tool (a typo, or a server that
  isn't configured).
- **Static:** policy is loaded once at startup; changing it means a restart.

## Alternatives considered

- **Argument constraints** (e.g. restricting `send_message` recipients) —
  deferred; they would add a rule language before any defense needs it.
- **Explicit allow/deny rules with precedence** — rejected; a second deny
  path makes misconfiguration easier with no V2 use case.
- **Hot reload** — deferred; it would require versioned in-flight decisions
  and State, which arrive with V3.

## Consequences

Policy is keyed by principal only. There is no task boundary in V2 (see
0011), so a principal's permissions apply across all of its sessions.
