# Transparent mode

Transparent mode makes the proxy look like the upstream server to the agent.
It fronts exactly one upstream server and adds, renames, and reorders nothing
that the proxy itself introduces. Policy, defenses, and the audit log work as
in the default mode.

## When to use it

Use it for evaluation and demos, where the agent's view must match a run
without the proxy: same tool names, same order, same definitions, same server
name and version, and the same request `_meta`. ADR 0023 sets out the
reasoning. Do not use it for a deployment with more than one upstream server.

## What changes

| | Default mode | Transparent mode |
| --- | --- | --- |
| Tool names | `server_id__tool` | the upstream's bare name |
| Tool list | merged from every server | the upstream's own order and JSON values, minus any tool policy or a defense hides |
| Server name and version | `mcp-security-proxy` | the upstream's, from its initialize result |
| `tools/call` `_meta` | not forwarded | forwarded unchanged |
| Upstream servers | one or more | exactly one |

Internal identity does not change. Policy rules, audit records, and defenses
still use `server_id/tool`, so a policy written for the default mode works
as it is.

## Tool definitions are listed as the upstream sent them

Each tool in `tools/list` is the JSON object the upstream sent, with the same
content and the same key order at every level: the tool's own keys,
`inputSchema` and its nested objects, `outputSchema`, `annotations`, and
`_meta`. A field the MCP specification does not define is kept too. JSON
whitespace may differ from the upstream's. The proxy captures the definitions
from the upstream's raw `tools/list` result at startup, and the agent-facing
server substitutes them for the SDK's own serialization, which would reorder
keys and drop unknown fields. Policy and defenses still decide which tools
are listed.

Limits:

- Only the first page of the upstream's tool list is read, as in the default
  mode. A `nextCursor` is not followed or forwarded.
- Other result members, such as `_meta` on the result itself, are not
  taken from the upstream. The `initialize` result is built by the SDK from the
  upstream's server name and version, so its other fields (for example
  `title` or `instructions`) and its key order are the SDK's.

## Configure it

```yaml
transparent: true
audit_meta_allowlist: [] # optional, see below
servers:
  - id: server_a # exactly one entry
    command: python
    args: ["-m", "fixtures.mock_servers.server_a"]
```

The proxy refuses to start if `transparent` is on and `servers` does not hold
exactly one entry. The pass-through profile is
[`config/config.transparent.yaml`](../../config/config.transparent.yaml) with
[`config/policies/transparent.yaml`](../../config/policies/transparent.yaml):
no defenses, and a policy that allows the upstream's tools.

## What it gives up

- No name disambiguation. Two servers could expose the same tool name, so
  transparent mode allows one. Run one proxy process per upstream server.
- A tool the agent calls by bare name is resolved against that one server.
  A tool that policy hides still answers like a nonexistent tool.

## `_meta`

The `_meta` object of an incoming `tools/call` is passed to the upstream
`tools/call` as it arrived, with whatever the SDK adds for its own connection
(for example, the progress token and, on newer protocol versions, its own
reserved keys). `_meta` is opaque. It never takes part in identity, policy, or
any defense decision.

The decision record keeps a masked view of it, as it does for arguments: a
SHA-256 digest and the key names, never the values. To join audit records to
evidence elsewhere by an identifier, name the keys whose values may be
recorded:

```yaml
audit_meta_allowlist: [eval_id]
```

Only string, number, and boolean values are recorded for an allowlisted key.
A value of any other type is masked. A request without `_meta` produces the
same record as before. `audit_meta_allowlist` requires `transparent: true`.

## Server instructions are not forwarded

The upstream's `instructions` text is not passed on, and the proxy forwards
no prompts or resources. Transparent mode does not implement the instruction
profile that ADR 0023 describes.
