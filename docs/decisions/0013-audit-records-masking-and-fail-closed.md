# 0013 — Audit records: what is logged, masking, and failing closed

Status: Accepted

## Context

V2 adds `Proxy -> Log`, and its acceptance criteria require correct decision
records. `docs/architecture.md` asks that audit evidence be kept "as
references or masked excerpts by default", that Log not be the live decision
state, and that mandatory paths not silently fail open.

## Decision

**Sink:** an append-only JSON Lines file (`audit_log_path` in the proxy
config), one record per line, written by `services/log/JsonlAuditSink`.
Writes are serialized with a lock and flushed before `write` returns. The
file is opened for append once at startup, so an unwritable path stops the
proxy from starting.

**Records** (all carry `record_id`, `timestamp`, `principal_id`,
`authenticated_by`):

- `discovery` — a `tools/list` answer: `policy_version`,
  `visible_tool_count`.
- `decision` — every `tools/call`, allowed or not: `correlation_id`,
  `requested_tool` (the agent-facing name), `tool_id` (`server/tool`, or null
  when unresolved), `decision_id`, `outcome`, `rule_refs`, `reason`,
  `policy_version`, `arguments`.
- `outcome` — every dispatched call: `correlation_id`, `decision_id`,
  `tool_id`, `status`, `tool_error`.

**Masking:** `arguments` is an `ArgumentDigest`: a SHA-256 of the canonical
JSON arguments plus the sorted top-level key names. Raw values are never
written. The digest still lets an investigator confirm whether a known
payload was sent.

**Outcome status:** `completed` when the upstream returned a result (with
`tool_error` showing whether the tool itself reported an error), `failed` when
the upstream returned a protocol error, and `unknown` when the connection
closed or the agent cancelled after dispatch, i.e. when the call may have
taken effect without a definitive answer. This partly closes the V1
limitation noted in 0007: interrupted calls are no longer reported as
`FAILED`.

**Fail closed:** if the `decision` record cannot be written, the call is not
dispatched and the agent receives an internal error. Once a call has been
dispatched it cannot be undone, so a failed `outcome` write is reported on
stderr, and the upstream result is still returned.

## Alternatives considered

- **Fail open** (log the failure, dispatch anyway) — rejected; it would let
  a full disk or a permissions change silently disable the audit trail.
- **Raw arguments** — rejected; it conflicts with the masking default and
  would put synthetic or real secrets into the audit file.
- **`fsync` on every record** — deferred; flushing protects against process
  crashes, which is the V2 requirement. Power-loss durability can be added
  in the sink without changing callers.

## Consequences

The audit log is evidence, not live decision state. Later phases that need
to query past operations (History, V3) must use State, not parse this file.
