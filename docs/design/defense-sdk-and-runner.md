# Defense SDK, Runner, and shared capabilities (V3)

Permanent reference for the contracts defenses are written against and the
shared capabilities behind them. Promoted from
[0016](../decisions/0016-task-boundary-and-state-backends.md),
[0017](../decisions/0017-enforcement-defaults-and-defense-overrides.md),
[0018](../decisions/0018-defense-extension-mechanism.md), and
[0019](../decisions/0019-inspection-stages-and-delivery-semantics.md). For
how to write one, see the
[developer guide](../guides/adding-a-defense.md).

## Lifecycle with inspection

```mermaid
sequenceDiagram
    participant Agent
    participant Orchestrator
    participant Control as ProxyControl
    participant Runner
    participant Guard
    participant History
    participant Log
    participant Upstream

    Agent->>Orchestrator: tools/call name, arguments
    Note over Orchestrator,History: per-task lock held
    Orchestrator->>Control: authorize_call
    Control->>Runner: discovery event (definition)
    Control->>Runner: before_execution event (arguments, action)
    Runner-->>Control: InspectionReport per defense
    Control->>History: commit signals / private state
    Control->>Guard: decide(tool_id, policy, reports)
    Guard-->>Control: Decision
    Orchestrator->>Log: decision record (fail closed)
    alt not permitted
        Orchestrator-->>Agent: unknown tool (hidden) or tool error
    else allow
        Orchestrator->>History: reserve pending operation
        Note over Orchestrator,History: lock released
        Orchestrator->>Upstream: call_tool
        Orchestrator->>History: finish (completed / failed / unknown)
        Orchestrator->>Log: outcome record
        Orchestrator->>Control: review_result (lock held)
        Control->>Runner: before_delivery event (result)
        Control->>Guard: review(policy, reports)
        Orchestrator->>Log: delivery record (if inspected)
        Orchestrator-->>Agent: result, or "withheld; the call was executed"
    end
```

## Modules

| Module | Code | Responsibility |
| --- | --- | --- |
| SDK | `sdk/` | Frozen contract types, the `Defense` protocol, capability protocols, `sdk.testing`. Imports nothing else in the package. |
| Runner | `core/runner/` | Entry-point catalog, startup plan (validation and ordering), per-event execution, context building. |
| Guard | `core/guard/` | Verdicts from policy and reports; the strictest wins. |
| ProxyControl | `core/proxy/control.py` | Per stage: trusted context, Runner, commit, Guard. Never dispatches. |
| Task locks | `core/proxy/locks.py` | One lock per task around decide, record, and reserve. |
| Events | `core/proxy/events.py` | Protocol messages to `Event`, keeping typed content blocks. |
| Registry | `services/registry/` | Versioned definitions; `Action` from operator-configured semantics. |
| History | `services/history/` | Task-scoped operations and signals, persisted through State. |
| State | `services/state/` | Scoped versioned records, CAS, atomic `apply`; memory and SQLite. |
| Policy | `services/policy/` | Adds `enforcement` defaults plus per-defense overrides. |
| Approval | `services/approval/` | Interfaces only; not implemented or wired (V5). |
| Defenses | `defenses/<category>/<name>/` | Manifest, checks, and tests. Imports only the SDK. |

## Contracts

All inputs are frozen dataclasses; nested payloads are read-only mappings
and tuples (`sdk.freeze`).

- **Event** — `event_id`, `correlation_id`, `stage`, `direction`,
  `method`, `server_id`, `payload`, `timestamp`, `content` (typed blocks with
  `Provenance`), `tool_id`, `action`, `contract_version` (`"1"`).
- **Context** — `principal`, `task_id`, `policy_version`,
  `state_version` (the history version), `tool_version` (definition
  digest), `signals` (earlier signals in this inspection, limited to
  required types), plus `registry`, `history`, `policy`, and
  `private_state`, each raising `CapabilityNotGrantedError` unless declared.
- **Manifest** — `id` (snake_case, equal to the entry-point name),
  `version`, `sdk_version_range` (PEP 440), `stages`,
  `required_capabilities`, `required_signals`, `produced_signals`.
- **Result** — `status` (`completed` | `not_applicable` | `unsupported` |
  `failed`), `findings`, `signals`, `state_changes`, `detail`. Only
  `completed` may carry output.
- **Finding** — `rule_id`, `category`, `severity`, `reason`,
  `evidence_refs`. **Signal** — `type`, `schema_version`, `producer`
  (must equal the defense id), `value`, `evidence_refs`.
- **Action** — `operation` (`read` | `write` | `send` | `execute` |
  `unknown`), `adapter_id`, `adapter_version`, `resource?`, `destination?`,
  `sensitivity` (default `unknown`).

## Shared capability contracts

**Registry** (`RegistryView`) — *Input:* `ToolId`, arguments. *Output:*
`current() -> ToolDefinition | None` (version = `canonical_digest` of the
definition as sent); `action() -> Action`. *Scope:* global, read-only.
*Errors:* none per request; `ToolSemanticsError` at startup for invalid
semantics or entries naming no discovered tool. *Concurrency:* immutable
after startup. *Versioning:* definition digest; `adapter_version` is the
digest of `config/tools.yaml`. Unregistered and unlisted tools are always
`unknown`.

**History** (`HistorySnapshot`) — *Input:* none (bound to the task).
*Output:* `operations` (`OperationRecord`: id, correlation id, tool id,
action, status, start time), `signals`, `version`. *Scope:* one task (the
principal, 0016). *Errors:* `StateUnavailableError` refuses the request
(`INTERNAL_ERROR`) before dispatch. *Concurrency:* a consistent snapshot
taken under the task lock; pending reservations are included. *Versioning:*
the record version; persisted JSON has its shape defined in
`history/codec.py`.

**Policy** (`PolicyView`) — *Output:* `version`, `can_discover(tool_id)`.
*Scope:* the principal's rules. Defenses never see or change enforcement.

**Private state** (`PrivateState`) — *Output:* `get(key) ->
VersionedValue` (version 0 = absent). *Scope:* one defense and one task.
*Writes:* `StateChange(key, expected_version, value)` in a `completed`
result; committed atomically with the inspection's other proposals. A stale
proposal refuses the request.

**State** (`StateStore`, core only) — `read`, `read_scope`, `scopes`,
`apply` (all-or-nothing), `compare_and_set`. JSON values; reads are frozen.
Contract tests run against both adapters (`tests/contracts/test_state.py`).

**Guard** — `decide(tool_id, policy, reports)` for calls;
`review(policy, reports)` for definitions and results. Precedence: unknown
tool or default deny → block; otherwise the strictest of the policy rule and
every report's enforcement.

**Approval** — `request(ActionBinding) -> ApprovalHandle`;
`validate_and_consume(handle, binding) -> ApprovalResult`. Declared only;
`require_approval` blocks. When Approval is wired (V5), it must stay fail
closed: an unconfigured, unreachable, or erroring approver blocks, so
`require_approval` never degrades to `allow`.

## Configuration

```yaml
# proxy config
tools_path: config/tools.yaml          # optional; otherwise every tool is unknown
defenses_path: config/defenses         # optional; otherwise no defenses
defense_deadline_seconds: 2.0
state: {backend: sqlite, path: proxy_state.sqlite3}   # or {backend: memory}
```

```yaml
# config/tools.yaml
schema_version: 1
tools:
  server_a/write_record: {operation: write}
```

```yaml
# policy file, optional section; unset values are block
enforcement:
  by_severity: {low: allow, medium: require_approval, high: block, critical: block}
  findings: {some.rule: block}
  on_failure: block
  on_unsupported: block
```

```yaml
# config/defenses/<id>.yaml
id: call_budget
enabled: true
settings: {max_operations: 50}
enforcement: {on_failure: block}       # optional override, same shape
```

## Limitations (deliberate, V3 scope)

- **Task = principal** (0016); no per-session or per-conversation history.
- **One process per state file**, because task locks are in-process. This is
  enforced: a second process using the same SQLite file refuses to start.
- **Unbounded per-task history**; no compaction.
- **Not inspected:** upstream protocol errors, notifications, resources,
  and prompts (resources and prompts are still not proxied at all).
- **No scan capability, argument-aware tool adapters, `Registry.approved`,
  or server-identity view** yet. V4 adds them one MR at a time
  ([0020](../decisions/0020-v4-capability-first-delivery.md)).
- **Definitions are still read once at startup**, so temporal defenses have
  nothing to compare against until re-discovery exists.
- **Deadlines** cannot interrupt a defense that blocks the event loop.
