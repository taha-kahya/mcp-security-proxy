# 0016 — V3 task boundary is the principal; State has memory and SQLite adapters

Status: Accepted

## Context

V3 adds task-scoped History and versioned State, and its acceptance criteria
require that concurrent calls cannot bypass a history rule. ADR 0011
established that there is no trusted source of task ids: the MCP session id
belongs to the connection, and headers or `_meta` are agent-controlled. The
architecture asks us to document the isolation boundary we use instead, and
to run State contract tests against both in-memory and persistent adapters.

## Decision

- **Task = principal.** `PrincipalTaskResolver` maps each verified principal
  to `TaskRef(principal_id, task_id=principal_id)`. All of a principal's
  sessions share one history, so a history rule (such as the call budget)
  applies across sessions. `TaskResolver` is an interface, so a trusted
  client integration can supply a real task boundary later without other
  changes.
- **State** stores JSON records under `Scope(owner, principal_id, task_id)`
  and a key, with a version per record. Writes are optimistic
  compare-and-set; `apply` commits several changes all-or-nothing.
  - `InMemoryStateStore`: tests and restart-free use. This is the default.
  - `SqliteStateStore`: standard-library `sqlite3`, so there is no new
    dependency. `BEGIN IMMEDIATE` transactions, `PRAGMA user_version`
    schema versioning, and it refuses unknown schemas. It holds an exclusive
    lock on the file while open, so a second process using the same file
    fails to start (`StateInUseError`). The reference configs use it.
- **Serialization:** the proxy holds a per-task `asyncio.Lock` while it
  inspects, decides, records, and reserves a call, then releases it before
  dispatch. Reservation means appending a `pending` operation to History. A
  later call therefore always decides against a history that includes every
  earlier authorized call, including in-flight ones.
- **Restart recovery:** at startup, operations still `pending` are marked
  `unknown`: they may or may not have taken effect. They are never retried.

## Alternatives considered

- **Session as task:** rejected, for the reasons in 0011.
- **Optimistic concurrency alone** (CAS on History, re-deciding on
  conflict): this works, but it makes each defense's evaluation part of a
  retry loop. A per-task lock is simpler, and the architecture suggests it
  as the initial approach.
- **aiosqlite:** an extra dependency for what a worker thread does just as
  well at this scale.

## Consequences

- Locks are per process, and decide-then-reserve atomicity relies on them.
  Two processes sharing one SQLite file could each let a call through a
  history rule, so this is enforced rather than only documented: the
  exclusive file lock makes the second process refuse to start. It is
  released when the process exits, so a crash never leaves the file locked.
  Running several proxies needs a shared lock or a reservation that rechecks
  the decision in the database; that waits until scaling out is in scope.
- Each task's history is one record that grows without bound. Compaction or
  windowing waits for a defense that needs long histories.
- Task-scoped claims in docs and audit records mean "per principal" until a
  trusted task source exists.
