# 0018 — Defense extension: entry points, manifests, and failures as results

Status: Accepted

## Context

V3's main acceptance criterion is that a defense can be added and enabled
without editing core code, and that a failed or unsupported inspection is
distinguishable from a clean one. Defenses are trusted application code
(architecture rule 9), not sandboxed plugins.

## Decision

- **Discovery:** a defense package registers a factory
  (`Callable[[Mapping[str, Any]], Defense]`) under the
  `mcp_security_proxy.defenses` entry-point group. A config file in
  `defenses_path` enables it by that name and supplies its settings.
  Installed but unconfigured defenses do not run.
- **Startup validation** (`build_plan`) refuses to start when an enabled
  defense is not installed, its factory rejects the settings (`ValueError`),
  its manifest id differs from the configured name, its
  `sdk_version_range` (PEP 440, checked with `packaging`) excludes the
  core's `SDK_VERSION`, it requires a capability the core lacks, it requires
  a signal no enabled defense produces in that stage, or signal dependencies
  form a cycle.
- **Ordering:** within a stage, producers of a signal type run before its
  consumers (Kahn's algorithm). Ties are broken by defense id, never by
  registration or config order.
- **Scoped context:** a defense receives only the capabilities its manifest
  declares. Using another raises `CapabilityNotGrantedError`. Capabilities
  are read-only views or snapshots (Registry, task History, Policy, its own
  private state).
- **Failures are results:** an exception (only its type is reported, since
  the message may quote inspected content), a deadline overrun
  (`defense_deadline_seconds`, default 2s), a non-`Result` return, a signal
  the manifest didn't declare or attributed to another producer, or a
  failed or unsupported required producer all become a `failed` result.
  Only `completed` results may carry findings, signals, or state changes.
  Request cancellation still propagates.
- **State changes are proposals.** The core commits them, scoped to the
  defense id the Runner attributed them to, in one atomic `apply` before
  anything is released. A stale proposal fails the request closed.
- **Dependency rules are tested statically:** the SDK imports nothing from
  core or services, and a defense imports only the SDK and its own package.

## Alternatives considered

- **`module:factory` import paths in config:** this avoids a pyproject
  edit, but it lets configuration import arbitrary code paths.
- **Synchronous `evaluate`:** this can't be bounded by a deadline without
  threads. `evaluate` is async; CPU-bound defenses should stay small.

## Consequences

Adding a defense requires its package, a pyproject entry-point line, tests,
and a config file, with no core edits. A new capability requires one
reviewed SDK and core change, after which every defense can use it.
Deadlines cannot interrupt a defense that blocks the event loop.
