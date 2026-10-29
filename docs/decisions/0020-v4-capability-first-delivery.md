# 0020 — V4 delivery: one MR per shared capability, each with its first defense

Status: Accepted

## Context

V3 provides the SDK contracts, the three inspection stages, the Runner,
signals, enforcement, State, History, and `sdk.testing`. Adding a defense
needs no core edits. However, the architecture's V4 categories need shared
capabilities that V3 deliberately left out, because the plan says to
"introduce shared Scan and tool adapters as actual defenses require them":

| Category | Usable in V3 | Missing |
| --- | --- | --- |
| Direct | discovery stage, `Registry.current` | Scan (`instructions`, `secrets`) |
| Indirect | delivery stage, typed content with provenance | Scan; inspecting errors, resources, and prompts |
| Cross-tool | History, signals, `Action` | argument-aware tool adapters (`resource`, `destination`, `sensitivity` from arguments; today always unknown) |
| Temporal | definition versions, private state | `Registry.approved()` and re-discovery (definitions are read once at startup) |
| Environment | — | a view of server identity (transport, URL, command); `RegistryView` exposes definitions only |

We had to decide how to deliver these additions.

## Decision

- **V3 ships as its own PR**, unchanged. The extension is not added to it.
- **V4 starts with SDK extensions, delivered as one MR per shared capability.**
  Each MR includes the capability, its contract tests (run against every
  adapter), and at least one real defense that uses it:
  1. **Scan**, with a Direct and an Indirect defense. Both categories need
     it, so it comes first.
  2. **Argument-aware tool adapters**, with a Cross-tool defense.
  3. **`Registry.approved` and re-discovery**, with a Temporal defense.
  4. **A server-identity view**, with an Environment defense.
  5. **A stage for errors and notifications**, when the Indirect defense
     needs to inspect error messages.
- **Order:** MR 1 merges first, so parallel defense work can start. MRs 2–4
  don't depend on each other.
- **Versioning:** every addition is new, so each one bumps the SDK minor
  version (`1.x`). Existing defenses and their `sdk_version_range` keep
  working.
- **After a capability merges**, further defenses in that category are their
  own small MRs: package, tests, entry point, and config, with no core edits.

## Alternatives considered

- **Add the extension to the V3 PR:** this would enlarge a finished,
  verified PR and delay it. It would also mix the mechanism with new public
  contracts that deserve their own review.
- **One MR with every capability and no defenses:** this unblocks everyone at
  once, but the interfaces would be designed without a real consumer to
  prove them. It is also one large contract change to review and revert.

## Consequences

Each interface is reviewed on its own and proven by the defense that needs
it, and a wrong design can be reverted alone. Categories wait for their
capability's MR. Merging Scan first limits that wait for the two categories
that share it.
