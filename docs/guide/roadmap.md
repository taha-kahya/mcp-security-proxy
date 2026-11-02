# Roadmap

The proxy is built in five phases. Each phase leaves a runnable system with its own acceptance criteria; the full plan is in the [architecture](../architecture.md#iterative-implementation).

| Phase | Adds | Status |
|---|---|---|
| V1 Proxy | stdio and Streamable HTTP, discovery, routing across servers, correlation | Complete |
| V2 Control | Identity, policy, Guard decisions, audit log | Complete |
| V3 SDK and Runner | Defense contracts, defense discovery, versioned state, Registry and History | Complete |
| V4 Specialized defenses | Defenses in the five categories, on shared Scan, Registry, History and Policy | In progress |
| V5 Approval and Sandbox | Consent bound to one exact action; optional containment of local servers | Planned |

## V4 delivery

V4 adds the shared capabilities that V3 deliberately left out, one at a time. Each addition arrives together with at least one real defense that uses it ([ADR 0021](../decisions/0021-v4-capability-first-delivery.md)):

1. **Scan**, with a Direct and an Indirect defense. It comes first, so defense work in other categories can start in parallel.
2. **Argument-aware tool adapters**, with a Cross-tool defense.
3. **`Registry.approved` and re-discovery**, with a Temporal defense.
4. **A view of server identity**, with an Environment defense.
5. **A stage for errors and notifications**, when the Indirect defense needs it.

Items 2 to 4 do not depend on each other. After a capability is available, further defenses in its category need no changes to core code ([Adding a defense](../guides/adding-a-defense.md)).

## Acceptance criteria

| Phase | Accepted when |
|---|---|
| V1 | Discovery and calls work across both servers; errors and cancellations behave correctly; no request reaches the wrong server |
| V2 | A denied call never reaches a server; hidden tools cannot be called by guessing their names; identity boundaries and decision records are correct |
| V3 | A sample defense can be added and enabled without editing core code; a failed or unsupported inspection is distinguishable from a clean one; concurrent calls cannot bypass the sample history rule |
| V4 | Every rule has malicious and matched benign cases; defenses pass tests alone and together; common scans are reused; unknown tool semantics and content are handled explicitly |
| V5 | Changed arguments, identities or tool versions, and expired approvals, cannot reuse consent; local servers cannot exceed their restrictions when Sandbox is enabled |
