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

V4 is delivered as the MRs in the [V4 Defense Plan](../design/v4-defense-plan.md) ([ADR 0024](../decisions/0024-v4-delivery-by-category-tracks.md)):

1. **S1** adds the plan, the attack-doc template and the ADR for this order.
2. **Shared foundations** come next: Scan rules (S2) and a destination classifier (S3) are on the critical path; a Scan classifier (S4) and an audit hash chain (S5) follow.
3. **One track per attack category** (Direct, Indirect, Cross-tool, Temporal, Environment), each owned by one person and starting with its attack doc.

Phases follow dependencies, not dates: D1, T1, T2, C1 and E1 need only S1, so they start while S2 and S3 are built. A new SDK capability still ships with the defense that uses it. After a capability is available, further defenses in its category need no changes to core code ([Adding a defense](../guides/adding-a-defense.md)).

## Acceptance criteria

| Phase | Accepted when |
|---|---|
| V1 | Discovery and calls work across both servers; errors and cancellations behave correctly; no request reaches the wrong server |
| V2 | A denied call never reaches a server; hidden tools cannot be called by guessing their names; identity boundaries and decision records are correct |
| V3 | A sample defense can be added and enabled without editing core code; a failed or unsupported inspection is distinguishable from a clean one; concurrent calls cannot bypass the sample history rule |
| V4 | Every rule has malicious and matched benign cases; defenses pass tests alone and together; common scans are reused; unknown tool semantics and content are handled explicitly |
| V5 | Changed arguments, identities or tool versions, and expired approvals, cannot reuse consent; local servers cannot exceed their restrictions when Sandbox is enabled |
