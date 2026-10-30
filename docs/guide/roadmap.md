# Roadmap

The proxy is built in five phases. Each phase leaves a runnable system with its own acceptance criteria; the full plan is in the [architecture](../architecture.md#iterative-implementation).

| Phase | Adds | Status |
|---|---|---|
| V1 Proxy | stdio and Streamable HTTP, discovery, routing across servers, correlation | Complete |
| V2 Control | Identity, policy, Guard decisions, audit log | Complete |
| V3 SDK and Runner | Defense contracts, defense discovery, versioned state, Registry and History | In review |
| V4 Specialized defenses | Defenses in the five categories, on shared Scan, Registry, History and Policy | Planned |
| V5 Approval and Sandbox | Consent bound to one exact action; optional containment of local servers | Planned |

## Acceptance criteria

| Phase | Accepted when |
|---|---|
| V1 | Discovery and calls work across both servers; errors and cancellations behave correctly; no request reaches the wrong server |
| V2 | A denied call never reaches a server; hidden tools cannot be called by guessing their names; identity boundaries and decision records are correct |
| V3 | A sample defense can be added and enabled without editing core code; a failed or unsupported inspection is distinguishable from a clean one; concurrent calls cannot bypass the sample history rule |
| V4 | Every rule has malicious and matched benign cases; defenses pass tests alone and together; common scans are reused; unknown tool semantics and content are handled explicitly |
| V5 | Changed arguments, identities or tool versions, and expired approvals, cannot reuse consent; local servers cannot exceed their restrictions when Sandbox is enabled |
