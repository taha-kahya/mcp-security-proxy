# 0024 — V4 delivery: shared foundations first, then one track per attack category

Status: Accepted. Supersedes [0021](0021-v4-capability-first-delivery.md).

## Context

[ADR 0021](0021-v4-capability-first-delivery.md) planned V4 as five MRs, one
per shared capability (Scan, argument-aware tool adapters,
`Registry.approved` and re-discovery, a server-identity view, a stage for
errors and notifications), each with its first defense.

Studying two existing tools, Arbitus (a runtime MCP gateway) and NVIDIA
SkillSpector (an install-time scanner), changed that picture. The analysis
is in the [V4 Defense Plan](../design/v4-defense-plan.md), Part 1. It showed:

- **More shared pieces than 0021 listed.** A destination classifier is needed
  by both Cross-tool (calls to metadata endpoints) and Environment (insecure
  remote servers). A local classifier behind Scan catches reworded injections
  that rules miss. An audit hash chain and redaction outcomes are core
  changes too.
- **Capabilities of very different size.** Scan blocks six later MRs.
  Argument-aware adapters block two. Others block none. Treating them as five
  equal steps hides the critical path.
- **Work that needs no new capability.** Some defenses (annotation mismatch,
  call rate) can be built on the V3 SDK today, but 0021 gave them no place.
- **Owners map to categories, not capabilities.** One person can own a
  category end to end, from its attack doc to its last defense.

## Decision

- **V4 is delivered as the MRs in the [V4 Defense Plan](../design/v4-defense-plan.md),
  Part 2.** Each MR has an id: S for shared, and D, I, C, T, E for the five
  categories (Direct, Indirect, Cross-tool, Temporal, Environment).
- **S1 comes first** and is docs only: the plan, this ADR, the attack-doc
  template in `docs/attacks/`, and the `add-defense` skill pointed at them.
- **Shared foundations next.** S2 (Scan rules) and S3 (destination
  classifier) are on the critical path and are staffed first. S4 (Scan
  classifier) and S5 (audit hash chain) follow.
- **One track per category**, owned by one person. Each track starts with
  its attack doc (D0, I0, C0, T0, E0), written from the template.
- **Phases follow dependencies, not dates.** An MR starts as soon as
  everything it needs has merged. D1, T1, T2, C1 and E1 need only S1.
- **0021's rule still holds where a capability has a consumer.** A new SDK
  contract ships with the defense that proves it: D2 and I1 ship inside S2,
  and C1, D4, T2, E1, I3 and I4 each carry both the core change and its defense.
  S3 and S4 are the exceptions, because they are pure helpers whose first
  consumers (C2, E2, and the Scan callers) are known and planned.
- **This replaces [ADR 0023](0023-evaluation-readiness-and-transparent-mode.md)'s
  decision 7** (coverage order), which restated 0021's order. 0023's other
  decisions stand. The capability that decision added, proxying initialize
  `instructions`, prompts and resources, is MR I4 in the plan, built on
  Scan and I1.
- **Versioning is unchanged from 0021.** Each SDK addition bumps the minor
  version, and existing defenses keep working.

## Alternatives considered

- **Keep 0021's five MRs.** This leaves out the destination classifier, the
  Scan classifier, redaction and the audit chain, and gives no place to
  defenses that need no new capability. Owners would wait on capability MRs
  they don't need.
- **Add the new pieces to 0021's list in place.** The order and ownership
  change too, not only the list, so a new record is clearer than an edited
  one.

## Consequences

- Five owners can start in parallel once S1 merges, while S2 and S3 are built.
- More MRs touch shared core files. D5 and C4 both change Guard, and S2, S3,
  C1, D4, E1 and I4 each bump the SDK minor version. The lead orders or rebases
  them.
- New signals between tracks need an ADR approved by both owners. The first
  is C3's `sensitivity.observed`.
- Evaluation stays a shared step across all tracks, against a frozen version,
  never per track.
