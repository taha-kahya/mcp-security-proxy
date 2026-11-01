# 0020 — Inspection stages: definitions gate calls; withheld results ran

Status: Accepted

## Context

V3 runs defenses at three stages so V4's direct (definitions), indirect
(results), and cross-tool and temporal (calls) defenses need no core
changes. Two questions needed explicit answers: what hiding a definition
means for calls, and what withholding a result means for the action that
produced it.

## Decision

- **Discovery** (`Stage.DISCOVERY`): one event per tool the principal's
  policy lets it discover, with the upstream definition as the payload.
  If Guard's review is not `allow`, the tool is left out of `tools/list` and
  listed in the discovery record's `hidden_by_inspection`. This binary
  visible-or-hidden outcome is the V3 behavior. Finer exposure outcomes,
  such as exposing a tool with a flagged field redacted and requiring
  approval for its calls, are decided in
  [0016](0016-direct-metadata-defense-defaults.md), which refines this
  discovery outcome.
- **Definitions gate calls too.** `tools/call` re-runs the same definition
  check first. A tool hidden by inspection answers exactly like a
  nonexistent tool (as in 0012), so it can't be called by guessing its name.
- **Discovery results are cached** per (task, tool, definition version,
  policy version), so a repeat listing or a call does not re-run the
  defenses or commit their signals again. Two exceptions keep the cache
  sound: a result with any `failed` report is not cached, since the failure
  may be transient and would otherwise hide the tool until its definition
  or the policy changes; and nothing is cached while a discovery-stage
  defense declares `history` or `private_state`, since its result may then
  change for the same definition. Entries are not evicted. They are bounded
  by the definition and policy versions one process sees, and the execution
  plan is fixed for the process lifetime, so defense versions need no place
  in the key until hot reload exists.
- **Execution** (`Stage.BEFORE_EXECUTION`): the payload holds the bare name
  and arguments, and `action` is Registry's operator-configured `Action`.
  Execution inspections run only for tools whose definition passed.
- **Delivery** (`Stage.BEFORE_DELIVERY`): the full `CallToolResult`, with
  every content block kept typed (plus `structured` for structured content).
  A blocked result is replaced by a tool error that says the call was
  executed and only its result was withheld. A `delivery` audit record is
  written only when some defense inspects results.
- Upstream protocol errors (`MCPError`) and notifications are not inspected
  yet. They pass through as in V1/V2.

## Consequences

Withholding a result never claims an action was prevented. Results are
already fully buffered (no streaming tool results), so nothing is released
before inspection. Inspecting error messages and notifications needs a
`lifecycle` stage and is left to V4, as the defenses that need it arrive.
