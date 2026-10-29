# 0019 — Inspection stages: definitions gate calls; withheld results ran

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
  listed in the discovery record's `hidden_by_inspection`.
- **Definitions gate calls too.** `tools/call` re-runs the same definition
  check first. A tool hidden by inspection answers exactly like a
  nonexistent tool (as in 0012), so it can't be called by guessing its name.
  This costs one discovery inspection per call; caching by tool and policy
  version can come when a definition check is expensive.
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
