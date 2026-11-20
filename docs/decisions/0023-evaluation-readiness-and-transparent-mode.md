# 0023 — Evaluation readiness: transparent mode, three evaluation arms, and coverage order

Status: Proposed

## Context

The proxy passes its scripted tests (ADR 0004). The manual runbook
(`docs/runbooks/codex-qwen-smoke-test.md`) records no outcome, so no live model
has been shown to use the proxy.

The held-out attack experiments live in a separate research repository. They
are never copied here, and defenses must not be designed from their payloads
(ADR 0016). Every harness there uses stdio, checks the server name, tool names,
order and definitions before inference, links evidence through an ID sent in
MCP request `_meta`, and freezes its configuration by hash.

The proxy cannot meet that setup today. It renames tools (ADR 0007), reports
the fixed name `mcp-security-proxy`, drops `_meta`, discards the upstream
`InitializeResult`, and forwards no instructions, prompts or resources. Any
change to model-visible text would also confound a with and without proxy
comparison. This ADR does not cover Scan, the first direct-metadata defense
(ADR 0016, ADR 0021), or the first pilot run.

## Decision

**1. A live smoke run comes first.** The manual runbook is run once with a
local model, and the outcome is recorded in the runbook. It stays manual and
outside CI (ADR 0004, ADR 0005).

**2. Transparent mode is opt-in, set in config.** When enabled, the proxy
fronts exactly one upstream server. It adds, renames and reorders nothing: the
agent receives the same tool names, order and JSON values the upstream sent.
Any removal or rewrite comes from a defense decision or from ADR 0016
sanitisation, and is recorded in the audit. The proxy reports the upstream's
server name and version and forwards request `_meta` unchanged. `_meta` is
opaque and is never used for identity or decisions (ADR 0011). Transparent mode
is a scoped exception to ADR 0007: the `server_id__` naming still governs the
default mode, which is unchanged. More than one upstream in transparent mode is
a startup error.

**3. `_meta` in the audit record.** `_meta` values follow ADR 0013 masking, as
arguments do: a SHA-256 digest and the key names, never raw values. Config may
name specific `_meta` keys whose values are recorded unmasked. The default is
none. Evaluation needs to join proxy records to upstream evidence by a
correlation ID. That key is an identifier, not user data, so an explicit
allowlist allows the join and keeps ADR 0013's default.

**4. Server instructions: an amendment to ADR 0016 for one profile.** This ADR
amends ADR 0016 for the pass-through evaluation profile only. In that profile
the proxy forwards the upstream `instructions` unchanged. It does not add the
wrapper structure ADR 0016 requires, and it does not remove undefined fields.
Each forwarding is logged as a loosening (ADR 0018). In every other
configuration, including the defended arm, ADR 0016 applies unchanged:
instructions are withheld until inspected, and then forwarded inside the
proxy-written structure.

**5. Three evaluation arms, and what the proxy owes each.** (a) Baseline: no
proxy. (b) Pass-through: transparent mode, no defenses, the Decision 4 profile,
and a policy that allows the experiment's tools. (c) Defended: the same, plus
the defenses under test, with ADR 0016 in force. The proxy provides a
documented pass-through profile. The harness checks that the pass-through arm's
model-visible definitions equal the baseline's, and that arm must reproduce the
baseline before a defended arm runs. Results from different arms are never
pooled. The research repository owns protocols and cohorts. The proxy never
reads experiment files.

**6. A demo in this repository.** One command runs one scenario in the
pass-through and defended arms against a local model, and prints the attack
outcome next to the proxy's audit records. It uses this repository's own
fixtures (mock servers with a poisoned description written from public
sources), never the held-out payloads. The defended arm uses the first real
defense from ADR 0021 MR 1, so the demo depends on that MR.

**7. Coverage order.** ADR 0021's order stands and is not changed here.

1. MR 1: Scan, with a Direct and an Indirect defense. Result scanning at
   `before_delivery` (ADR 0020) is part of this MR.
2. Argument-aware adapters, `Registry.approved` and re-discovery, and the
   server-identity view (ADR 0022, if accepted).
3. Errors and notifications, when an Indirect defense needs them.

This ADR adds one capability directly after MR 1: proxying initialize
`instructions`, prompts and resources, each delivered with its inspection stage
and never as uninspected forwarding by default (ADR 0016; ADR 0021 names these
surfaces as an Indirect need). It reuses Scan, and these surfaces are invisible
to the proxy today, so no defense can be evaluated on them.

**8. The model-based classifier is parked, and its shape is fixed now.** It is
not on the path to the demo. When added, it runs as a scan once per
tool-definition version, outside the defense deadline, and its result is
cached by definition hash, scanner version and settings. The defense that reads
the result supplies no enforcement (ADR 0018). The reference policy maps
classifier findings to `require_approval`. A `failed` result, or a missing one,
is resolved by policy `on_failure`, which defaults to `block` (ADR 0018). A
cache miss is an unfinished scan and reports `failed`, never clean. The
read-only defense must not declare `history` or `private_state`, so ADR 0020's
discovery caching still applies. Model dependencies stay out of the proxy core.

Reason: the research repository's offline measurements show a 0.1 to 0.5 s mean
per tool on CPU, with multi-second outliers. The 2.0 s defense deadline
(`core/runner/runner.py`) applies per call, one per tool. The mean fits; the
outliers do not.

## Alternatives considered

- **Change the harnesses to accept renamed tools and identity.** Rejected. It
  changes model-visible input and touches every frozen experiment, so results
  stop being comparable with the baseline.
- **A translation shim that renames things back.** Rejected. It puts untested
  code in the measured path.
- **Transparent behaviour as the default.** Rejected. Multi-server deployments
  need collision-free names (ADR 0007).
- **Run the classifier inline in the discovery defense.** Rejected. It breaks
  the deadline and I/O limits (ADR 0019).

## Consequences

- Transparent mode gives up tool-name disambiguation, so experiments need one
  proxy process per upstream server.
- Forwarding instructions and `_meta` passes attacker-controlled text through.
  That is intended in the pass-through arm. The defended arm must inspect it.
- The instruction profile must never be used outside evaluation.
- The defended arm changes model-visible text by design, because ADR 0016
  wraps and sanitises instructions and definitions. That difference is a
  defense effect and must be reported as one, not as noise.
- The proxy must keep the upstream `InitializeResult`, which ADR 0016 says V1/V2
  discard, so transparent mode can report the upstream name and version.
- The SDK models drop fields they do not declare and reorder keys, so
  transparent mode keeps each tool as the raw JSON object the upstream sent
  and tests equality of JSON values. The same object is what defenses and the
  Registry version see, so what the agent receives is what was inspected.
- ADR 0020's discovery event is defined per tool. Prompts and resources need a
  new event definition, and their SDK addition needs a minor version bump
  (ADR 0021). Transparent mode is proxy configuration and needs no bump.
- `require_approval` still blocks until approval exists (V5), as ADR 0018 states.
  Prompts and resources need their own tests.
