# 0017 — Enforcement: policy defaults, per-defense overrides, strictest wins

Status: Accepted

## Context

From V3, defenses report findings and inspection statuses, and something
must decide what those mean. The architecture says Policy maps findings and
statuses to enforcement, mandatory checks must not fail open silently, and
"a defense reporting no finding cannot cancel another defense's finding."
Operators also want to tune individual defenses without editing one shared
file for everything.

## Decision

- **Defaults in the policy file**, as an optional `enforcement` section
  (additive, so `schema_version` stays 1):
  `by_severity` (low/medium/high/critical), `findings` (by `rule_id`),
  `on_failure`, and `on_unsupported`, each mapping to `allow`,
  `require_approval`, or `block`. **Anything unset is `block`.**
  `not_applicable` and clean `completed` results never object.
- **Per-defense overrides** go in that defense's operator-written config
  file (`config/defenses/<id>.yaml`, under `enforcement`), using the same
  shape. They merge field by field over the defaults and apply only to that
  defense's own reports. The defense package itself never supplies its
  enforcement.
- **One version.** The policy version is the canonical digest of the policy
  document *and* every enabled defense's override, so `policy_version` on a
  decision identifies every rule behind it.
- **Strictest wins.** Guard maps the policy rule and every report to
  verdicts and takes the strictest (`block` > `require_approval` > `allow`),
  citing every deciding rule (`defense:<id>:<rule_id>`,
  `inspection:<id>:failed|unsupported`). Findings can tighten what policy
  allows, but never loosen what it denies.
- **Loosening is visible:** at startup, the proxy logs a warning for each
  override that is less strict than the defaults, for example
  `on_failure: allow` for an observation-only check.
- Reasons shown to the agent are Guard's fixed strings. A finding's
  `reason` text is not forwarded.

## Alternatives considered

- **Enforcement only in the policy file:** workable, but one file couples
  every defense's tuning.
- **Enforcement in the defense package:** rejected; a defense could allow
  its own findings.
- **A fixed severity table in Guard:** rejected; it embeds policy in Guard.

## Consequences

`require_approval` verdicts from findings block, like policy ones, until
Approval exists (V5). An override for a disabled defense is ignored and does
not affect the version.
