# 0016 — Direct metadata defense defaults and the discovery lifecycle

Status: Proposed

The V2 follow-up parts (see "Phases") are decided. The V3-V5 defaults are
hypotheses, to be confirmed in the phase that implements them and through
the evaluation in `docs/design/direct-metadata-defenses.md`. This ADR is
recorded before implementation because it shapes V3 and V4.

## Context

Direct prompt injection, as `docs/architecture.md` defines it, is malicious
instructions in tool definitions, schemas, and server metadata. This metadata
reaches the LLM when the agent lists tools, before any tool call, so the proxy
has to act during discovery. The architecture names a `discovery` stage but
specifies only the call lifecycle, and its `Decision` contract has only call
outcomes.

The project's attack experiments, run without a proxy with Qwen 3.5 9B
(4-bit builds) on local mock MCP servers, show three separate metadata
channels that reach the LLM in an ordinary host:

| Experiment | Attacker controls | Unauthorized outcome |
| --- | --- | --- |
| Tool description poisoning | a tool's description and its parameter description | a call to another server's document search |
| Server instructions injection | `InitializeResult.instructions` | a call to another server's document listing |
| Malicious server registration | a second server's name, tool name and descriptions | the report sent to that server's tool |

Each attack produced its unauthorized outcome with the payload and not
without it. Results are recorded in the project's research repository.
Three observations follow:

- Each channel is independent: a tool description, a server's instructions,
  and a server's reported identity and tool metadata.
- A hardened system prompt that called server instructions untrusted did not
  prevent the server-instructions attack, so the host's prompt is not a
  sufficient control.
- In every case the harmful step was a call to a different tool from the one
  carrying the payload, made after the metadata was shown to the LLM.
  Controlling calls to the flagged item alone does not stop it.

These experiments were designed and run independently of the proxy. They are
used to evaluate the proxy, not to design it.

V1 and V2 forward tool definitions unchanged, read them once at startup,
discard each upstream `InitializeResult`, and identify a tool by
`server_id/name` without a definition version.

## Decision

**Lifecycle.** Discovery follows the nine steps in
`docs/design/discovery-lifecycle.md`. The lifecycle is shared by all defense
categories and covers tools, prompts and resources; the defaults below are
specific to direct defenses and are described in
`docs/design/direct-metadata-defenses.md`.

**Exposure decisions.** Guard makes one exposure decision per (principal,
item version) and per (principal, server record), used by both listing and
calling. Item outcomes are `expose`, `expose_redacted` and `hide`;
instruction outcomes are `forward` and `withhold`. An exposed tool carries the
call outcome its calls receive. Policy maps findings to these outcomes; the
values below are defaults in the shipped policy, not rules fixed in Guard.

**Definition versions.** An item's version is a hash of its canonical
upstream form, named with its algorithm. The proxy's own changes (the
disambiguated name, redaction, stripped fields) are applied afterwards and do
not change it.

**First sight: scan, then expose.** An item seen for the first time is
inspected and then exposed according to the findings. It is not quarantined
until a person reviews it. The scan is staged: a deny list of known override
phrases, a fast yes/no classifier, and a targeted semantic check on what they
flag. Stages 1 and 2 set detection recall; stage 3 only sets confidence and
removes false positives. Exposure waits for the scan within a time budget,
and a failed or timed-out inspection is never treated as clean.

**A tool with a high-confidence finding: redact, warn, and require
approval.** The tool stays visible. Each flagged field is replaced by a fixed
proxy string, so the flagged text does not reach the LLM, and every call to
the tool requires explicit user approval. A low-confidence finding exposes
the tool unchanged and records the finding. A failed inspection is treated as
a high-confidence finding.

**Server instructions: forward only if inspected and clean.** Some servers
need their instructions to be usable, so they are not dropped as a design
default. Instructions are inspected on their own and forwarded only with no
finding, inside a structure the proxy writes that carries each server's
configured id outside the server's text. Otherwise they are withheld and the
decision recorded. Until an inspection exists (V4), instructions are
withheld.

**Unknown fields: strip unknown top-level fields; inspect all other text.**
Top-level fields the pinned MCP specification does not define are removed
from what the agent receives. All text inside defined fields is inspected at
any depth, including `_meta`, `annotations` and every JSON Schema keyword.
Invisible and formatting characters and terminal escape sequences are a
finding; with the default outcome, the field containing them is redacted.

**Held calls are rejected.** A call to a tool whose version differs from the
one the principal was shown is rejected at once with a fixed tool error, not
held open.

## Phases

| Part | Phase | Status |
| --- | --- | --- |
| One exposure decision by Guard for listing and calling | V2 follow-up | decided |
| Definition versions in discovery and decision records | V2 follow-up | decided |
| Complete listing; upstream `InitializeResult` recorded, instructions withheld | V2 follow-up | decided |
| Registry with server records and versioned items | V3 | hypothesis |
| Discovery-stage inspection with explicit statuses; unknown-field stripping | V3 | hypothesis |
| Re-discovery; calls bound to the exposed version | V3 | hypothesis |
| Staged scan; default outcomes; instructions forwarded when clean | V4 | hypothesis |
| Approval of a redacted tool's calls | V5 | hypothesis |

## Alternatives considered

- **Quarantine until reviewed** (as mcp-context-protector does on first use):
  rejected. It blocks every new item until a person acts, so the result
  depends on the reviewer rather than on detection.
- **Drop server instructions as a design default:** rejected. It removes a
  channel that some servers need to be usable. They remain withheld until an
  inspection exists.
- **Forward a flagged tool's text with a warning and gate only its calls:**
  rejected. The poisoned text steers the LLM toward other tools, which the
  approval does not cover.
- **Hide a tool with a finding by default:** rejected as the default. It
  breaks the user's task without telling them why. It remains available as a
  policy choice.
- **Replace a flagged description with an operator-written one:** deferred.
  It needs a source of trusted descriptions.
- **Pin definitions from a reviewed configuration:** deferred. It detects
  changes, which is temporal, rather than what a definition says.
- **Strip every non-essential field, or pass every field:** rejected. The
  first loses legitimate metadata; the second forwards text that no check
  is guaranteed to read.

## Consequences

- The `Decision` contract gains exposure decisions alongside call decisions.
- Exposure of new metadata waits for the scan, so the scan's latency adds to
  discovery.
- Until V4, instructions are withheld; until V5, a redacted tool is visible
  but its calls are blocked.
- Detection recall decides the outcome for metadata seen for the first time.
  False negatives expose poisoned text; false positives redact fields and add
  approvals. Both are measured in the evaluation.
