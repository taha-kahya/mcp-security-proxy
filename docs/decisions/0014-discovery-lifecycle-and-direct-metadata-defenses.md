# 0014 — Discovery lifecycle and defaults for direct metadata defenses

Status: Proposed

This ADR records decisions before they are implemented, because they shape
V3 and V4. It covers work in several phases (see "Phase mapping"). Each part
becomes Accepted when the phase that implements it is merged.

## Context

Direct prompt injection, as `docs/architecture.md` defines it, is malicious
instructions in tool definitions, schemas, and server metadata. This metadata
reaches the LLM when the agent lists tools, before any tool call, so the proxy
has to act during discovery. The architecture names a `discovery` stage but
specifies only the call lifecycle.

The project's attack experiments, run without a proxy with Qwen 3.5 9B
(4-bit builds; runtimes in `docs/design/discovery-lifecycle.md`) on local mock
MCP servers, show three separate metadata channels that reach the LLM in an
ordinary host:

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
- In every case the harmful step was a call the user did not ask for, made
  after the metadata was shown to the LLM.

These experiments were designed and run independently of the proxy. They are
used to evaluate the proxy, not to design it (see
`docs/design/discovery-lifecycle.md`, "Evaluation").

V1 and V2 forward tool definitions unchanged, read them once at startup,
discard each upstream `InitializeResult`, and identify a tool by
`server_id/name` without a definition version.

## Decision

**Lifecycle.** Discovery follows the nine steps in
`docs/design/discovery-lifecycle.md`: initialize, list completely, normalize
and fingerprint, register, inspect, decide exposure, publish, bind calls to
the exposed version, and re-discover on change.

**First sight: scan, then expose.** A server or tool seen for the first time
is inspected and then exposed according to the findings. It is not
quarantined until a person reviews it. The scan is staged, so most metadata
is decided by fast checks:

1. a deny list of known override phrases, such as instructions to ignore
   previous instructions;
2. a fast yes/no classifier;
3. a targeted semantic check, run only on expressions the earlier stages
   flag.

Exposure waits for the scan, within a configured time budget. An inspection
that fails or exceeds the budget is recorded as `failed`, never as clean, and
is handled as a high-confidence finding.

**Server instructions: forward if an isolated inspection finds them clean.**
Some servers need their instructions to be usable, so they are not dropped
by default. Each server's instructions are inspected on their own, apart from
the tool definitions. Clean instructions are forwarded in the proxy's own
`InitializeResult`, labelled with the configured server id. Instructions with
a finding are withheld, and the decision is recorded.

**A tool with a high-confidence finding: warn, and require explicit
approval.** The tool stays visible. Its exposed description carries a fixed
proxy warning, and every call requires explicit user approval
(`require_approval`). Only high-confidence findings do this, so that the
proxy does not block too much. A low-confidence finding exposes the tool
unchanged and records the finding. Until the Approval module exists (V5),
`require_approval` blocks, as the architecture requires.

**Unknown fields: strip unknown top-level fields; inspect all other text.**
Fields that the pinned MCP specification does not define for a tool or for
`InitializeResult` are removed before exposure. All text inside defined
fields is inspected at any depth, including `title`, `annotations`, `_meta`,
and every JSON Schema keyword (`description`, `title`, `examples`, `default`,
`enum`, and non-standard keywords).

**Definition versions.** A tool's version is the hash of its canonical
definition after normalization and field stripping. Exposure decisions, call
decisions, and audit records carry it.

## Phase mapping

| Part | Phase |
| --- | --- |
| One exposure decision, made by Guard, for both listing and calling | V2 follow-up |
| Per-tool definition version and exposure outcome in discovery and decision records | V2 follow-up |
| Complete listing (`nextCursor`); upstream `InitializeResult` kept and its handling stated | V2 follow-up |
| Server record, versioned definitions, `Registry.server()` | V3 |
| Normalization and unknown-field stripping | V3 |
| Discovery-stage inspection with explicit statuses (`not_inspected`, `failed`) | V3 |
| Re-discovery on `list_changed`; calls bound to the exposed version | V3 |
| Staged scan and direct defenses | V4 |
| Warning and `require_approval` on a high-confidence finding; instructions forwarded or withheld by inspection | V4 |
| Approval of a flagged tool's calls | V5 |

Until V4, no inspection exists, so server instructions are not forwarded:
the "forward if clean" default needs an inspection to establish that they
are clean.

## Alternatives considered

- **Quarantine until reviewed** (as mcp-context-protector does on first use):
  rejected. It blocks every new server and tool until a person acts, so the
  result depends on the reviewer rather than on detection.
- **Drop server instructions by default:** rejected. It removes a channel
  that some servers need to be usable.
- **Hide a tool with a finding:** rejected. It breaks the user's task
  without telling them why. Warning and approval keep the decision with the
  user.
- **Replace a flagged description with an operator-written one:** deferred.
  It needs a source of trusted descriptions, which the proxy does not have.
- **Pin definitions from a reviewed configuration:** deferred. It detects
  changes, which is temporal, rather than what a definition says.
- **Strip every non-essential field, or pass every field:** rejected. The
  first loses legitimate metadata; the second forwards text that no check
  is guaranteed to read.

## Consequences

- Exposure of new metadata waits for the scan, so the scan's latency adds to
  discovery. The staged scan keeps the expensive check off most metadata.
- Guard needs an exposure decision for discovery, separate from the call
  decision, and listing and calling must use it.
- Registry needs a server record and definition versions; audit records need
  per-tool versions and outcomes.
- Until V5, a high-confidence finding makes a tool visible but unusable.
- Detection quality decides the outcome for metadata seen for the first
  time. False negatives expose poisoned metadata; false positives add
  approvals. Both are measured in the evaluation.
