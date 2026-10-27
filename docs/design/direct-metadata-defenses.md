# Direct metadata defenses

Status: proposed. These defaults are hypotheses, to be confirmed in V4 and
through the evaluation below. The reasons are in
[ADR 0016](../decisions/0016-direct-metadata-defense-defaults.md).

Direct defenses inspect what server and tool metadata says, at steps 5 and 6
of the [discovery lifecycle](discovery-lifecycle.md). They report findings;
Policy maps the findings to exposure outcomes, and Guard applies them.

## What is inspected

Every text value the agent could receive, at any depth:

- **Server record:** `instructions`, and the reported `serverInfo` (`name`,
  `title`, `description`, `websiteUrl`).
- **Tools:** `name`, `title`, `description`, `annotations`, `_meta`, and every
  JSON Schema keyword in `inputSchema` and `outputSchema`, including
  `description`, `title`, `examples`, `default`, `enum` and non-standard
  keywords.
- **Prompts and resources,** when proxied: their names, titles, descriptions
  and argument descriptions.

Server instructions are inspected on their own, apart from the item
definitions.

Before inspection, a copy of the text is normalized (Unicode NFKC, with
invisible and formatting characters made visible). Invisible and formatting
characters (the Unicode TAG block, zero-width and bidirectional controls)
and terminal escape sequences are a finding in their own right.
Normalization is applied to the copy that is inspected; it does not change
the definition version.

## Unknown fields

Top-level fields that the pinned MCP specification does not define for an
item or for `InitializeResult` are removed from what the agent receives.
Everything inside defined fields is kept and inspected, including `_meta`,
`annotations` and non-standard schema keywords.

## Scan

The scan is staged, so that the slower check runs on little of the metadata:

| Stage | Check | Runs on | Role |
| --- | --- | --- | --- |
| 1 | Deny list of known override phrases | all text | catches known phrasings |
| 2 | Fast yes/no classifier | all text | the main detector; tuned for recall |
| 3 | Targeted semantic check | text flagged by stages 1-2 | sets confidence; removes false positives |

Stage 3 only re-examines what stages 1-2 flagged. It can lower a finding's
confidence or clear it, but it cannot find what they missed, so detection
recall is set by stages 1 and 2.

Exposure waits for the scan, within a configured time budget. An inspection
that fails or exceeds the budget has status `failed`, which is never treated
as clean.

## Default outcomes

These are the defaults in the shipped policy. An operator can change them,
including choosing `hide` or `withhold` for any finding.

| Subject | Condition | Default outcome | Calls |
| --- | --- | --- | --- |
| Tool | no finding | `expose` | per principal policy |
| Tool | low-confidence finding | `expose`; finding recorded | per principal policy |
| Tool | high-confidence finding, or `failed` inspection | `expose_redacted` | `require_approval` |
| Server instructions | inspected, no finding | `forward` | n/a |
| Server instructions | any finding, `failed`, or not inspected | `withhold` | n/a |

With `expose_redacted`, every flagged field is replaced by a fixed proxy
string stating that the field was withheld by the proxy. The agent still sees
the tool, its name and its unflagged fields, so the user's task can proceed
with approval, but the flagged text never reaches the LLM. Replacing the text
matters as much as the approval: the poisoned text steers the LLM toward
other tools, which approval of the flagged tool alone would not stop.

Until V4 there is no inspection, so instructions are withheld. Until V5,
`require_approval` blocks.

## Forwarded instructions

Forwarded instructions are placed in a structure the proxy writes. Each
server's configured id is a field set by the proxy, outside the server's
text, and the server's text is a quoted value within that structure, so a
server cannot present its text as another server's or as the proxy's.

## Evaluation

The project's attack experiments are rerun with the proxy between the agent
and the servers. They were designed independently of the proxy and are used
as held-out tests; the proxy is not tuned to their payloads.

**Arms.** Each experiment keeps its protocol, seeds, prompts and model
runtime:

1. **Direct:** the existing cohort without a proxy, cited as recorded.
2. **Pass-through:** the proxy with no defenses. This separates the proxy's
   own effect, such as the disambiguated names, from the defenses'.
3. **Defended:** the proxy with these defaults.

**Measures.**

- Attack outcome, from the upstream servers' own audit logs, not from
  detector findings.
- What the agent was shown: each item's exposure outcome and version, from
  the discovery records.
- False findings and approvals on runs without the attack and on the
  authorized-control runs.
- Task completion. A flagged tool requires approval, so the protocol states
  whether approvals are granted or refused and reports both where relevant.
- Added latency at discovery.

**Runtimes.** Each rerun pins its cohort's runtime:

| Experiment | Runtime |
| --- | --- |
| Tool description poisoning | LM Studio, `qwen3.5-9b-mlx` (MLX 4-bit) |
| Server instructions injection | LM Studio, `qwen3.5-9b-mlx` (MLX 4-bit) |
| Malicious server registration | Ollama 0.40.6, `qwen3.5:9b-q4_K_M` (GGUF Q4_K_M) |
