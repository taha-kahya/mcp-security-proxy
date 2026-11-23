# 0022 — Server identity view and the registration defense (Environment)

Status: Proposed

## Context

ADR 0021 lists "a view of server identity" as V4 capability 4, delivered with
an Environment defense. `RegistryView` exposes tool definitions only, so a
defense cannot ask which server a tool came from, how that server was
launched, what name it reported, or whether it is one the operator approved.

The threat is **malicious server registration**: the attacker controls a
whole MCP server that the host connects to alongside trusted ones, and uses
that server's reported name and its tool metadata to divert the agent. ADR
0016 records that this channel produced its unauthorized outcome in the
project's experiment without a proxy. This ADR does not take its payloads,
prompts or results as design input: they are the held-out evaluation (see
"Held-out evaluation").

Two facts from the current design shape the decision:

- **Trust already has a source.** V2 policy is a per-principal tool allowlist
  with default deny (ADR 0010), so a tool of a server the operator did not
  allow cannot be listed or called by a principal. What is missing is not the
  control but its evidence: a server that is connected but not approved is
  silent today, and a *lookalike* of an approved server is not noticed.
- **A name is a claim.** A server's reported name (`InitializeResult`) and
  its tool descriptions are controlled by whoever runs the server. They must
  never decide trust.

## Decision

**1. A read-only server-identity capability.** A new SDK capability,
`servers`, granted only to defenses whose manifest declares it, exposes for
each connected server a frozen record:

| Field | Source | Trust |
| --- | --- | --- |
| `server_id` | operator config | authoritative |
| `transport` and `launch` (command and arguments, or URL without credentials) | operator config | authoritative |
| `reported_name`, `reported_version`, declared capabilities | upstream `InitializeResult` | **claim** |
| `approved` | operator config entry for the server | authoritative |
| `tool_ids` | discovery | derived |

It carries no tool content and no secrets. `reported_*` fields are labelled
as claims in the type, so a defense cannot mistake them for identity.

**2. Trust comes from the operator's registry, never from a reported name.**
A server is approved only when its configured `server_id` and pinned launch
(command or URL) match an operator entry. A changed launch is a different
server. Reported names are inputs to *detection*, not to trust.

**3. One Environment defense, `environment_server_registration`,** at the
`discovery` stage, with these rules. Each has a matched benign twin in its
tests (ADR 0021, V4 acceptance):

| Rule | Fires when | Benign twin |
| --- | --- | --- |
| `.unregistered_server` | a connected server has no operator approval | an approved server |
| `.lookalike_name` | a server's reported name, or a tool name, is confusably close to an approved server's or tool's after Unicode normalization, case folding and edit distance | two unrelated names |
| `.capability_overlap` | an unapproved server offers a tool with the same name or the same input-schema shape as an approved server's tool | a unique tool |
| `.identity_changed` | an approved `server_id` reports a different name, or its launch no longer matches the pin | the same record on re-discovery |

Findings describe; the operator's policy maps severity and rule id to
exposure and call outcomes (ADR 0018). The defense contains no allow or block
logic, and it uses only the SDK.

**4. Data flow between servers is not this defense's job.** Whether content
returned by one server is passed to another is a Cross-tool question and
needs argument-aware tool adapters (ADR 0021, capability 2). This ADR does
not add that, and the design note says so explicitly.

**5. Held-out evaluation.** The defense is designed and tested from the
attack taxonomy and public descriptions of the attack. Its cases never come
from the experiment's tool, server or prompt texts, system prompts, fixtures
or results. The research repository evaluates it in three arms (no proxy,
proxy pass-through, proxy with this defense), described in
`docs/design/server-identity-and-registration-defense.md`.

**6. Delivery follows ADR 0021.** The `servers` capability, its contract
tests (run against every adapter) and `environment_server_registration` ship
as one MR, with an SDK minor-version bump.

## Alternatives considered

- **Decide trust from the reported name or description.** Rejected: both are
  attacker-controlled, which is the attack.
- **Rely on the V2 allowlist alone.** It already blocks calls to unapproved
  tools, but it gives the operator no signal about a connected, unapproved
  server or a lookalike, and it does not notice an approved server that
  changed. Kept as the enforcement layer; this defense adds the evidence.
- **Quarantine every new server until a person reviews it.** Rejected for V4
  by the same reasoning as ADR 0016 (first sight is scanned and exposed
  according to findings); V5 approval may revisit it.
- **Put identity checks in core Guard.** Rejected: ADR 0019 keeps defenses out
  of core, and a new capability needs one reviewed SDK change.

## Consequences

A defense in the Environment category becomes possible without core edits
after the capability merges. Operators must pin launch commands and URLs in
the registry, which is extra configuration. Lookalike detection is
heuristic: it has false positives on genuinely similar names and misses
semantic imitation (a different name that implies the same role); the design
note states both. Tool-level imitation is only partly covered by
`.capability_overlap`. A trusted server that is itself compromised, and
changes after approval without a launch change, belong to the Temporal
category and `Registry.approved` (ADR 0021, capability 3).
