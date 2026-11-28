# 0027 — Four defense layers, and a measured value for every defense

Status: Proposed

## Context

V4 delivers defenses by attack category (ADR 0024). Ten defenses now exist.
Categories say *which attack* a defense targets, not *what kind of evidence*
it decides on, and the kind of evidence is what sets a defense's cost, its
false-positive risk and how far it generalises. A rule that matches a known
phrase, a check that compares a definition with its approved version and a
model that grades a whole definition fail in different ways and need
different tests.

The existing defenses, at the commit this ADR was written on:

| Defense | Plan MR | Stage | Evidence | Rules (severity) | Default | Unit tests |
|---|---|---|---|---|---|---|
| `direct_hidden_metadata` | D2 | discovery | Scan rules | 8 (3 high, 4 medium, 1 low) | on | 12 |
| `direct_schema_injection` | D3 | discovery | Scan rules | 3 (medium, high for chat-template tokens; medium; low) | on | 18 |
| `direct_tool_name_spoofing` | D4 | discovery | Scan lookalikes, registry | 3 (1 high, 2 medium) | on | 18 |
| `direct_claim_mismatch` | D1 | discovery | annotations vs `tools.yaml` | 4 (1 high, 2 medium, 1 low) | on | 12 |
| `direct_definition_classifier` | S4 | discovery | Scan classifier | 3 grades (critical, high, medium) | off (needs the bundle) | 9 |
| `indirect_result_injection` | I1, I3, I4 | before_delivery | Scan rules | 2 (high concealed, low plain) | on | 13 |
| `indirect_argument_propagation` | I2 | before_execution | Scan rules, operation | 3 (high, medium, low) | on | 13 |
| `temporal_definition_drift` | T2 | discovery | approved definition | 4 (1 high, 2 medium, 1 low) | on | 12 |
| `temporal_call_rate` | T1 | before_execution | history | 1 (high) | off (limits are workload-specific) | 12 |
| `call_budget` | sample | before_execution | history | 1 (high) | off | 8 |

Two core checks are not plugins: the stdio binary hash pin (E1, opt-in per
upstream) and inspection of `initialize` instructions (I4, through I1).

Facts that shape this decision:

- **A medium finding blocks today.** The reference policy maps medium to
  `require_approval`, and `require_approval` does not dispatch until V5
  wires approval (`core/guard/decision.py`). So every medium rule has the
  benign cost of a blocking rule.
- **The rule layer is cheap.** The five rule- and registry-based discovery
  defenses were run over a synthetic benign definition at three sizes, 20
  times each, against the real `RuleScanner`. The slowest,
  `direct_hidden_metadata`, took 23 ms on a cold 68 KB definition and about
  3 ms once Scan had cached it; at 7 KB the cold run took 2 ms. That is about
  1% of the 2 s defense deadline at the largest size.
- **The repository has no benign corpus to measure false positives on.**
  The only real definitions are the eight mock-server tools. All five
  discovery defenses report nothing on them, including the `send_message`
  name both mock servers expose, which `direct_tool_name_spoofing` treats as
  a collision, not a disguise. Every other benign case is a twin written
  next to the rule it tests, so it measures what the author thought of, not
  what real servers publish.
- **Model checks fail closed on what they cannot read.** The classifier
  reports a definition longer than its 8192-token window as failed, and
  `on_failure: block` hides it (ADR 0026). That is the right default for
  security, and a cost for large legitimate servers.
- **Planned work not built yet**: the Cross-tool track (C0 to C4, so no
  defense uses the SDK's destination classifier yet), insecure remote
  upstreams (E2), the registration defense (ADR 0022, Proposed) and
  redaction (D5, C4). Without D5 a flagged field hides its whole tool.
- An internal held-out evaluation of these defenses against end-to-end
  attacks was run. Its results are not published here. It informs which
  attack families are prioritised below, and nothing else: no pattern,
  example, threshold or test comes from it (the held-out rule in the
  `add-defense` skill).

## Decision

**1. Every defense belongs to one of four layers, by the evidence its rules
decide on.** The layer is not the stage: a text rule run on call arguments
is still Layer 1.

| Layer | Evidence | Runs | Generalises by | Current defenses |
|---|---|---|---|---|
| **L1 Signatures** | Text patterns from Scan's rule stage: hidden content, encodings, injection phrases, commands, secrets, lookalike letters | In the 2 s deadline, linear-time | New public attack descriptions → Scan rules | `direct_hidden_metadata`, `direct_schema_injection`, `indirect_result_injection`, `indirect_argument_propagation` |
| **L2 Protocol and integrity** | Structure, identity and versions: names against other names, a definition against its approved version, annotations against the operator's classification, a binary against its pin, an upstream's address | In the deadline, or in core at startup | Structure, not wording: an attacker who rewords text does not escape it | `direct_tool_name_spoofing`, `temporal_definition_drift`, `direct_claim_mismatch`, E1 pin |
| **L3 Semantic classifier** | A local model's grade of the whole definition (later, other surfaces) | Once per definition version, outside the deadline (ADR 0023 §8, ADR 0026) | New training data and a new pinned checkpoint, never rules | `direct_definition_classifier` |
| **L4 Behavioural runtime** | What the task does over time: call volume, sequences, destinations, sensitivity of what was read | In the deadline, over `history` and adapters | Operator classification of tools and data | `temporal_call_rate`, `call_budget`; C1 to C4 planned |

`indirect_argument_propagation` weighs its L1 match by the call's operation,
an L4 input; it stays L1 because a match is what it reports.

A defense's module docstring names its layer. A defense that needs evidence
from two layers is two defenses, or one layer's defense that reads a signal
from the other.

**2. Each layer has its own severity and failure contract.**

- **L1.** High only for concealed evidence (text revealed by decoding, tag
  characters, lookalike letters, hidden markup), which benign content has
  no reason to produce. Plain visible text is low, or medium only where the
  surface is one a model acts on with no human in between (a tool
  definition, an argument to a `write`, `send` or `execute` call). A failure
  is a bug: `on_failure: block` applies.
- **L2.** High where the structure has no benign reason (two different
  names with the same skeleton, a new capability after approval). A change
  the defense cannot classify is reported, never treated as unchanged.
- **L3.** The grade is the severity (ADR 0026). A definition the model has
  not graded is failed, not clean. Thresholds belong to one checkpoint and
  are refitted with it.
- **L4.** A missing signal or an unclassified tool is unknown, never safe.
  Volume and flow limits are operator settings with no universal default,
  so these defenses may ship disabled.

Because a medium finding blocks until V5, a new medium rule needs the same
benign evidence as a high one (decision 3). Low findings are recorded and
never block under the reference policy.

**3. A defense is added only with measured value, reported in its MR.**

- **Attack cases.** Written from `docs/attacks/<category>.md` and public
  descriptions. Each names the attack type it covers and its layer.
- **Benign cost.** The defense runs over the benign corpus (decision 4) and
  the MR reports findings by rule and severity. A high or medium rule with
  findings on the corpus's held-out half needs a stated reason to merge.
- **Unique contribution.** The MR reports which of the repository's attack
  cases the defense catches that no enabled defense already catches. A rule
  with no unique case and a non-zero benign cost is not added. A rule that
  only repeats another layer's catch is accepted when it is the cheaper or
  more robust layer for it (for example, L2 against a reworded attack that
  L1 depends on wording for).
- **Cost.** The defense's time on the corpus's largest definition, cold,
  against the 2 s deadline.

No rule is written to match one attack variant. A rule describes a class of
evidence that a family of attacks needs, so that rewording or re-encoding
the attack does not escape it. When a family can be described only by what
the text means, it is L3's, and the gap is stated in the attack doc's *Not
covered* section rather than filled with phrases.

**4. A benign corpus of public tool definitions, split in two.** It holds
definitions published by real MCP servers, each with its source and
licence, frozen by hash. One half is for development: rules may be tuned on
it. The other half is held out and only reported, never tuned on. Its first
MR also reports, for every existing defense, the benign cost and the
unique contribution of decision 3, so the current set has a baseline before
anything is added.

**5. Order of work.** Layers that generalise by structure come first, and a
family's essential L1 and L2 checks come before more L3 or L4 work on it:

1. The benign corpus and the baseline report (decision 4).
2. L2 gaps: insecure or internal remote upstreams (E2, which also gives the
   destination classifier its first defense), the registration defense
   (ADR 0022), and tool names one edit away from another server's tool,
   which `direct_tool_name_spoofing` does not cover.
3. The Cross-tool foundation: its attack doc (C0) and argument-aware
   adapters with the sensitive-read-then-external-send rule (C1), the first
   L4 defense that does not depend on detecting the injection.
4. Usability: field redaction (D5), so a flagged description no longer
   costs the user the whole tool.
5. L3 beyond definitions (tool results, server instructions), only after
   the corpus can measure its benign cost.

## Alternatives considered

- **Keep organising by category only.** The categories stay as tracks (ADR
  0024); layers are added beside them because category does not predict cost
  or false-positive risk, and the evaluation each defense needs follows the
  layer.
- **Add rules for each attack variant the evaluation misses.** It would
  raise the held-out number and stop measuring generalisation: the next
  rewording escapes again, and each phrase rule adds benign cost. Rejected
  by decision 3.
- **Rely on the classifier and drop L1.** L1 runs in milliseconds, explains
  its finding with a pointer and covers results and arguments, which the
  classifier does not read yet. L3 also fails closed on definitions past its
  window. Rejected.
- **Measure false positives on the twins in the unit tests.** They are
  written next to each rule and pass by construction. Kept as unit tests,
  not as evidence of benign cost.
- **Make medium never block (`medium: allow`).** That is the operator's
  choice, not the reference policy's; decision 2 instead holds medium rules
  to the evidence bar of a blocking rule until V5 approval exists.

## Consequences

- The `add-defense` skill asks for the layer at design time and for the
  decision 3 report in every defense MR.
- The baseline report may show an existing rule with no unique catch and a
  benign cost. It is then lowered in severity or removed in its own MR.
- Corpus definitions are untrusted text. Tests and reports refer to them by
  hash and pointer, never by quoting them.
- The corpus does not cover private or enterprise servers, so its benign
  cost is a lower bound for those deployments.
- Deferred: L3 on results and server instructions, an approval-backed
  medium (V5), and a classifier answer for definitions past its window
  other than failing closed.
