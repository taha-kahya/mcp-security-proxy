---
name: add-defense
description: Add or change a defense in mcp-security-proxy (direct, indirect, cross-tool, temporal, or environment attacks, or a sample). Use whenever work touches src/mcp_security_proxy/defenses/, adds a detection rule, a defense config in config/defenses/, or a mcp_security_proxy.defenses entry point.
---

# Adding a defense

A defense inspects one event and returns a `Result`. Guard and the
operator's policy decide what happens. The full explanation is in
`docs/guides/adding-a-defense.md` and the contracts are in
`docs/design/defense-sdk-and-runner.md`. Read both before the first defense
in a session. This skill is the workflow and the checklist.

V4 is delivered as the MRs in `docs/design/v4-defense-plan.md` (ADR 0024).
Also read it before the first defense in a session, and find the defense's
MR id there (for example D3 or C2):

- **Part 1** says, for each attack type, what our defense must do better
  than the prior art (Arbitus, NVIDIA SkillSpector). Arbitus is AGPL-3.0:
  take its ideas only, never its code or rule text.
- **Part 2** says which MRs this one needs and which category track owns it.

The category's attack doc, `docs/attacks/<category>.md`, lists the attacks,
benign twins and planned rule ids. It is written from
`docs/attacks/0000-template.md` in the track's phase 0 MR (D0, I0, C0, T0,
E0).

Every defense also belongs to one of four layers
(`docs/decisions/0027-layered-defenses-and-measured-value.md`), set by the
evidence its rules decide on, not by its stage:

| Layer | Evidence | Example |
| --- | --- | --- |
| L1 Signatures | Scan rule matches: hidden content, encodings, phrases, commands, secrets | `direct_hidden_metadata` |
| L2 Protocol and integrity | Structure, identity, versions, pins, addresses | `temporal_definition_drift` |
| L3 Semantic classifier | A Scan model's grade, outside the deadline | `direct_definition_classifier` |
| L4 Behavioural runtime | History, sequences, destinations, sensitivity | `temporal_call_rate` |

The layer decides the severity rules, the failure behaviour and the evidence
the MR must report (ADR 0027, decisions 2 and 3). Prefer the lowest-cost
layer that does not depend on the attack's wording: an L2 check survives a
rewording that an L1 phrase does not.

## 1. Pin down the design with the user first

Before writing code, settle these with the user. Start from the category's
attack doc and the plan's Part 1 row for this attack, if they exist; if the
attack doc is missing, say so, because it is the track's first MR. Explain
each decision plainly, with a concrete malicious example and its benign
twin. Then state the rule's severity by its layer's contract (ADR 0027,
decision 2):

- **L1**: high only for concealed evidence; plain text is low, or medium on
  a surface a model acts on directly (a definition, an argument to a write,
  send or execute call).
- **L2**: high only where the structure has no benign reason; a change the
  defense can't classify is reported, never clean.
- **L3**: the model's grade is the severity; an ungraded input is failed.
- **L4**: a missing signal or unclassified tool is unknown, never safe.

Medium blocks under the reference policy until V5 wires approval, so a
medium rule needs the same benign evidence as a high one.

| Decision | Example |
| --- | --- |
| Attack and category | "A tool description tells the agent to read `~/.ssh/id_rsa`" → `direct` |
| Layer | L1, L2, L3 or L4, with the reason (see the table above) |
| Class of evidence | What every variant of the attack needs, not one variant's text: "instructions hidden from a reviewer", not "this phrase" |
| Matched benign case | "An SSH tool whose description says it reads `~/.ssh/config`" |
| Stage | `discovery` (definitions), `before_execution` (arguments, `Action`), `before_delivery` (results) |
| Capabilities | Only the ones it reads: `registry`, `history`, `policy`, `private_state` |
| Rule ids and severity | `direct_hidden_instructions.file_read`, high |
| Signals | Produced or consumed; see step 2 |
| Settings | What an operator tunes, with safe defaults |
| What it does **not** cover | So it is stated in the module docstring |

**Keep the evaluation held out.** The experiments in the research repository
are the held-out evaluation of these defenses, so a defense must be designed
without them. Never take examples, rules, patterns, thresholds or test cases
from those experiments: not their poisoned tool, server or prompt texts,
their system prompts, their fixtures, or their results. Write attack cases
from the attack taxonomy and public descriptions of the attacks instead. If
the user offers an example from the experiments, say why it can't be used
and write a different one. Held-out results may decide which attack family
is worked on next; they never supply its rules.

**No variant-specific rules.** A rule describes a class of evidence a family
of attacks needs, so rewording or re-encoding the attack doesn't escape it.
If the family can only be described by what the text means, it is L3's:
write the gap into the attack doc's *Not covered* section instead of adding
phrases.

## 2. Check the SDK is enough

Use only `mcp_security_proxy.sdk` (and third-party libraries). If the check
needs something no capability provides, **stop and tell the user**. Never
import core or services, and never add a workaround inside the defense.
The plan (Part 2) lists the planned V4 capabilities and the MR that adds
each one:

- Scan rules: decoding, hidden content, lookalikes, secrets (S2)
- a destination classifier for URLs and hosts (S3)
- a local classifier behind Scan (S4)
- argument-aware tool adapters: `resource`, `destination`, `sensitivity` (C1)
- `RegistryView.tool_ids()` (D4)
- re-discovery and the approved version of a definition (T2)
- a server-identity view (ADR 0022) and `ServerRecord.integrity` (E1)
- inspection of errors and notifications (I3)
- inspection of initialize instructions, prompts and resources (I4)
- redaction outcomes for definitions (D5) and for calls and results (C4)

Check `src/mcp_security_proxy/sdk/` for what exists now; some of these may
already be merged. If the defense needs one that hasn't merged, name its MR
id when you tell the user.

**Text analysis belongs to Scan.** Decoding, hidden content, injection
phrases, lookalikes and secrets are `context.scan` methods (S2,
`docs/decisions/0025-scan-contract-and-rule-stage.md`). Declare
`Capability.SCAN` and map its matches to your own rule ids and severities;
never copy a decoder or a phrase list into a defense. If a detector is
missing, it is a Scan change, not a defense workaround.

**Model-based checks belong to Scan.** A defense has no I/O and a 2 s
deadline, so a classifier, an embedding model or a semantic check can't run
inside it. Those are the job of Scan (plan MRs S2 and S4), which
the defense calls. If Scan hasn't merged and the check needs it, stop and
tell the user rather than building a model into the defense or settling for
weaker patterns without saying so.

**Signals are cross-team contracts.** Reuse an existing signal type if one
fits. A new type needs agreement from the owners of the producer and
consumer, recorded in the decisions. A consumer must still work when the
signal is missing: no evidence means `unknown`, not safe.

## 3. Create the files

Use the templates in [templates.md](templates.md). Naming:

- Package: `src/mcp_security_proxy/defenses/<category>/<name>/`, where
  `<category>` is one of `direct`, `indirect`, `cross_tool`, `temporal`,
  `environment`, `samples`. Create `<category>/__init__.py` if it's missing.
- Defense id: `<category>_<name>`. It must be unique and snake_case, and it
  must equal the entry-point name.
- Rule ids: `<defense_id>.<rule>`. The Runner fails any finding whose rule
  id doesn't start with the defense id, so collisions can't happen silently.
- `Finding.category`: the category name.

The sample `call_budget` (id `call_budget`, category `"sample"`) predates
these conventions and exists only to test the extension mechanism. Follow
the conventions above, not its names.

Files:

1. `<name>/__init__.py`, `<name>/defense.py`
2. `<name>/tests/__init__.py`, `<name>/tests/test_<name>.py`
3. One line in `pyproject.toml` under
   `[project.entry-points."mcp_security_proxy.defenses"]`
4. `config/defenses/<defense_id>.yaml`. Leave `enforcement` out unless the
   user asks; the policy file's defaults apply. Add `enabled: false` if the
   reference configs shouldn't run it yet.

Then run `uv sync` so the entry point is installed.

## 4. Rules a defense must follow

**Report honestly:**
- `completed()` with no findings means "inspected, clean". Return it only
  when you actually inspected the event.
- `not_applicable()` means the event isn't one this defense checks.
- `unsupported("<content kind>")` means you can't inspect this content (for
  example, an image). It blocks by default. Never use it to mean "fine".
  At `before_delivery`, check every block's type before inspecting, as the
  template's skeleton does: one uninspected block makes the event
  `unsupported`, not `completed`.
- Never catch broad exceptions to return `completed`. Let them propagate;
  the Runner reports them as `failed`.

**Keep output free of inspected content:**
- `detail`, `reason`, and `evidence_refs` must not quote the content you
  inspected, so a secret never lands in logs.
- Use JSON Pointers to the exact field instead, for nested fields too:
  `/description`, `/inputSchema/properties/path/description`,
  `/arguments/url`, `/content/0/text`. Add a range when it helps
  (`/description#120-180`). A precise pointer also lets the proxy act on just
  that field later, such as redacting it.

**Stay pure and fast:**
- The result depends only on the event, the context, and the settings: no
  I/O, no network, no globals, no mutable state on the instance.
- Use `private_state` and `StateChange` for memory across events.
- The deadline is 2 s and can't interrupt code that blocks the event loop.
  Keep CPU work small and never call blocking functions.

**Use the SDK's helpers for shared judgements:**
- Classify URLs and hosts with `classify_destination`, never with your own
  regex or `ipaddress` calls, so every defense agrees on what is internal
  and disguised addresses can't slip past one of them. Treat `name` and
  `invalid` as unknown, never as external or safe.

**Validate settings:**
- Use a pydantic model with `extra="forbid", frozen=True`.
- `create` raises `ValueError` for bad settings; pydantic's
  `ValidationError` already is one.

**Leave enforcement to the operator:**
- Never put allow or block logic in the defense.
- Findings describe; the operator's policy maps severity and rule id to a
  verdict.

## 5. Tests (required matrix)

Tests use only `mcp_security_proxy.sdk.testing`: no proxy, no servers. As
in step 1, cases come from the attack taxonomy and public descriptions,
never from the evaluation experiments. The test template has one test per
row below. Each rule needs:

- [ ] each malicious case → the expected `rule_id`
- [ ] **its matched benign twin** → `completed` with no findings
- [ ] other stages or events it ignores → `not_applicable`
- [ ] content it can't inspect → `unsupported`
- [ ] missing input (no `action`, no signal, empty history) → the
      documented behaviour, never a crash
- [ ] invalid settings → `ValueError`
- [ ] produced signals carry `producer=DEFENSE_ID` and are declared in the
      manifest
- [ ] every rule id starts with `DEFENSE_ID + "."`

A defense that uses Scan scripts it with
`make_context(..., scan=FakeScan(matches=(...)))`, so its unit tests check
how matches become findings. Add its malicious cases and benign twins
against the real `RuleScanner` in `tests/contracts/test_scan_defenses.py`.

Build events the way the proxy does: discovery events have
`method="tools/list"` (the template's `_event` helper sets it), so a
defense that checks the method behaves the same in tests and in production.

Prefer `pytest.mark.parametrize` tables of `(case, expected)`, so new
attack variants are one line each.

Add an integration test under `tests/integration/` only when the behaviour
depends on the proxy (for example, a sequence across calls or a restart).
Use `tests/integration/test_defense_extension_e2e.py` as the pattern, and
check outcomes against the mock servers' audit logs, not the proxy's own
claims.

## 6. Measure its value

Unit tests show a rule works on cases its author wrote. Before handing
back, measure what it adds (ADR 0027, decision 3):

- **Benign cost**: run it over the benign corpus (ADR 0027, decision 4) and
  count findings by rule and severity, on the held-out half separately.
  Tune only on the development half. Until the corpus exists, say so and
  report the mock-server definitions only; never present the twins as a
  false-positive measurement.
- **Unique contribution**: which of the repository's attack cases this
  defense catches that no enabled defense already catches. No unique case
  plus a non-zero benign cost means the rule is not added.
- **Cost**: its time on the corpus's largest definition, cold, against the
  2 s deadline.

Refer to corpus definitions by hash and pointer; never quote them.

## 7. Verify before handing back

```sh
uv run ruff check . && uv run ruff format --check .
uv run mypy src fixtures/mock_servers tests/harness
uv run pytest
uv run python -c "from importlib.metadata import entry_points; print(sorted(e.name for e in entry_points(group='mcp_security_proxy.defenses')))"
```

The last command must list the new id. If the defense is enabled in the
reference configs, start the proxy once
(`uv run python -m mcp_security_proxy.app.main --config config/config.stdio.yaml`,
then Ctrl-C) to check it passes startup validation.

`tests/contracts/test_dependency_rules.py` fails if the defense imports
anything internal other than the SDK and its own package. Fix the import;
never change the test.

## 8. Scope of one MR

- One plan MR per MR, and it must match its scope in the plan. A defense MR
  has one defense, or one tightly related rule set, and no core, SDK, or
  other-category changes. Capability changes go in the plan MR that owns
  them, together with that MR's defense (ADR 0024).
- Some plan MRs ship more than one piece. D2 and I1 ship inside S2, and
  C1, D4, T2, E1, I3 and I4 each carry a core change and a defense. Follow the
  plan rather than splitting them.
- In the MR description, give the plan MR id and the layer, and list the
  attacks covered, the benign twins, what's deliberately not covered, any
  new signal types, and the step 6 numbers (benign cost, unique
  contribution, cost).
