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

## 1. Pin down the design with the user first

Before writing code, settle these with the user. Explain each one plainly,
with a concrete malicious example and its benign twin:

| Decision | Example |
| --- | --- |
| Attack and category | "A tool description tells the agent to read `~/.ssh/id_rsa`" → `direct` |
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
and write a different one.

## 2. Check the SDK is enough

Use only `mcp_security_proxy.sdk` (and third-party libraries). If the check
needs something no capability provides, **stop and tell the user**. Never
import core or services, and never add a workaround inside the defense.
ADR 0020 lists the planned V4 capabilities, each delivered as its own MR:

- Scan (`instructions`, `secrets`, sensitivity)
- argument-aware tool adapters (`resource`, `destination`, `sensitivity`)
- `Registry.approved` and re-discovery
- a server-identity view
- a stage for errors and notifications

Check `src/mcp_security_proxy/sdk/` for what exists now; the list above may
be partly merged.

**Model-based checks belong to Scan.** A defense has no I/O and a 2 s
deadline, so a classifier, an embedding model or a semantic check can't run
inside it. Those are the job of the Scan capability (ADR 0020, MR 1), which
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

## 6. Verify before handing back

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

## 7. Scope of one MR

- One defense, or one tightly related rule set, per MR. No core, SDK, or
  other-category changes in the same MR. Capability changes are their own
  MR (ADR 0020).
- In the MR description, list the attacks covered, the benign twins, what's
  deliberately not covered, and any new signal types.
