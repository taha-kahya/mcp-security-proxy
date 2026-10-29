# Adding a defense

A defense inspects one event and reports what it saw. It never blocks,
forwards, or approves anything itself: Guard turns its report into a
decision using the operator's policy. You need four things, and none of
them is a change to core code:

1. a package under `src/mcp_security_proxy/defenses/<category>/<name>/`,
2. its tests, in the same package,
3. one entry-point line in `pyproject.toml`,
4. a config file in `config/defenses/`.

The sample in
[`defenses/samples/call_budget`](../../src/mcp_security_proxy/defenses/samples/call_budget)
is the working reference for everything below.

## 1. Write the defense

Import only `mcp_security_proxy.sdk` and your own package. A test fails if
a defense imports core, services, or another defense.

```python
from collections.abc import Mapping
from typing import Any

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Event,
    Finding,
    Manifest,
    Result,
    Severity,
    Stage,
)

MANIFEST = Manifest(
    id="my_check",  # must equal the entry-point name
    version="1.0.0",
    sdk_version_range=">=1.0,<2",
    stages=frozenset({Stage.BEFORE_EXECUTION}),
    required_capabilities=frozenset({Capability.HISTORY}),
)


class MyCheck:
    def __init__(self, limit: int) -> None:
        self._limit = limit

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.action is None:
            return Result.not_applicable()
        if len(context.history.operations) < self._limit:
            return Result.completed()
        return Result.completed(
            [
                Finding("my_check.too_many", "sample", Severity.HIGH, "limit reached"),
            ]
        )


def create(settings: Mapping[str, Any]) -> MyCheck:
    """Raise ValueError for invalid settings; the proxy refuses to start."""
    return MyCheck(int(settings["limit"]))
```

**Choosing a stage.** Each stage sees a different event:

- `discovery`: one tool definition (`event.payload` is the definition as
  the server sent it).
- `before_execution`: a call's arguments (`event.payload["arguments"]`)
  and its operator-configured `event.action`.
- `before_delivery`: a call's result (`event.content` holds typed blocks:
  `text`, `image`, `resource`, ..., or `structured`).

**Report what happened, honestly.**

- `Result.completed(findings)`: you inspected it. No findings means clean.
- `Result.not_applicable()`: this event isn't something you check.
- `Result.unsupported("image content")`: you can't inspect this kind of
  content. By default this **blocks**, so never return it to mean "fine".
- You don't need to catch exceptions. Anything you raise, a deadline
  overrun, or a malformed return becomes `failed`, which also blocks by
  default.

**Use only what you declare.** The context gives you only the capabilities
in `required_capabilities` (`registry`, `history`, `policy`,
`private_state`). Using an undeclared one fails the inspection.

**Signals** are observations for other defenses (for example, "sensitive
data seen"). Declare their types in `produced_signals` and set
`producer=MANIFEST.id`. A consumer declares `required_signals`; the Runner
runs producers first and passes their signals in `context.signals`.

**Private state.** Read `context.private_state.get(key)` and propose
`StateChange(key, expected_version=current.version, value=...)` in a
completed result. The core commits it after the inspection. You never
write directly.

## 2. Test it without the proxy

`mcp_security_proxy.sdk.testing` builds events and contexts with fake
capabilities. `make_context` grants exactly what your manifest declares, the
same way the Runner does.

```python
from mcp_security_proxy.sdk import Operation
from mcp_security_proxy.sdk.testing import action, history, make_context, make_event, operation


async def test_blocks_at_the_limit() -> None:
    defense = create({"limit": 1})
    context = make_context(defense.manifest(), history=history(operation()))
    result = await defense.evaluate(make_event(action=action(Operation.WRITE)), context)
    assert result.findings
```

Cover malicious and matched benign cases, plus unsupported content and
missing context. Put tests in `<your package>/tests/`; pytest collects
`src/mcp_security_proxy/defenses` automatically.

## 3. Register it

```toml
# pyproject.toml
[project.entry-points."mcp_security_proxy.defenses"]
my_check = "mcp_security_proxy.defenses.samples.my_check:create"
```

Then run `uv sync` so the entry point is installed.

## 4. Enable, tune, and disable it

```yaml
# config/defenses/my_check.yaml
id: my_check
enabled: true            # false keeps it installed but not running
settings:
  limit: 10
enforcement:             # optional; overrides the policy file's defaults
  findings:
    my_check.too_many: require_approval
  on_failure: block
```

Restart the proxy. It refuses to start if the defense isn't installed,
rejects its settings, needs an SDK version or capability the core doesn't
provide, or requires a signal no enabled defense produces. Overrides that
loosen enforcement are logged as warnings. Enforcement is the operator's
call: a defense package never sets it.

To disable a defense, set `enabled: false` or delete its config file.

## 5. Check it end to end

Every decision record in the audit log lists each defense's inspection:

```json
"inspections": [{"defense_id": "my_check", "defense_version": "1.0.0",
                 "status": "completed", "finding_rule_ids": ["my_check.too_many"]}]
```

and a blocking finding appears in `rule_refs` as
`defense:my_check:my_check.too_many`.

## When the SDK isn't enough

If a check needs something no capability provides (content scanning,
argument-aware tool semantics, or a new stage), don't reach into core. That
needs one reviewed SDK and core extension, which then serves every defense.
