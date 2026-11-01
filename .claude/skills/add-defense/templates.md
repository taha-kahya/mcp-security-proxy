# Templates

Replace the placeholders:

| Placeholder | Example |
| --- | --- |
| `<category>` | `direct` |
| `<name>` | `hidden_instructions` |
| `<Name>` | `HiddenInstructions` |
| `<attack>` | `instructions hidden in tool descriptions` |
| `<rule>` / `<RULE>` | `file_read` / `FILE_READ` |
| `<signal_type>` / `<SIGNAL>` | `hidden_instructions` / `HIDDEN_INSTRUCTIONS` |
| `<STAGE>` | `DISCOVERY`, `BEFORE_EXECUTION`, or `BEFORE_DELIVERY` |

Delete anything the defense doesn't use; keep comments sparse.

## `<name>/__init__.py`

```python
"""<Category> defense: <attack>."""

from mcp_security_proxy.defenses.<category>.<name>.defense import (
    DEFENSE_ID,
    <RULE>_RULE,
    <Name>Defense,
    <Name>Settings,
    create,
)

__all__ = ["DEFENSE_ID", "<RULE>_RULE", "<Name>Defense", "<Name>Settings", "create"]
```

## `<name>/defense.py`

```python
"""Detect <attack>.

Inspects <what> at <stage>. Does not cover <known gaps>.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_security_proxy.sdk import (
    Context,
    Event,
    Finding,
    Manifest,
    Result,
    Severity,
    Signal,
    Stage,
)

DEFENSE_ID = "<category>_<name>"
<RULE>_RULE = f"{DEFENSE_ID}.<rule>"
# Only if the defense produces a signal (agreed with its consumers, step 2).
<SIGNAL>_SIGNAL = "<signal_type>"

# Content stages only: the block types this defense actually inspects.
INSPECTED_BLOCK_TYPES = frozenset({"text"})

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.0,<2",
    stages=frozenset({Stage.<STAGE>}),
    required_capabilities=frozenset(),
    produced_signals=frozenset({<SIGNAL>_SIGNAL}),
)


class <Name>Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class <Name>Defense:
    def __init__(self, settings: <Name>Settings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if not self._applies_to(event):
            return Result.not_applicable()
        # Content stages: a block this defense can't read was not inspected,
        # so the event is `unsupported`, never `completed`. Delete for
        # `discovery` and `before_execution` defenses.
        uninspected = sorted({block.type for block in event.content} - INSPECTED_BLOCK_TYPES)
        if uninspected:
            return Result.unsupported(f"{', '.join(uninspected)} content")
        findings = [*self._<rule>(event)]
        return Result.completed(findings, signals=self._signals(findings))

    def _applies_to(self, event: Event) -> bool:
        return event.stage is Stage.<STAGE>

    def _<rule>(self, event: Event) -> list[Finding]:
        # Evidence names a location, never the inspected text itself.
        return []

    def _signals(self, findings: list[Finding]) -> list[Signal]:
        if not findings:
            return []
        return [
            Signal(
                type=<SIGNAL>_SIGNAL,
                schema_version=1,
                producer=DEFENSE_ID,
                value={"rule_ids": sorted({f.rule_id for f in findings})},
                evidence_refs=tuple(ref for f in findings for ref in f.evidence_refs),
            )
        ]


def create(settings: Mapping[str, Any]) -> <Name>Defense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return <Name>Defense(<Name>Settings.model_validate(settings))
```

A defense that produces no signal drops `<SIGNAL>_SIGNAL`, `_signals`,
`signals=` and `produced_signals`. A defense that consumes one declares
`required_signals` and reads `context.signals`; a missing signal means
`unknown`, never safe.

A finding looks like:

```python
Finding(
    rule_id=<RULE>_RULE,
    category="<category>",
    severity=Severity.HIGH,
    reason="description asks the agent to read a credential file",
    evidence_refs=("/inputSchema/properties/path/description",),
)
```

`evidence_refs` are JSON Pointers into what was inspected: the definition
at `discovery` (`/description`, `/inputSchema/properties/path/description`,
`/annotations/title`), the arguments at `before_execution`
(`/arguments/url`), and the content block at `before_delivery`
(`/content/0/text`). Add a character range after the pointer when it helps,
as in `/description#120-180`. They never contain the inspected text.

## `<name>/tests/test_<name>.py`

One test per row of the matrix in SKILL.md step 5. Delete the content-block
test for `discovery` and `before_execution` defenses, and the signal test if
the defense produces none.

```python
"""<Name>, tested with SDK helpers only: no proxy, no servers.

Cases come from the attack taxonomy and public descriptions, never from the
evaluation experiments (SKILL.md step 1).
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.<category>.<name> import DEFENSE_ID, <RULE>_RULE, create
from mcp_security_proxy.defenses.<category>.<name>.defense import MANIFEST
from mcp_security_proxy.sdk import (
    ContentBlock,
    ContentSource,
    Event,
    InspectionStatus,
    Provenance,
    Result,
    Stage,
)
from mcp_security_proxy.sdk.testing import TEST_TOOL, make_context, make_event

STAGE = Stage.<STAGE>


def _event(stage: Stage = STAGE, **fields: Any) -> Event:
    """Like the proxy's events: discovery events are `tools/list`."""
    method = "tools/list" if stage is Stage.DISCOVERY else "tools/call"
    return make_event(stage, method=method, **fields)


def _block(block_type: str, **data: Any) -> ContentBlock:
    provenance = Provenance(TEST_TOOL.server_id, TEST_TOOL, ContentSource.TOOL_RESULT)
    return ContentBlock(block_type, {"type": block_type, **data}, provenance)


async def _evaluate(event: Event, **settings: Any) -> Result:
    defense = create(settings)
    return await defense.evaluate(event, make_context(defense.manifest()))


MALICIOUS = [
    pytest.param({}, id="<short case name>"),
]
BENIGN_TWINS = [
    pytest.param({}, id="<matching benign case name>"),
]


@pytest.mark.parametrize("payload", MALICIOUS)
async def test_flags_malicious_cases(payload: dict[str, Any]) -> None:
    result = await _evaluate(_event(payload=payload))
    assert [f.rule_id for f in result.findings] == [<RULE>_RULE]


@pytest.mark.parametrize("payload", BENIGN_TWINS)
async def test_allows_matched_benign_cases(payload: dict[str, Any]) -> None:
    result = await _evaluate(_event(payload=payload))
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_other_stages_are_not_applicable() -> None:
    for other in set(Stage) - MANIFEST.stages:
        result = await _evaluate(_event(other))
        assert result.status is InspectionStatus.NOT_APPLICABLE


async def test_content_it_cannot_read_is_unsupported() -> None:
    result = await _evaluate(_event(content=[_block("text", text="<benign>"), _block("image")]))
    assert result.status is InspectionStatus.UNSUPPORTED


@pytest.mark.parametrize(
    "event",
    [
        pytest.param(_event(), id="empty payload"),
        # e.g. no `action`, no consumed signal, empty history
    ],
)
async def test_missing_input_has_the_documented_behaviour(event: Event) -> None:
    result = await _evaluate(event)
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


@pytest.mark.parametrize("settings", [{"unknown_setting": 1}])
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)


@pytest.mark.parametrize("payload", MALICIOUS)
async def test_produced_signals_are_declared_and_attributed(payload: dict[str, Any]) -> None:
    result = await _evaluate(_event(payload=payload))
    assert result.signals
    for signal in result.signals:
        assert signal.producer == DEFENSE_ID
        assert signal.type in MANIFEST.produced_signals


@pytest.mark.parametrize("payload", MALICIOUS)
async def test_rule_ids_are_namespaced_by_the_defense(payload: dict[str, Any]) -> None:
    result = await _evaluate(_event(payload=payload))
    assert all(f.rule_id.startswith(DEFENSE_ID + ".") for f in result.findings)
```

## `pyproject.toml`

```toml
[project.entry-points."mcp_security_proxy.defenses"]
<category>_<name> = "mcp_security_proxy.defenses.<category>.<name>:create"
```

## `config/defenses/<category>_<name>.yaml`

```yaml
# <attack>. See src/mcp_security_proxy/defenses/<category>/<name>.
id: <category>_<name>
enabled: true
settings: {}
```
