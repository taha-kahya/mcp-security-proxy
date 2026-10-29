# Templates

Replace the placeholders:

| Placeholder | Example |
| --- | --- |
| `<category>` | `direct` |
| `<name>` | `hidden_instructions` |
| `<Name>` | `HiddenInstructions` |
| `<attack>` | `instructions hidden in tool descriptions` |
| `<rule>` / `<RULE>` | `file_read` / `FILE_READ` |
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
    Stage,
)

DEFENSE_ID = "<category>_<name>"
<RULE>_RULE = f"{DEFENSE_ID}.<rule>"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.0,<2",
    stages=frozenset({Stage.<STAGE>}),
    required_capabilities=frozenset(),
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
        findings = [*self._<rule>(event)]
        return Result.completed(findings)

    def _applies_to(self, event: Event) -> bool:
        return event.stage is Stage.<STAGE>

    def _<rule>(self, event: Event) -> list[Finding]:
        # Evidence names a location, never the inspected text itself.
        return []


def create(settings: Mapping[str, Any]) -> <Name>Defense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return <Name>Defense(<Name>Settings.model_validate(settings))
```

A finding looks like:

```python
Finding(
    rule_id=<RULE>_RULE,
    category="<category>",
    severity=Severity.HIGH,
    reason="description asks the agent to read a credential file",
    evidence_refs=("description",),
)
```

For content at `before_delivery`, check `block.type` for each block in
`event.content`, and return `Result.unsupported("<type> content")` for types
the defense can't inspect.

## `<name>/tests/test_<name>.py`

```python
"""<Name>, tested with SDK helpers only: no proxy, no servers."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.defenses.<category>.<name> import <RULE>_RULE, create
from mcp_security_proxy.sdk import Event, InspectionStatus, Result, Stage
from mcp_security_proxy.sdk.testing import make_context, make_event


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
    result = await _evaluate(make_event(Stage.<STAGE>, payload=payload))
    assert [f.rule_id for f in result.findings] == [<RULE>_RULE]


@pytest.mark.parametrize("payload", BENIGN_TWINS)
async def test_allows_matched_benign_cases(payload: dict[str, Any]) -> None:
    result = await _evaluate(make_event(Stage.<STAGE>, payload=payload))
    assert result.status is InspectionStatus.COMPLETED and result.findings == ()


async def test_other_stages_are_not_applicable() -> None:
    other = next(s for s in (Stage.DISCOVERY, Stage.BEFORE_DELIVERY) if s is not Stage.<STAGE>)
    result = await _evaluate(make_event(other))
    assert result.status is InspectionStatus.NOT_APPLICABLE


@pytest.mark.parametrize("settings", [{"unknown_setting": 1}])
def test_invalid_settings_raise_value_error(settings: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        create(settings)
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
