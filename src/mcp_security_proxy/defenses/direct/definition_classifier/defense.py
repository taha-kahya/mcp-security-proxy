"""Tool definitions that Scan's classifier stage grades as poisoned.

Tool poisoning puts instructions for the model in a tool's definition: a
description that tells the agent to read `~/.ssh/id_rsa` and pass it in a
parameter, or to send every message to another address. Phrase rules
(`direct_hidden_metadata`) catch such text when it is hidden or uses known
wording; a reworded instruction needs a model. Scan's classifier stage (ADR
0026) grades the whole definition once, before inspection and outside the
deadline, and this defense reports its grade:

- `critical`: the definition aims at credentials, exfiltration or code
  execution;
- `high`: it instructs the model against the user;
- `medium`: it is suspicious but the classifier sees no clear harm.

The grade becomes the finding's severity; the operator's policy decides
what each severity does (by default high and critical block, medium needs
approval). A definition the classifier has not scored, including one
longer than the model's 8192-token window, raises `ScanError`, so the
inspection is reported failed rather than clean.

Does not cover: tool results (the classifier reads definitions only), and server instructions from
`initialize`. Scores are not calibrated probabilities, so every finding has
the same confidence; the evidence names the whole definition because the
classifier does not localise.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

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

DEFENSE_ID = "direct_definition_classifier"
CATEGORY = "direct"
CRITICAL_RULE = f"{DEFENSE_ID}.critical"
HIGH_RULE = f"{DEFENSE_ID}.high"
MEDIUM_RULE = f"{DEFENSE_ID}.medium"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.2,<2",
    stages=frozenset({Stage.DISCOVERY}),
    required_capabilities=frozenset({Capability.SCAN, Capability.SCAN_CLASSIFIER}),
)

# classifier level -> (rule id, severity, reason); reasons never quote the
# inspected text.
LEVELS: Mapping[str, tuple[str, Severity, str]] = {
    "critical": (
        CRITICAL_RULE,
        Severity.CRITICAL,
        "classifier grades this tool definition as critical poisoning",
    ),
    "high": (
        HIGH_RULE,
        Severity.HIGH,
        "classifier grades this tool definition as high-severity poisoning",
    ),
    "medium": (
        MEDIUM_RULE,
        Severity.MEDIUM,
        "classifier grades this tool definition as suspicious",
    ),
}

# The classifier grades the definition as a whole.
WHOLE_DEFINITION = ""


class DefinitionClassifierSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DefinitionClassifierDefense:
    def __init__(self, settings: DefinitionClassifierSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.DISCOVERY or event.method != "tools/list":
            return Result.not_applicable()
        result = await context.scan.poisoning(event.payload)
        findings = []
        for match in result.matches:
            level = LEVELS.get(match.label or "")
            if level is None:
                # An unknown grade must not pass as clean; the Runner
                # reports the inspection as failed.
                raise ValueError("classifier returned an unknown level")
            rule, severity, reason = level
            findings.append(Finding(rule, CATEGORY, severity, reason, (WHOLE_DEFINITION,)))
        return Result.completed(findings)


def create(settings: Mapping[str, Any]) -> DefinitionClassifierDefense:
    return DefinitionClassifierDefense(DefinitionClassifierSettings.model_validate(settings))
