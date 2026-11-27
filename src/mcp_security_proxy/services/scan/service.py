"""The `ScanView` defenses receive: the rule stage, plus the classifier
stage when the operator configured one (ADR 0025, ADR 0026)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import AbstractAsyncContextManager, nullcontext
from typing import Any

from mcp_security_proxy.sdk import ScanResult
from mcp_security_proxy.services.scan.classifier.stage import DefinitionClassifier
from mcp_security_proxy.services.scan.scanner import RuleScanner


class Scan:
    def __init__(self, rules: RuleScanner, classifier: DefinitionClassifier | None = None) -> None:
        self._rules = rules
        self._classifier = classifier

    async def hidden(self, value: Any) -> ScanResult:
        return await self._rules.hidden(value)

    async def instructions(self, value: Any) -> ScanResult:
        return await self._rules.instructions(value)

    async def lookalikes(self, value: Any) -> ScanResult:
        return await self._rules.lookalikes(value)

    async def secrets(self, value: Any) -> ScanResult:
        return await self._rules.secrets(value)

    async def commands(self, value: Any) -> ScanResult:
        return await self._rules.commands(value)

    async def skeleton(self, text: str) -> str:
        return await self._rules.skeleton(text)

    async def skeletons(self, texts: Iterable[str]) -> Mapping[str, str]:
        return await self._rules.skeletons(texts)

    async def poisoning(self, definition: Mapping[str, Any]) -> ScanResult:
        if self._classifier is None:
            return await self._rules.poisoning(definition)
        return self._classifier.result(definition)

    def prepared(
        self, definitions: Iterable[Mapping[str, Any]]
    ) -> AbstractAsyncContextManager[None]:
        """Run the classifier stage ahead of inspection, and keep its grades
        readable for the block; a no-op without one."""
        if self._classifier is None:
            return nullcontext()
        return self._classifier.prepared(definitions)
