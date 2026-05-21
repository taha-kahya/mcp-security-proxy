import hashlib
import json

from mcp_security_tester.detection.attacks.tool_poisoning.analyzer import analyze_manifest
from mcp_security_tester.detection.attacks.tool_poisoning.signals import SENSITIVE_PATHS
from mcp_security_tester.core.models import Finding


class ManifestWatcher:
    def __init__(self, server_name: str):
        self.server_name = server_name
        self._snapshot: dict[str, str] = {}
        self._connected = False

    def watch(self, tools: list[dict]) -> list[Finding]:
        current = {t.get("name", ""): self._hash_tool(t) for t in tools}

        if not self._connected:
            self._snapshot = current
            self._connected = True
            return analyze_manifest(tools)

        return self._diff(current, tools)

    def _diff(self, current: dict[str, str], tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        tool_map = {t.get("name", ""): t for t in tools}

        for name, current_hash in current.items():
            if name not in self._snapshot:
                findings.append(Finding(
                    attack_type="rug_pull",
                    severity="HIGH",
                    tool_name=name,
                    field="manifest",
                    evidence=f"Tool '{name}' appeared after initial approval",
                    signal="rug_pull_new_tool",
                    reproduction_steps=[
                        f"Connect to {self.server_name}.",
                        f"Tool '{name}' was not present at first connect but appeared on re-fetch.",
                    ],
                ))
            elif current_hash != self._snapshot[name]:
                severity = self._rug_pull_severity(tool_map[name])
                findings.append(Finding(
                    attack_type="rug_pull",
                    severity=severity,
                    tool_name=name,
                    field="manifest",
                    evidence=f"Tool '{name}' definition changed after initial approval",
                    signal="rug_pull_changed",
                    reproduction_steps=[
                        f"Connect to {self.server_name} and approve tool '{name}'.",
                        "On a subsequent session, the tool definition changed silently.",
                        "The agent re-uses the tool without re-validation.",
                    ],
                ))

        for name in self._snapshot:
            if name not in current:
                findings.append(Finding(
                    attack_type="rug_pull",
                    severity="MEDIUM",
                    tool_name=name,
                    field="manifest",
                    evidence=f"Tool '{name}' was removed after initial approval",
                    signal="rug_pull_removed_tool",
                    reproduction_steps=[
                        f"Tool '{name}' was present at first connect but disappeared on re-fetch.",
                    ],
                ))

        return findings

    def _hash_tool(self, tool: dict) -> str:
        canonical = json.dumps(tool, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _rug_pull_severity(self, tool: dict) -> str:
        text = json.dumps(tool).lower()
        if any(p.lower() in text for p in SENSITIVE_PATHS):
            return "CRITICAL"
        return "HIGH"
