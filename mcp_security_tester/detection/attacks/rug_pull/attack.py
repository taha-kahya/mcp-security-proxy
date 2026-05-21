from mcp_security_tester.detection.attacks.base import AttackDetector
from mcp_security_tester.detection.attacks.rug_pull.watcher import ManifestWatcher
from mcp_security_tester.core.models import Finding


class RugPullDetector(AttackDetector):
    attack_type = "rug_pull"

    def __init__(self, server_name: str):
        self._watcher = ManifestWatcher(server_name)

    def scan_manifest(self, tools: list[dict]) -> list[Finding]:
        return self._watcher.watch(tools)
