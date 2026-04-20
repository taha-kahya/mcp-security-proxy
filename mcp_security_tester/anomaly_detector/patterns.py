import fnmatch
from dataclasses import dataclass


@dataclass
class SequencePattern:
    name: str
    description: str
    trigger_tool: str       # glob-style pattern, e.g. "read_*"
    following_tool: str     # glob-style pattern for the suspicious follow-up
    max_gap_calls: int = 3  # how many intervening calls still counts as a sequence
    severity: str = "HIGH"

    def matches_trigger(self, tool_name: str) -> bool:
        return fnmatch.fnmatch(tool_name, self.trigger_tool)

    def matches_following(self, tool_name: str) -> bool:
        return fnmatch.fnmatch(tool_name, self.following_tool)


SEQUENCE_PATTERNS: list[SequencePattern] = [
    SequencePattern(
        name="read_then_send",
        description="File read immediately followed by an outbound send/message call — classic exfiltration sequence.",
        trigger_tool="read_*",
        following_tool="send_*",
        max_gap_calls=2,
        severity="HIGH",
    ),
    SequencePattern(
        name="read_then_http",
        description="File read followed by an HTTP/fetch call — potential data exfiltration.",
        trigger_tool="read_*",
        following_tool="*http*",
        max_gap_calls=2,
        severity="HIGH",
    ),
    SequencePattern(
        name="read_then_create_message",
        description="File read followed by create_message — potential injection-driven exfiltration.",
        trigger_tool="read_*",
        following_tool="create_message",
        max_gap_calls=3,
        severity="CRITICAL",
    ),
    SequencePattern(
        name="list_then_bulk_read",
        description="Directory listing followed by many read calls — potential bulk data harvesting.",
        trigger_tool="list_*",
        following_tool="read_*",
        max_gap_calls=1,
        severity="MEDIUM",
    ),
]


# Tools that should never be called without explicit user confirmation
HIGH_RISK_TOOLS: list[str] = [
    "delete_*", "remove_*", "drop_*",   # destructive
    "send_*", "email_*", "message_*",   # outbound
    "*exec*", "*shell*", "*command*",   # code execution
    "*token*", "*credential*",          # credential access
]
