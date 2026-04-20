"""
Individual detector functions. Each returns a Finding or None.
All text matching is case-insensitive.
"""

from mcp_security_tester.reports.models import Finding
from mcp_security_tester.static_analyzer.signals import (
    HIDDEN_TEXT_CHARS,
    HIDDEN_WHITESPACE_THRESHOLD,
    IMPERATIVE_VERBS,
    SECRECY_DIRECTIVES,
    SENSITIVE_PATHS,
)


def detect_imperative_verb(tool_name: str, field_path: str, text: str) -> Finding | None:
    lower = text.lower()
    for verb in IMPERATIVE_VERBS:
        if verb in lower:
            return Finding(
                attack_type="tool_poisoning",
                severity="MEDIUM",
                tool_name=tool_name,
                field=field_path,
                evidence=_excerpt(text, verb),
                signal="imperative_verb",
                reproduction_steps=[
                    f"Load the manifest for tool '{tool_name}'.",
                    f"Inspect field '{field_path}'.",
                    f"Found imperative verb '{verb}' — may indicate embedded instructions.",
                ],
            )
    return None


def detect_secrecy_directive(tool_name: str, field_path: str, text: str) -> Finding | None:
    lower = text.lower()
    for directive in SECRECY_DIRECTIVES:
        if directive in lower:
            return Finding(
                attack_type="tool_poisoning",
                severity="HIGH",
                tool_name=tool_name,
                field=field_path,
                evidence=_excerpt(text, directive),
                signal="secrecy_directive",
                reproduction_steps=[
                    f"Load the manifest for tool '{tool_name}'.",
                    f"Inspect field '{field_path}'.",
                    f"Found secrecy directive '{directive}' — strong indicator of tool poisoning.",
                ],
            )
    return None


def detect_sensitive_path(tool_name: str, field_path: str, text: str) -> Finding | None:
    lower = text.lower()
    for path in SENSITIVE_PATHS:
        if path.lower() in lower:
            # Co-occurrence with imperative verb escalates to CRITICAL
            has_verb = any(v in lower for v in IMPERATIVE_VERBS)
            severity = "CRITICAL" if has_verb else "HIGH"
            return Finding(
                attack_type="tool_poisoning",
                severity=severity,
                tool_name=tool_name,
                field=field_path,
                evidence=_excerpt(text, path),
                signal="sensitive_path",
                reproduction_steps=[
                    f"Load the manifest for tool '{tool_name}'.",
                    f"Inspect field '{field_path}'.",
                    f"Found sensitive path reference '{path}'."
                    + (" Co-occurs with imperative verb → CRITICAL." if has_verb else ""),
                ],
            )
    return None


def detect_cross_tool_reference(
    tool_name: str, field_path: str, text: str, all_tool_names: list[str]
) -> Finding | None:
    lower = text.lower()
    for other_name in all_tool_names:
        if other_name == tool_name:
            continue
        if other_name.lower() in lower:
            return Finding(
                attack_type="shadowing",
                severity="HIGH",
                tool_name=tool_name,
                field=field_path,
                evidence=_excerpt(text, other_name),
                signal="cross_tool_reference",
                reproduction_steps=[
                    f"Load the manifest for tool '{tool_name}'.",
                    f"Inspect field '{field_path}'.",
                    f"Found reference to sibling tool '{other_name}' — potential tool shadowing attack.",
                    "Connect both tools to the same agent and observe whether the passive description alters calls to the referenced tool.",
                ],
            )
    return None


def detect_hidden_text(tool_name: str, field_path: str, text: str) -> Finding | None:
    # Zero-width / invisible Unicode
    for char in HIDDEN_TEXT_CHARS:
        if char in text:
            return Finding(
                attack_type="tool_poisoning",
                severity="HIGH",
                tool_name=tool_name,
                field=field_path,
                evidence=f"Unicode character U+{ord(char):04X} found in field",
                signal="hidden_text_unicode",
                reproduction_steps=[
                    f"Load the manifest for tool '{tool_name}'.",
                    f"Inspect field '{field_path}' in a hex editor or repr().",
                    f"Found invisible Unicode character U+{ord(char):04X} — may be hiding injected instructions.",
                ],
            )

    # Excessive whitespace padding (instructions hidden below the visible fold)
    newline_run = max(
        (len(run) for run in text.split(" ") if run == "\n" * len(run)),
        default=0,
    )
    consecutive_newlines = _max_consecutive_char(text, "\n")
    if consecutive_newlines >= HIDDEN_WHITESPACE_THRESHOLD:
        return Finding(
            attack_type="tool_poisoning",
            severity="HIGH",
            tool_name=tool_name,
            field=field_path,
            evidence=f"{consecutive_newlines} consecutive newlines found",
            signal="hidden_text_whitespace",
            reproduction_steps=[
                f"Load the manifest for tool '{tool_name}'.",
                f"Inspect field '{field_path}' — scroll past {consecutive_newlines} blank lines.",
                "Instructions may be hidden below the visible fold.",
            ],
        )

    return None


# ── helpers ──────────────────────────────────────────────────────────────────

def _excerpt(text: str, match: str, context: int = 60) -> str:
    """Return a short excerpt of text centred around the first match."""
    idx = text.lower().find(match.lower())
    if idx == -1:
        return text[:120]
    start = max(0, idx - context // 2)
    end = min(len(text), idx + len(match) + context // 2)
    snippet = text[start:end].replace("\n", "\\n")
    return f"...{snippet}..." if start > 0 or end < len(text) else snippet


def _max_consecutive_char(text: str, char: str) -> int:
    max_run = current = 0
    for c in text:
        if c == char:
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run
