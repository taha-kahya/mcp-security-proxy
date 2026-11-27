"""Replace flagged fields of a tool definition with a proxy notice (plan MR D5).

When the operator's enforcement maps a finding to `redact`, the agent still
sees the tool, its name and its unflagged fields, but every flagged text
field is replaced by `NOTICE`, so the flagged text never reaches the model.
Calls to a redacted tool need approval (ADR 0016), which blocks until V5.

A finding's evidence names the field by JSON Pointer, optionally with a
character range (`/description#120-180`); the whole field is replaced. A
pointer that can't be redacted safely makes the tool hidden instead, never
exposed with the flagged text: no reference at all, the tool's `name`, the whole definition, a
mapping key (`#key`), a value that isn't a string, or one that doesn't
resolve.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from mcp_security_proxy.sdk import thaw

NOTICE = "[withheld by mcp-security-proxy: flagged by a security check]"
_UNREDACTABLE = frozenset({"", "/name"})


def _tokens(pointer: str) -> list[str]:
    return [t.replace("~1", "/").replace("~0", "~") for t in pointer.split("/")[1:]]


def redact(definition: Mapping[str, Any], refs: Iterable[str]) -> dict[str, Any] | None:
    """A copy of `definition` with each referenced string replaced by `NOTICE`,
    or None when any reference can't be redacted, or when there is nothing to
    redact: `redact` without evidence (an inspection that failed or couldn't
    read the content) would otherwise expose uninspected text as "redacted".
    """
    refs = list(refs)
    if not refs:
        return None
    redacted: dict[str, Any] = thaw(definition)
    for ref in refs:
        pointer, _, suffix = ref.partition("#")
        if suffix.startswith("key") or pointer in _UNREDACTABLE or not pointer.startswith("/"):
            return None
        *parents, last = _tokens(pointer)
        node: Any = redacted
        for token in parents:
            node = _child(node, token)
            if node is None:
                return None
        if isinstance(node, dict) and isinstance(node.get(last), str):
            node[last] = NOTICE
        elif isinstance(node, list) and last.isdigit() and int(last) < len(node):
            if not isinstance(node[int(last)], str):
                return None
            node[int(last)] = NOTICE
        else:
            return None
    return redacted


def _child(node: Any, token: str) -> Any:
    if isinstance(node, dict):
        return node.get(token)
    if isinstance(node, list) and token.isdigit() and int(token) < len(node):
        return node[int(token)]
    return None
