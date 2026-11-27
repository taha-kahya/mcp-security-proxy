"""The text the classifier reads: a fixed serialization of a tool definition.

This must match the serialization the checkpoint was trained on (`ser-1`)
character for character, or its scores and thresholds no longer apply.
Its output is pinned by golden tests (ADR 0026). Change it only together
with a new checkpoint and a new `SERIALIZATION_VERSION`.

    tool: <name>
    title: <title>                         (only if present)
    annotation title: <annotations.title>  (only if present)
    description: <description>             (only if present)
    parameters:                            (only if the input schema has properties)
    - <path> (<type>; required; title: t; enum: a | b; default: x; const: y): <description>

`<path>` is the property name; a nested property is `parent.child`, an array
element is `parent[]`, and a branch of `anyOf`, `oneOf` or `allOf` keeps the
path of its parent. Left out, as in training: `annotations` hints,
`outputSchema`, `_meta`, `icons`, `execution` and numeric constraints. Those
fields are not graded by the classifier; other Scan stages inspect them.

Proxy definitions are frozen (read-only mappings, tuples), so the input is
thawed first and the training code's `dict` and `list` checks apply as is.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any

from mcp_security_proxy.sdk import thaw

SERIALIZATION_VERSION = "ser-1"

_BRANCH_KEYS = ("anyOf", "oneOf", "allOf")

_Node = tuple[str, dict[str, Any], bool]


def _type_of(node: dict[str, Any]) -> str:
    t = node.get("type")
    if isinstance(t, list):
        return "|".join(str(x) for x in t)
    if isinstance(t, str):
        return t
    for key in _BRANCH_KEYS:
        if key in node:
            return key
    return "any"


def _scalar(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _walk(node: Any, path: str, required: bool) -> Iterator[_Node]:
    """Yield (path, node, required) for every schema node below a property, depth first."""
    if not isinstance(node, dict):
        return
    yield path, node, required
    props = node.get("properties")
    if isinstance(props, dict):
        req = node.get("required")
        req = req if isinstance(req, list) else []
        for name, child in props.items():
            yield from _walk(child, f"{path}.{name}" if path else name, name in req)
    items = node.get("items")
    if isinstance(items, dict):
        yield from _walk(items, f"{path}[]", False)
    elif isinstance(items, list):
        for child in items:
            yield from _walk(child, f"{path}[]", False)
    for key in _BRANCH_KEYS:
        branches = node.get(key)
        if isinstance(branches, list):
            for child in branches:
                yield from _walk(child, path, False)


def _schema_nodes(definition: dict[str, Any]) -> Iterator[_Node]:
    schema = definition.get("inputSchema")
    if not isinstance(schema, dict):
        return
    # The root is not a parameter; start at its properties and branches.
    props = schema.get("properties")
    if isinstance(props, dict):
        req = schema.get("required")
        req = req if isinstance(req, list) else []
        for name, child in props.items():
            yield from _walk(child, name, name in req)
    for key in _BRANCH_KEYS:
        branches = schema.get(key)
        if isinstance(branches, list):
            for child in branches:
                yield from _walk(child, "", False)


def serialize_tool(frozen: Mapping[str, Any]) -> str:
    definition: dict[str, Any] = thaw(frozen)
    lines = [f"tool: {definition.get('name', '')}"]
    if isinstance(definition.get("title"), str):
        lines.append(f"title: {definition['title']}")
    ann = definition.get("annotations")
    if isinstance(ann, dict) and isinstance(ann.get("title"), str):
        lines.append(f"annotation title: {ann['title']}")
    if isinstance(definition.get("description"), str):
        lines.append(f"description: {definition['description']}")
    params: list[str] = []
    for path, node, required in _schema_nodes(definition):
        if not path:
            continue
        attrs = [_type_of(node)]
        if required:
            attrs.append("required")
        if isinstance(node.get("title"), str):
            attrs.append(f"title: {node['title']}")
        if isinstance(node.get("enum"), list):
            attrs.append("enum: " + " | ".join(_scalar(v) for v in node["enum"]))
        if "default" in node:
            attrs.append(f"default: {_scalar(node['default'])}")
        if "const" in node:
            attrs.append(f"const: {_scalar(node['const'])}")
        desc = node.get("description") if isinstance(node.get("description"), str) else ""
        params.append(f"- {path} ({'; '.join(attrs)}): {desc}".rstrip())
    if params:
        lines.append("parameters:")
        lines.extend(params)
    return "\n".join(lines)
