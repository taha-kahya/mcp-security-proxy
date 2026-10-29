"""Content-addressed versions: a digest of a value's canonical JSON form.

Key order and formatting do not change the digest; any change in content
does. Used for policy, tool-definition, and tool-semantics versions.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcp_security_proxy.sdk.frozen import thaw


def canonical_digest(value: Any) -> str:
    canonical = json.dumps(thaw(value), sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
