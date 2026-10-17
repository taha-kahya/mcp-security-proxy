"""Message validation contract, independent of transport. Implementation lands in MR4."""

from __future__ import annotations

from typing import Protocol


class MessageCodec(Protocol):
    """Validates and preserves structure of MCP protocol messages."""
