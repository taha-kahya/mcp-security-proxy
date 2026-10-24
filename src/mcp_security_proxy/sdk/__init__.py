"""Public contract types shared by core modules, services, and (from V3) defenses.

Depends on nothing else in this package, so every other module can import it
without creating a dependency on core or service implementations.
"""

from mcp_security_proxy.sdk.types import Principal, ToolId

__all__ = ["Principal", "ToolId"]
