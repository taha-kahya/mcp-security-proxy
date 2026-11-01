"""Identity: verify connection credentials and resolve the principal."""

from mcp_security_proxy.core.identity.resolvers import (
    BearerTokenPrincipalResolver,
    IdentityResolver,
    StaticPrincipalResolver,
    UnauthenticatedError,
)
from mcp_security_proxy.core.identity.tasks import PrincipalTaskResolver, TaskResolver
from mcp_security_proxy.core.identity.tokens import StaticTokenVerifier, hash_token

__all__ = [
    "BearerTokenPrincipalResolver",
    "IdentityResolver",
    "PrincipalTaskResolver",
    "StaticPrincipalResolver",
    "StaticTokenVerifier",
    "TaskResolver",
    "UnauthenticatedError",
    "hash_token",
]
