"""Resolve the verified principal behind an agent request.

A resolver receives only what the transport attached to the request (the
Starlette request for Streamable HTTP, nothing for stdio). It never reads
the MCP payload, so a principal claimed in `_meta` or tool arguments has no
effect.
"""

from __future__ import annotations

from typing import Protocol

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.requests import HTTPConnection

from mcp_security_proxy.sdk import Principal


class UnauthenticatedError(Exception):
    """No verified principal is attached to the request."""


class IdentityResolver(Protocol):
    def resolve(self, transport_request: object | None) -> Principal: ...


class StaticPrincipalResolver:
    """stdio: whoever launched the proxy process is the caller.

    stdio carries no per-connection credentials, so the principal is fixed by
    configuration. The trust boundary is the OS user that can start the
    process, not anything inside the connection.
    """

    def __init__(self, principal_id: str) -> None:
        self._principal = Principal(id=principal_id, authenticated_by="static_config")

    def resolve(self, transport_request: object | None) -> Principal:
        return self._principal


class BearerTokenPrincipalResolver:
    """Streamable HTTP: the principal the SDK's bearer-auth middleware verified.

    Requests without a valid token are rejected with 401 by that middleware
    before reaching any handler; raising here is a second line of defense in
    case the middleware is ever misconfigured.
    """

    def resolve(self, transport_request: object | None) -> Principal:
        if not isinstance(transport_request, HTTPConnection):
            raise UnauthenticatedError("no HTTP request attached to this message")
        user = transport_request.scope.get("user")
        if not isinstance(user, AuthenticatedUser):
            raise UnauthenticatedError("request was not authenticated")
        return Principal(id=user.access_token.client_id, authenticated_by="bearer_token")
