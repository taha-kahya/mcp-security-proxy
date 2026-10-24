"""Pure-logic tests for principal resolution and static bearer-token verification."""

from __future__ import annotations

import pytest
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.requests import Request

from mcp_security_proxy.core.identity import (
    BearerTokenPrincipalResolver,
    StaticPrincipalResolver,
    StaticTokenVerifier,
    UnauthenticatedError,
    hash_token,
)
from mcp_security_proxy.sdk import Principal


def _http_request(user: object | None = None) -> Request:
    scope: dict[str, object] = {"type": "http", "headers": []}
    if user is not None:
        scope["user"] = user
    return Request(scope)


def _authenticated_user(principal_id: str) -> AuthenticatedUser:
    return AuthenticatedUser(AccessToken(token="t", client_id=principal_id, scopes=[]))


def test_static_resolver_returns_configured_principal_regardless_of_request() -> None:
    resolver = StaticPrincipalResolver("local-user")
    expected = Principal(id="local-user", authenticated_by="static_config")

    assert resolver.resolve(None) == expected
    assert resolver.resolve(_http_request(_authenticated_user("someone-else"))) == expected


def test_bearer_resolver_returns_the_verified_principal() -> None:
    principal = BearerTokenPrincipalResolver().resolve(_http_request(_authenticated_user("alice")))
    assert principal == Principal(id="alice", authenticated_by="bearer_token")


@pytest.mark.parametrize("transport_request", [None, object(), _http_request()])
def test_bearer_resolver_rejects_requests_without_a_verified_user(
    transport_request: object | None,
) -> None:
    with pytest.raises(UnauthenticatedError):
        BearerTokenPrincipalResolver().resolve(transport_request)


async def test_token_verifier_maps_a_known_token_to_its_principal() -> None:
    verifier = StaticTokenVerifier({hash_token("alice-token"): "alice"})
    access = await verifier.verify_token("alice-token")
    assert access is not None and access.client_id == "alice"


async def test_token_verifier_rejects_unknown_tokens_and_raw_digests() -> None:
    digest = hash_token("alice-token")
    verifier = StaticTokenVerifier({digest: "alice"})

    assert await verifier.verify_token("wrong-token") is None
    assert await verifier.verify_token(digest) is None
