"""Static bearer-token verification for the agent-facing Streamable HTTP listener.

Configuration stores only SHA-256 digests of tokens, so a leaked config file
does not leak usable credentials. Implements the SDK's `TokenVerifier`
protocol, so the SDK's own middleware handles header parsing and 401s.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping

from mcp.server.auth.provider import AccessToken


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class StaticTokenVerifier:
    def __init__(self, principal_ids_by_token_sha256: Mapping[str, str]) -> None:
        self._principal_ids_by_digest = dict(principal_ids_by_token_sha256)

    async def verify_token(self, token: str) -> AccessToken | None:
        principal_id = self._principal_id_for(hash_token(token))
        if principal_id is None:
            return None
        return AccessToken(token=token, client_id=principal_id, scopes=[])

    def _principal_id_for(self, digest: str) -> str | None:
        # Compare against every entry in constant time, without stopping early.
        match = None
        for known_digest, principal_id in self._principal_ids_by_digest.items():
            if hmac.compare_digest(known_digest, digest):
                match = principal_id
        return match
