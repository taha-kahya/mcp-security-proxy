"""Proxy's inbound, agent-facing MCP listener over Streamable HTTP.

Every request must carry a bearer token accepted by `token_verifier`; the
SDK's auth middleware answers anything else with 401 before it reaches a
handler. The SDK only installs that middleware alongside an `AuthSettings`,
whose `issuer_url` is required but unused here: with no
`resource_server_url` and no authorization-server provider, no OAuth
metadata routes are exposed (see 0011).
"""

from __future__ import annotations

import uvicorn
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.lowlevel import Server
from pydantic import AnyHttpUrl


async def serve_streamable_http(
    server: Server, host: str, port: int, token_verifier: TokenVerifier
) -> None:
    auth = AuthSettings(
        issuer_url=AnyHttpUrl(f"http://{host}:{port}"),
        resource_server_url=None,
    )
    app = server.streamable_http_app(host=host, auth=auth, token_verifier=token_verifier)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    await uvicorn.Server(config).serve()
