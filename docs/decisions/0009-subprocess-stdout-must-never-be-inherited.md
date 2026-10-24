# 0009 — Spawned upstream subprocess stdout/stderr must never be inherited

Status: Accepted

## Context

While building Config B, spawning a mock server over Streamable HTTP via
`asyncio.create_subprocess_exec(command, *args)` without redirecting its
standard streams caused the agent-facing stdio connection (Config A) to
break: every `tools/call` and discovery round-trip started failing with
`Failed to parse JSONRPC message from server`. The cause, confirmed by
reproducing it directly: the spawned mock server's uvicorn process inherited
the proxy's own stdout file descriptor, so its access-log lines (e.g.
`INFO:     127.0.0.1:... "POST /mcp HTTP/1.1" 200 OK`) were interleaved
directly into the same pipe the agent was reading the proxy's own JSON-RPC
responses from, corrupting the stream.

## Decision

Every subprocess the proxy spawns — regardless of which transport it will be
reached over — must have `stdout` and `stderr` explicitly redirected
(`asyncio.subprocess.DEVNULL` for V1; a real log sink is a later-phase
concern, not V1 scope) rather than inherited. This applies even when the
*proxy's own* agent-facing transport is Streamable HTTP rather than stdio:
the rule is about never accidentally sharing a file descriptor with a
subprocess's own unrelated output, not specifically about stdio protocol
framing, so it is enforced unconditionally rather than only when
`agent_transport == "stdio"`.

`core/proxy/transport/stdio_client.py`'s approach (`mcp.client.stdio.stdio_client`)
was never affected: the SDK's own stdio transport already creates dedicated
pipes per subprocess rather than inheriting the parent's stdio. This bug was
specific to the hand-written `streamable_http_client.spawn_streamable_http_upstream`,
which has been fixed to pass `stdout=DEVNULL, stderr=DEVNULL` explicitly.

## Consequences

Any future transport adapter or defense-support process the proxy spawns
must follow the same rule. This is exactly the kind of protocol-correctness
detail `docs/architecture.md` calls out generally ("Maintain correct protocol
behavior... do not stream unchecked fragments"); here it manifests as a
subprocess file-descriptor hygiene requirement rather than a framing one.
