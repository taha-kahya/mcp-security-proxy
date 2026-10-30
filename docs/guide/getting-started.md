# Getting started

The proxy is a Python application. It runs locally with two harmless mock MCP servers, so it can be tried without connecting any real service.

## Install

Requires Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/taha-kahya/mcp-security-proxy.git
cd mcp-security-proxy
uv sync --locked --all-extras --dev
```

Run the checks:

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy src fixtures/mock_servers tests/harness
uv run pytest
```

## Run the proxy

There are two reference configurations. Each runs the client side, the proxy and both mock servers over one transport.

=== "stdio (Config A)"

    ```sh
    uv run python -m mcp_security_proxy.app.main --config config/config.stdio.yaml
    ```

    The proxy starts both mock servers as subprocesses and speaks MCP on its own standard input and output. Any stdio MCP client can use it by running this command. The caller is the configured `identity.stdio_principal`, `local-agent`.

=== "Streamable HTTP (Config B)"

    ```sh
    uv run python -m mcp_security_proxy.app.main --config config/config.http.yaml
    ```

    The proxy starts both mock servers over HTTP (ports 8001 and 8002) and listens on `http://127.0.0.1:9000/mcp`. Clients must send `Authorization: Bearer dev-token-change-me`; requests without a valid token receive HTTP 401.

    The development token is public. For any other use, generate a random token of at least 256 bits and put its SHA-256 digest in `identity.bearer_tokens`. This prints a new token, then its digest:

    ```sh
    python3 -c 'import hashlib, secrets; t = secrets.token_urlsafe(32); print(t); print(hashlib.sha256(t.encode()).hexdigest())'
    ```

    The listener speaks plain HTTP. Keep it on `127.0.0.1` or put a TLS-terminating reverse proxy in front ([ADR 0014](../decisions/0014-http-listener-exposure-and-token-strength.md)).

The proxy appends its audit log to `proxy_audit.jsonl` in the working directory. Each mock server writes the calls it actually received to `server_a_audit.jsonl` and `server_b_audit.jsonl`, an independent record of what reached the servers.

## Connect a client

Most MCP hosts accept a server entry with a command and arguments. For the stdio configuration, point the entry at the proxy, with the repository as the working directory:

```json
{
  "mcpServers": {
    "security-proxy": {
      "command": "uv",
      "args": ["run", "python", "-m", "mcp_security_proxy.app.main", "--config", "config/config.stdio.yaml"],
      "cwd": "/path/to/mcp-security-proxy"
    }
  }
}
```

The exact format depends on the host. The [Codex CLI runbook](../runbooks/codex-qwen-smoke-test.md) walks through a complete setup with a local LLM.

The client sees seven tools, such as `server_a__read_record` and `server_b__send_message`. Calling `server_b__send_message` returns an error that names a decision ID, and `server_b__slow_write` is reported as an unknown tool. [How it works](how-it-works.md) explains both.

## Change the policy

The policy is a YAML file, `config/policies/default.yaml` by default:

```yaml
schema_version: 1
principals:
  local-agent:
    - tool: server_a/*                  # every tool on server_a
      effect: allow
    - tool: server_b/read_record
      effect: allow
    - tool: server_b/write_record
      effect: allow
    - tool: server_b/send_message       # listed, refused until Approval (V5)
      effect: require_approval
    # server_b/slow_write is not listed, so it is hidden
```

Each rule names a tool as `server_id/tool_name` or `server_id/*` and an effect, `allow` or `require_approval`. An exact rule overrides a wildcard for the same server. Restart the proxy after a change.

The proxy refuses to start if the file is invalid or a rule matches no tool. It starts with a warning if a policy principal has no configured identity, or a configured principal has no rules (it is denied every tool). The full model is in [ADR 0010](../decisions/0010-policy-model-and-default-deny.md).
