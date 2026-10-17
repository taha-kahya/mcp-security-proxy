# 0001 — Language, MCP SDK, and tooling for V1

Status: Accepted

## Context

`docs/architecture.md` requires the language, MCP SDK/protocol version, initial
transport, target client, and local-vs-remote server scope to be confirmed before
implementation, rather than silently chosen.

## Decision

- **Language/runtime:** Python, pinned to 3.12 locally (`.python-version`),
  `requires-python >= 3.11` in `pyproject.toml`. No version matrix for V1.
- **MCP SDK:** the official `mcp` PyPI package, pinned `>=2.3.0,<3.0.0` (2.3.0 was
  the latest release at the time this was checked).
- **Env/dependency manager:** `uv`, matching the conventions used by the upstream
  `mcp` SDK itself.
- **Tests:** `pytest` + `pytest-asyncio` (the SDK is async/anyio-based).
- **Lint/format:** `ruff`. **Type-check:** `mypy` on `src/`, `mock_servers/`,
  `tests/harness/`, at moderate (not full) strictness to avoid friction at the SDK
  boundary.
- **Config validation:** `pydantic` v2 — already a transitive dependency of `mcp`.
- **ASGI server** for the Streamable HTTP config (MR5): `uvicorn`.
- **CI:** a new `tests.yml` GitHub Actions workflow, added alongside the existing
  CodeQL/super-linter/issue-summarizer workflows without modifying them.

## Alternatives considered

- TypeScript + the official TypeScript MCP SDK — viable, but Python was preferred
  for consistency with the async orchestration style and the security/scanning
  libraries expected in later phases.
- `poetry` instead of `uv` — rejected; `uv` is faster and is what the upstream SDK
  itself uses, reducing friction when reading its examples.
- A `make`/`just` task runner — rejected as unnecessary; `uv run ...` commands are
  documented directly instead.

## Consequences

Package name is `mcp_security_proxy` rather than bare `app`/`core` (the names used
directly in the architecture doc's illustrative layout), since those are unsafe
top-level import names for an installable package. The doc's internal module
structure (`app/`, `core/proxy/{transport,codec,routing}`, ...) is otherwise
preserved exactly, one level deeper under `src/mcp_security_proxy/`.
