# 0004 — Automated V1 acceptance tests use a scripted harness, not an LLM agent

Status: Accepted

## Context

The architecture diagram's "Agent" role is a protocol role (whatever speaks the
MCP client protocol to the Proxy), not necessarily an LLM. V1's acceptance
criteria are precise and mechanical: discovery and calls work across both mock
servers, errors/cancellations behave correctly per transport, and no request is
ever routed to the wrong server.

## Decision

Automated V1 acceptance tests (`tests/integration/`, `tests/contracts/`) are
driven by a deterministic, scripted MCP test-harness client
(`tests/harness/client.py`) that sends exact request sequences and asserts exact
responses, errors, and cancellations. No LLM is involved in the automated suite.

A real LLM-driven host is still part of V1, but only as a separate, manual,
non-CI smoke test — see 0005.

## Alternatives considered

Driving CI acceptance tests with a real MCP host app (e.g. Codex CLI or Claude
Code) backed by an LLM was considered. Rejected for automated testing: an LLM's
tool-call decisions are not reproducible enough to assert exact routing/error/
cancellation outcomes in CI, even though the host app itself correctly implements
the MCP client protocol.

## Consequences

The scripted harness is CI-specific scaffolding, intentionally kept inside
`tests/harness/` rather than the top-level `mock_servers/` package, since it is
not reused by the Codex/Qwen smoke test in MR7 — Codex CLI itself plays the host
role there instead.
