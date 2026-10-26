# Architecture Decision Records

Lightweight ADRs documenting non-obvious decisions made while implementing the phases
defined in `docs/architecture.md`. Added incrementally as decisions are made, not
written retroactively at the end of a phase.

Use `0000-template.md` as the starting point for a new record. Number sequentially.

## Index

| ID | Title | Status |
| --- | --- | --- |
| [0001](0001-language-runtime-and-tooling.md) | Language, MCP SDK, and tooling for V1 | Accepted |
| [0002](0002-dual-transport-scope.md) | V1 targets stdio and Streamable HTTP as two independent full configs | Accepted |
| [0003](0003-mock-server-hosting-subprocess.md) | Proxy spawns mock servers as local subprocesses | Accepted |
| [0004](0004-scripted-harness-over-llm-agent.md) | Automated V1 acceptance tests use a scripted harness, not an LLM agent | Accepted |
| [0005](0005-codex-qwen-smoke-test-isolated-mr.md) | Real-agent smoke test is a separate, non-CI, final MR | Accepted |
| [0006](0006-mock-server-http-port-allocation.md) | Mock server default ports and test port allocation for Streamable HTTP | Accepted |
| [0007](0007-tool-identity-correlation-and-stdio-failure-semantics.md) | Tool identity disambiguation, correlation scope, and stdio connection-failure semantics | Accepted |
| [0008](0008-streamable-http-scope-and-port-allocation.md) | Streamable HTTP session/resumability scope and multi-process port allocation | Accepted |
| [0009](0009-subprocess-stdout-must-never-be-inherited.md) | Spawned upstream subprocess stdout/stderr must never be inherited | Accepted |
| [0010](0010-policy-model-and-default-deny.md) | V2 policy model: per-principal tool allowlist, default deny | Accepted |
| [0011](0011-identity-per-transport-and-no-task-boundary.md) | Identity per transport, and no task boundary in V2 | Accepted |
| [0012](0012-decision-semantics-and-denial-responses.md) | Decision semantics and what the agent sees on denial | Accepted |
| [0013](0013-audit-records-masking-and-fail-closed.md) | Audit records: what is logged, masking, and failing closed | Accepted |
| [0014](0014-http-listener-exposure-and-token-strength.md) | HTTP listener exposure and bearer-token strength | Accepted |
