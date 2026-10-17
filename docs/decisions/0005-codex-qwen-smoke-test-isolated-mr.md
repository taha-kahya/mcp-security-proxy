# 0005 — Real-agent smoke test is a separate, non-CI, final MR

Status: Accepted

## Context

Alongside the deterministic scripted harness (0004), a real LLM-driven host was
wanted to validate V1 end-to-end with an actual model making tool-call decisions,
specifically Qwen-3.5 9b, served locally, with Codex CLI as the MCP host.

## Decision

This validation ships as its own final MR (MR7), entirely separate from the six
core V1 MRs, and is **not** wired into CI:

- Qwen-3.5 9b is served locally via an OpenAI-compatible endpoint (Ollama or
  vLLM).
- Codex CLI is pointed at it via a custom `[model_providers.&lt;id&gt;]` entry in
  `~/.codex/config.toml` (`base_url`, `env_key`, `wire_api = "responses"` —
  confirmed supported: custom provider blocks are a documented Codex CLI
  feature for any OpenAI-compatible `/v1/chat/completions`-style endpoint).
- Codex CLI is configured as an MCP client connecting to the Proxy, defaulting to
  Config A (stdio) — see the MR7 runbook for the up-to-date rationale on whether
  Codex's Streamable HTTP MCP client support is mature enough to use Config B
  instead.
- Verification is manual (a human runs the runbook and confirms tool discovery
  and at least one successful read/write/send call); no pytest code is added for
  this MR, and it is never referenced by `tests.yml`.

## Alternatives considered

Folding this into the Config A or Config B MRs was considered and rejected —
mixing a non-reproducible, manual, real-model validation step into an
automated-tests MR would blur what "done" means for that MR and make CI green
status misleading about whether the smoke test had actually been run.

## Consequences

Keeping this isolated means V1's CI-provable acceptance criteria never depend on
real-model availability or determinism; the smoke test is purely additive
evidence, run by a human, on demand.
