# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A developer tool for detecting security vulnerabilities in MCP servers before deployment. Combines static contract testing with live adversarial simulation to catch tool poisoning, prompt injection, rug pull, and shadowing attacks.

ENS 491/492 final year project — Sabanci University 2026. Team: Ahmet Taha Kahya, Yunus Emre Ulusoy, Emirhan Oguz, Semih Dogan, Burak Ala. Supervisor: Cemal Yilmaz.

## Commands

No code exists yet. Once scaffolded, expected commands will be:

```bash
pip install -e ".[dev]"          # install with dev deps
pytest                           # run all tests
pytest tests/unit/               # unit tests only
pytest tests/integration/        # integration tests (requires a running MCP server)
mcp-tester run --target <url> --layers 1,2 --output sarif
```

## Architecture

Three composable layers. Each is independently runnable. See `docs/architecture.md` for full detail.

**Layer 1 — Contract Testing** (no LLM, ENS 491 core)
Parse MCP tool manifests → auto-generate valid/invalid/boundary test inputs → validate output schema conformance → check error response consistency. Also runs static poisoning signal detection on raw manifests (imperative verbs, secrecy directives, sensitive paths, cross-tool references, full-schema scan beyond `description`).

**Layer 2 — Adversarial Testing** (LLM-assisted, ENS 492 core)
Requires controlling a malicious MCP server. The client under test (Copilot, Cursor, Claude Desktop) connects to the server. The tool observes every tool call the client makes — not model text output. Attack modes: prompt injection into tool outputs, rug pull simulation (manifest hash + mid-session diff), multi-server shadowing, LLM semantic contract checker.

**Layer 3 — Workflow Testing** (stretch)
Multi-step agent scenarios, cross-server contamination. Only if Layers 1 and 2 are complete.

## Module layout

```
manifest_collector/   # fetch real MCP manifests; saves to corpus/
static_analyzer/      # poisoning signal detection on raw manifests (Layer 1 static)
contract_tester/      # input_generator, schema_validator, error_checker (Layer 1 dynamic)
adversarial_engine/   # injection_engine, rug_pull_simulator, shadowing_tester, semantic_checker (Layer 2)
malicious_server/     # FastMCP-based configurable attack server + profiles/
observation_logger/   # intercepts and logs every tool call a client makes
corpus/               # real-world manifests as ground-truth dataset
reports/              # Finding + Report dataclasses; json/html/sarif reporters
```

## Key design decisions

**You control the server, not the client.** The attack flow is: malicious server → poisons client → client takes wrong action. The client is what is being tested. Layer 2 only works if you run `malicious_server/` and point the client at it.

**Observe actions, not text.** This tool tests whether clients execute actions they should not (file reads, writes, network calls) — not whether models repeat injected text. The observation logger intercepts tool calls, not model responses.

**Static first, runtime second.** Layer 1 flags candidates; Layer 2 confirms them. A finding backed by both static detection and live adversarial proof is stronger evidence than either alone.

**Finding severity** — Critical: payload triggers file system or network action, or passive tool demonstrably alters another server. High: silent behavior modification confirmed. Medium: suspicious static signals unconfirmed by live test. Low: unusual schema patterns worth manual review.

## Tech stack

- Python 3.11+, `mcp` official SDK (FastMCP for malicious_server)
- Anthropic SDK (`claude-sonnet-4-6`) for semantic_checker only
- `jsonschema` for schema validation, Jinja2 for HTML reports
- SARIF 2.1.0 (hand-rolled JSON) for GitHub security annotations
- pytest, GitHub Actions

## What this tool does NOT do

- Attack servers you do not own
- Test servers directly — you are the server, the client is what is tested
- Replace `mcp-security-lab` (that repo reproduces known attacks; this repo automates detection)
