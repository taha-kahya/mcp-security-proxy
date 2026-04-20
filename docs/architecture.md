# Architecture

Three composable layers — each independently buildable and runnable. Every layer addresses a distinct class of attacks from the documented CVE and incident record.

---

## Layer 1 — Contract Testing

**No LLM required. Core ENS 491 deliverable.**

### What it does

1. **Manifest parsing** — parse MCP tool definitions: name, description, input schema (parameter names, types, enum values), output schema, error responses.
2. **Test input generation** — auto-generate three classes of inputs per tool:
   - Valid inputs (happy path)
   - Invalid inputs (wrong types, missing required fields, null values)
   - Boundary inputs (oversized strings, path traversal sequences like `../../../etc/passwd`, deeply nested objects)
3. **Output schema validation** — on every tool call, validate the response against the declared output schema. Silent failures (tool returns 200 but ignores the contract) are flagged.
4. **Error consistency checking** — send 10+ invalid input variants and verify that error responses are consistent. Tools that silently swallow errors or return different status codes for the same error class are flagged.

### What it catches

- Schema violations and undeclared fields in responses
- Silent failures — tool accepts garbage input and returns garbage output with no error
- Inconsistent error handling — same invalid input returns different error shapes across calls
- Path traversal inputs being accepted without sanitisation (direct path to CVE-2025-68143 class)

### Key design decision

Layer 1 is entirely rule-based. No model calls, no network beyond the target MCP server. A developer with no API keys can run it. This is intentional — it must be zero-friction enough to go in a CI pipeline.

---

## Layer 2 — Adversarial Testing

**LLM-assisted where noted. Core ENS 492 deliverable.**

### What it does

1. **Prompt injection engine** — inject known payloads into tool return values (XML-tagged directives, `<IMPORTANT>` blocks, whitespace-padded instructions, Unicode obfuscation). Verify whether the connected agent follows embedded instructions rather than treating output as data.
2. **Full-Schema Poisoning scanner** — scan all manifest fields beyond `description`: type, parameter names, enum values, return field names. Any field containing imperative verbs, secrecy directives (`do not inform`, `do not log`), sensitive path mentions (`/etc/`, `~/.ssh/`), or cross-tool references is flagged. (Formal terminology from CyberArk 2025.)
3. **Rug pull simulation** — hash the full tool manifest (description, schema, permissions) at first load. Modify the tool definition mid-session. Verify whether the connected agent re-validates before proceeding. Severity escalates if the new definition adds file system access, network calls, or new permission scopes.
4. **Multi-server shadowing tests** — connect a trusted server and a malicious server simultaneously. Scan all tool descriptions for references to other tools' names. Verify that the malicious server's passive descriptions cannot alter calls made to the trusted server.
5. **Semantic contract checker (LLM)** — given a tool's natural language description and a transcript of its actual calls, ask a model whether the observed behavior matches the declared intent. Flags semantic drift that rule-based checks miss.
6. **Destructive action safety** — verify that tools with write, delete, or exfiltration capabilities require explicit confirmation and cannot be triggered silently by injected instructions.

### What it catches

- Tool poisoning via description field (Attack 1 — Invariant Labs / CVE-2025-68143)
- Rug pull after user approval (Attack 2 — CVE-2025-68143/44/45)
- Indirect prompt injection via tool output (Attack 3 — GitHub MCP data breach)
- Tool shadowing across servers (Attack 4 — Elastic Security Labs)

### Malicious server

Layer 2 requires a configurable MCP server (`malicious_server/`) that can serve any combination of:
- Poisoned tool manifests
- Injected tool responses
- Mid-session manifest updates (rug pull)
- Shadow tool definitions targeting other servers

The client under test (Copilot, Claude Desktop, Cursor) connects to this server. The tool logs every tool call the client makes, not just model output text. **You control the server; the client is what is being tested.**

---

## Layer 3 — Workflow Testing (Stretch Goal)

**ENS 492 stretch — only if Layers 1 and 2 are complete ahead of schedule.**

### What it does

1. **Multi-step agent scenarios** — define expected tool call sequences (create → write → read → delete). Detect deviation: incorrect ordering, skipped steps, unexpected extra calls.
2. **Infinite loop detection** — flag tools that cause the agent to call them repeatedly without termination.
3. **Cross-server contamination** — in multi-server setups, verify that a malicious server's state cannot bleed into a trusted server's execution path.

---

## CI/CD + Reports

Applied across all layers:

- **GitHub Actions plugin** — runs automatically on every commit against the target MCP server
- **Severity ranking** — Critical / High / Medium / Low with full reproduction steps
- **JSON output** — machine-readable findings for downstream tooling
- **HTML output** — human-readable report
- **SARIF output** — inline GitHub security annotations (integrates with GitHub Advanced Security)
- **Reusable artifact storage** — same test suite re-runs across server versions for regression tracking

---

## Module overview

```
manifest_collector/     → fetches and stores real MCP server manifests
static_analyzer/        → poisoning signal detection on raw manifests (no server call needed)
contract_tester/        → Layer 1: input gen + schema validation + error consistency
adversarial_engine/     → Layer 2: injection + rug pull + shadowing + semantic checker
malicious_server/       → serves configurable attack profiles for Layer 2 tests
observation_logger/     → intercepts and logs every tool call a client makes
corpus/                 → collected real-world manifests as ground-truth dataset
reports/                → HTML / JSON / SARIF output generation
```

Each module is independently importable. Running the full tool is:

```bash
mcp-tester run --target <server-url> --layers 1,2 --output sarif
```
