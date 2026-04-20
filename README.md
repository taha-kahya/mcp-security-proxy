# MCP Security Tester

A developer tool for detecting security vulnerabilities in MCP servers **before deployment**. Combines static contract testing with live adversarial simulation to catch tool poisoning, prompt injection, rug pull, and shadowing attacks — the full attack surface documented in 2025/2026 CVEs and academic benchmarks.

ENS 491/492 Final Year Project — Sabanci University — 2026  
Team: Ahmet Taha Kahya, Yunus Emre Ulusoy, Emirhan Oguz, Semih Dogan, Burak Ala  
Supervisor: Cemal Yilmaz

---

## Why this exists

Every known MCP vulnerability to date was found through **manual security research** — isolated PoCs and post-incident analysis (CVE-2025-68143/44/45, Snyk CVEs, GitHub data breach May 2025). No automated framework exists that a developer can run against their server before shipping it. This project builds that framework.

See [docs/references.md](docs/references.md) for the full academic and CVE evidence base.

---

## Architecture

Three composable layers, each independently runnable:

| Layer | Name | Requires LLM | Status |
|-------|------|--------------|--------|
| 1 | Contract Testing | No | ENS 491 core deliverable |
| 2 | Adversarial Testing | Yes (optional) | ENS 492 core deliverable |
| 3 | Workflow Testing | Yes | ENS 492 stretch goal |

**Layer 1 — Contract Testing**  
Parse MCP tool manifests; auto-generate valid, invalid, and boundary test inputs; validate output schema conformance; check error response consistency. Entirely rule-based. Catches schema violations, silent failures, path traversal inputs (→ CVE-2025-68143).

**Layer 2 — Adversarial Testing**  
Prompt injection engine, Full-Schema Poisoning detection, rug pull simulation, multi-server shadowing tests, LLM semantic contract checker, destructive action safety. Catches all four attack types from documented real-world incidents.

**Layer 3 — Workflow Testing (stretch)**  
Multi-step agent scenarios, cross-server contamination verification, unexpected destructive call detection.

See [docs/architecture.md](docs/architecture.md) for detail.

---

## Attack coverage

| Attack | Real-world case | Layer |
|--------|----------------|-------|
| Tool Poisoning | CVE-2025-68143, Invariant Labs / Cursor (Apr 2025) | 1 + 2 |
| Rug Pull | CVE-2025-68143/44/45, mcp-server-git | 2 |
| Indirect Prompt Injection | GitHub MCP data breach (May 2025) | 2 |
| Tool Shadowing | Elastic Security Labs (Sep 2025), WhatsApp exfil | 2 + 3 |

See [docs/attacks.md](docs/attacks.md) for payloads and detection logic.

---

## Project structure

```
mcp-security-tester/
├── manifest_collector/     # scrape real public MCP server manifests
├── static_analyzer/        # poisoning signal detection (Layer 1 static)
├── contract_tester/        # schema validation + boundary testing (Layer 1)
├── adversarial_engine/     # injection, rug pull, shadowing (Layer 2)
├── malicious_server/       # configurable MCP server for attack injection
├── observation_logger/     # log every tool call clients make
├── corpus/                 # collected real-world manifests as dataset
├── reports/                # HTML / JSON / SARIF output
├── docs/                   # project documentation
└── .github/workflows/      # CI/CD plugin
```

---

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for the full semester-by-semester plan.

- **ENS 491 Wk 1–9**: Layer 1 complete (manifest parser → contract tester → design sign-off)
- **ENS 491 Wk 10–14**: Adversarial taxonomy, first evaluation on 3–5 public servers
- **ENS 492 Wk 1–9**: Layer 2 complete (injection engine → rug pull → shadowing → LLM checker)
- **ENS 492 Wk 8–11**: CI/CD plugin, SARIF reports
- **ENS 492 Wk 11–14**: Full evaluation, open-source release, final paper

---

## Documentation

- [Architecture](docs/architecture.md) — layer-by-layer design
- [Attacks](docs/attacks.md) — attack mechanisms, payloads, detection logic
- [Implementation Plan](docs/implementation-plan.md) — module breakdown with file structure
- [Roadmap](docs/roadmap.md) — semester timeline and deliverables
- [References](docs/references.md) — academic papers, CVEs, industry reports
