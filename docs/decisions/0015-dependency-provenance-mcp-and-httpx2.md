# 0015 — Dependency provenance: mcp, mcp-types, and httpx2

Status: Accepted

## Context

`uv.lock` resolves `mcp==2.3.0`, which pulls in `mcp-types` and `httpx2` /
`httpcore2`; the familiar `httpx` is absent. For a security proxy, its
dependencies are part of what must be trusted, and a less-common package in
place of a well-known one is what a typosquat or dependency-confusion attack
looks like. A review asked for the provenance of these packages to be
verified before merging V2.

## Decision

The packages were verified on 2026-10-26 and are kept:

- **`mcp` 2.3.0 and `mcp-types` 2.3.0** carry PEP 740 provenance attestations
  on PyPI binding both files to the `modelcontextprotocol/python-sdk`
  repository's `publish-pypi.yml` workflow (`release` environment). They are
  the official SDK and its split-out wire types.
- **`httpx2` / `httpcore2`** are not chosen by this project: the official SDK
  itself declares `httpx2>=2.10.0`. They are published from
  `github.com/pydantic/httpx2`, owned by the Pydantic organization, with
  httpx's original author as author, released through PyPI Trusted Publishing
  (GitHub OIDC). They carry **no** PEP 740 attestations, so this link rests on
  the publishing setup and the SDK's declaration rather than a per-file
  signature.
- Every sdist and wheel hash in `uv.lock` for these four packages matches the
  SHA-256 digest PyPI publishes.

`pyproject.toml` declares only `mcp` directly and adds no HTTP client of its
own. Installs should use `uv sync --locked` so the hash-pinned lock is
enforced.

## Alternatives considered

- **Pinning `mcp` to a release that still used `httpx`** — rejected; it trades
  a verified dependency for an outdated SDK.
- **Vendoring the SDK** — rejected; it moves the update burden here without
  improving provenance.

## Consequences

Upgrading `mcp` (or anything that changes these packages in the lock) should
repeat the checks: attestations via
`https://pypi.org/integrity/<project>/<version>/<file>/provenance`, the
upstream `pyproject.toml`, and lock hashes against PyPI digests. If `httpx2`
starts publishing attestations, prefer checking those.
