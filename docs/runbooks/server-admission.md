# Server admission runbook

Status: Draft. Owner: Emirhan Oguz.

Run this before adding an MCP server to a proxy config, and again before
changing its pinned version. It covers what the proxy can't check at
runtime: who publishes the server, which version you run, and whether its
dependencies have known vulnerabilities. The attacks it addresses are in
[Environment attacks](../attacks/environment.md).

## 1. Identify the server

- [ ] Find the publisher's source repository and confirm the package name
      links to it (npm or PyPI "repository" field, container image labels).
      Watch for lookalike names: compare letter by letter with the name in
      the project's own README.
- [ ] Note who maintains it and whether releases are tagged in the
      repository.
- [ ] Read the tool list it exposes (start it once in a sandbox and send
      `tools/list`), and the README. Every tool should be one you expect.

## 2. Choose and pin a version

- [ ] Pick an exact version, never a range or `latest`.
  - npm via `npx`: `package@2.4.1`
  - PyPI via `uvx`: `package==2.4.1`
  - container: `image@sha256:<digest>`
- [ ] For a binary or script run directly, record its SHA-256
      (`sha256sum /opt/mcp/server` or `Get-FileHash -Algorithm SHA256`) in
      the server's `sha256` setting once E1 has merged.
- [ ] Record why this version was chosen in the change that adds it.

## 3. Scan it

- [ ] Run NVIDIA SkillSpector against the package or its MCP manifest.
      Review every finding; poisoned descriptions and unpinned dependencies
      are the ones to act on.
- [ ] Check dependencies for known vulnerabilities with
      [OSV-Scanner](https://google.github.io/osv-scanner/) against the
      package's lockfile, or look the package and version up on
      [osv.dev](https://osv.dev/).
- [ ] A server that fails either check is not added until the finding is
      fixed upstream or accepted in writing by the operator.

## 4. Classify and connect

- [ ] Add each tool to `config/tools.yaml` with its operation (`read`,
      `write`, `send`, `execute`). An unlisted tool is `unknown`, which
      several defenses treat like a write or a send.
- [ ] Prefer stdio, or `https://` for remote servers. Use plain `http://`
      only for loopback.
- [ ] Add the server to the policy with the least access each principal
      needs.
- [ ] Start the proxy once and check its audit log: no
      `direct_hidden_metadata` findings (or, once D1 has merged,
      `direct_claim_mismatch` findings) you haven't reviewed.

## 5. Re-admit on change

- [ ] Repeat steps 2 to 4 for every version change. Once T2 has merged, a
      `notifications/tools/list_changed` from a running server is graded
      against the approved definition; treat a `capability_added` finding
      as a new admission.
