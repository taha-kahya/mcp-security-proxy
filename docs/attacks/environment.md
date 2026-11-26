# Environment attacks

Status: Draft. Owner: Emirhan Oguz.

This category covers how servers are obtained, launched and reached: the
package or binary a stdio server runs, the connection to a remote server,
and which servers are connected at all. What a connected server's tools say
is Direct; what its content says is Indirect.

Every example in this doc was written for it from the public sources listed.
A held-out evaluation exists for malicious server registration in the
research repository; its servers, names and results are not design input for
this doc or for the defenses built from it.

## Attacks

The first two types come from the plan's Part 1 table. "Malicious server
registration" is ADR 0022's, listed here so the category is complete.

### Tampered or unpinned server

- **How it works.** A stdio server is launched from a package runner or a
  binary on disk. With no version pin (`npx some-server`, `uvx some-server`,
  `docker run image:latest`), every start pulls whatever is published now,
  so a compromised maintainer account, a typosquatted name or a malicious
  update runs with the user's privileges on the next start. A binary on disk
  can be replaced by anything that can write to its path.
- **Malicious example.** `servers: [{id: mail, command: npx, args: ["-y",
  "mail-mcp-server"]}]`. A new release of `mail-mcp-server` adds a hidden
  copy of every outgoing message to an outside address; the proxy starts it
  on the next restart.
- **Benign twins.**
  - `args: ["-y", "mail-mcp-server@2.4.1"]`, a pinned version the operator
    reviewed.
  - `command: /opt/mcp/mail-server` with a configured SHA-256 that matches
    the file.
  - `command: python, args: ["-m", "fixtures.mock_servers.server_a"]`, a
    module from the proxy's own locked environment.
- **Where the proxy sees it.** At startup, in core: the server entry's
  `command` and `args`, and the bytes of the file `command` resolves to. A
  defense can't read files, so E1 hashes in core and exposes the result as
  `ServerRecord.integrity` for policy and an Environment defense at
  `discovery`.
- **Evasions to expect.** A pinned version that is itself malicious (the
  pin only stops silent change); a range (`^2.4.1`) that looks pinned; a
  pinned runner whose dependencies float; a hash pin on `npx` itself, which
  says nothing about the package it downloads; a wrapper script that pins
  nothing inside.
- **Public sources.**
  - JFrog, [CVE-2025-6514: critical mcp-remote RCE vulnerability](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
    (July 2025): a widely used MCP package, run unpinned through `npx`,
    gave remote code execution until users updated.
  - Model Context Protocol specification, [Security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
    (2025-06-18): local servers run with the user's privileges.
  - OpenSSF, [SLSA](https://slsa.dev/): pinning and provenance for
    build artifacts.
  - NVIDIA SkillSpector, rules RP1 (unpinned `npx`, `uvx`, `pip`, `docker`)
    and SC4 (known-vulnerable dependencies); Arbitus's SHA-256 pin before
    start (prior art in the plan's Part 1; Arbitus ideas only, AGPL-3.0).

### Insecure remote server connection

- **How it works.** A Streamable HTTP upstream is reached over plain
  `http://` on a network the operator doesn't control, so anyone on the path
  can read the traffic or rewrite tool definitions and results. Or the URL
  points somewhere it shouldn't: a link-local or cloud metadata address, or
  an internal host the proxy can reach but the operator didn't mean to
  expose.
- **Malicious example.** `url: "http://mcp.tools-hub.example/mcp"`, so
  definitions and results cross the internet unencrypted.
- **Benign twins.**
  - `url: "http://127.0.0.1:8001/mcp"`, a local server (as in the reference
    HTTP config).
  - `url: "https://mcp.tools-hub.example/mcp"`.
- **Where the proxy sees it.** At startup, the server entry's `url`,
  classified as loopback, private, link-local, cloud metadata or external by
  the destination classifier (S3), without a DNS lookup.
- **Evasions to expect.** A hostname that resolves to a private address
  (classified as unknown, never safe); IPv4-mapped IPv6 or decimal IP
  forms; an `https://` URL with certificate checks turned off elsewhere.
- **Public sources.**
  - Model Context Protocol specification, [Transports: security warning](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#security-warning)
    (2025-06-18).
  - OWASP, [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

### Malicious server registration

- **How it works.** The attacker gets a server connected: a lookalike of a
  known server, an extra entry added to the config, or a known server whose
  launch was changed. Its tools then compete with, or shadow, an approved
  server's tools.
- **Malicious example.** An entry `id: github` that launches
  `npx -y gíthub-mcp` (with an accented "í") next to the operator's approved
  GitHub server.
- **Benign twin.** Two approved servers with unrelated names and tools.
- **Where the proxy sees it.** `discovery`, through ADR 0022's server
  identity view.
- **Public sources and rules.** See
  [ADR 0022](../decisions/0022-server-identity-view-and-registration-defense.md)
  and the [registration defense design](../design/server-identity-and-registration-defense.md).

## Detection

Rule ids marked *proposed* are settled with the user in that MR's design
check and may change there; this table is updated in the same MR.

| Rule (planned id) | Attack | Evidence it uses | Severity | MR |
| --- | --- | --- | --- | --- |
| `environment_server_integrity.unpinned_package` *proposed* | Unpinned server | Launch command is a package runner (`npx`, `uvx`, `pipx run`, `docker run`, `bunx`) and the package has no exact version or digest | medium | E1 |
| `environment_server_integrity.unverified_binary` *proposed* | Tampered server | `integrity` is `unpinned`: no SHA-256 configured for a stdio command that isn't a package runner or the proxy's own interpreter | low | E1 |
| (startup error, not a rule) *proposed* | Tampered server | `integrity` would be `mismatch`: the file's SHA-256 differs from the pin, so core refuses to start that server | n/a | E1 |
| `environment_remote_url.plain_http` *proposed* | Insecure connection | `url` scheme `http` and the host isn't loopback | high | E2 |
| `environment_remote_url.internal_destination` *proposed* | Insecure connection | Host classified link-local or cloud metadata | high | E2 |
| `environment_remote_url.unclassified_host` *proposed* | Insecure connection | Hostname the classifier can't place | low | E2 |
| ADR 0022's four rules | Registration | Server identity view | per ADR 0022 | ADR 0022 MR |

- **Why a mismatch stops startup.** A changed binary is not a finding to
  weigh; the operator pinned it to say "only this". Failing closed at
  startup, as for a bad config, keeps it from ever running.
- **Signals.** None produced or consumed.
- **Missing evidence.** `integrity` is `not_applicable` for HTTP servers and
  `unpinned` when no hash is set, never `verified` by default.
- **Capabilities needed** that the SDK does not have yet: the server
  identity view (ADR 0022) with `integrity` (E1), and the destination
  classifier (S3) for E2.

## Not covered

- **Vulnerable dependencies (CVEs).** Lookups need the network, so they
  stay out of the proxy's hot path; the
  [server admission runbook](../runbooks/server-admission.md) runs them
  before a server is added.
- **A pinned version that is malicious from the start.** Pinning stops
  silent change, not a bad first choice; the admission runbook is the
  control.
- **What a server does once running** (its traffic, files, processes).
  Out of scope for a protocol proxy; use OS sandboxing.
- **Signature checks (cosign, Sigstore).** Not planned for V4; a hash pin
  covers the same tampering case for binaries the operator vetted.

## Test cases

One line per case, for each rule's parametrized tests. Malicious first,
then its benign twin.

**E1, `environment_server_integrity`:**

- `command: npx, args: ["-y", "mail-mcp-server"]` → `unpinned_package`
- `command: npx, args: ["-y", "mail-mcp-server@2.4.1"]` → clean
- `command: npx, args: ["-y", "@scope/mail-mcp@^2.4.1"]` → `unpinned_package` (a range is not a pin)
- `command: npx, args: ["-y", "@scope/mail-mcp@2.4.1"]` → clean
- `command: uvx, args: ["mail-mcp-server"]` → `unpinned_package`
- `command: uvx, args: ["mail-mcp-server==2.4.1"]` → clean
- `command: docker, args: ["run", "-i", "ghcr.io/acme/mail:latest"]` → `unpinned_package`
- `command: docker, args: ["run", "-i", "ghcr.io/acme/mail@sha256:<64 hex>"]` → clean
- `command: /opt/mcp/mail-server`, no `sha256` → `unverified_binary`
- `command: /opt/mcp/mail-server`, matching `sha256` → clean
- `command: /opt/mcp/mail-server`, wrong `sha256` → startup error naming the server, no finding
- `command: python, args: ["-m", "fixtures.mock_servers.server_a"]` → clean (the proxy's own interpreter)
- an HTTP server → `not_applicable`

**E2, `environment_remote_url`** (after S3 and E1):

- `url: http://mcp.tools-hub.example/mcp` → `plain_http`
- `url: https://mcp.tools-hub.example/mcp` → clean
- `url: http://127.0.0.1:8001/mcp` → clean
- `url: https://169.254.169.254/mcp` → `internal_destination`
- `url: https://10.0.4.2/mcp` → clean (private, operator-run)
