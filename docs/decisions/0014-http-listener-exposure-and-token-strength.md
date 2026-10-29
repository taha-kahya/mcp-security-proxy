# 0014 — HTTP listener exposure and bearer-token strength

Status: Accepted

## Context

The Streamable HTTP listener (0011) speaks plain HTTP. Bearer tokens and all
tool arguments and results cross the socket unencrypted. On the default
`agent_host: 127.0.0.1` that traffic never leaves the machine, but
`agent_host` is configurable, and `0.0.0.0` or a LAN address would expose it
to anyone who can observe the network.

Separately, the config stores only unsalted SHA-256 digests of tokens. That
keeps a leaked config from revealing usable credentials only when the tokens
themselves cannot be guessed: a short or human-chosen token can be recovered
from its digest by brute force or a wordlist.

## Decision

**The listener must stay on loopback, or sit behind TLS.** The proxy does not
terminate TLS itself. When `agent_host` is not a loopback address
(`127.0.0.0/8`, `::1`, or `localhost`), startup logs a warning but continues,
so deliberate deployments behind a TLS-terminating reverse proxy on another
interface still work. Any other hostname counts as non-loopback, since it may
resolve off-host.

**Tokens must be random, with at least 256 bits of entropy.** Generate them
with a CSPRNG, for example:

```sh
python3 -c 'import hashlib, secrets; t = secrets.token_urlsafe(32); print(t); print(hashlib.sha256(t.encode()).hexdigest())'
```

The first line is the token for the client; the second is the
`token_sha256` for the config. The reference config's `dev-token-change-me`
is a placeholder for local development only and must be replaced.

## Alternatives considered

- **Refusing to start off loopback** — rejected; it would block the legitimate
  reverse-proxy setup, and a warning already states the requirement.
- **Built-in TLS** (passing certificates to uvicorn) — deferred; it adds
  certificate management that a reverse proxy already handles well.
- **Salted, slow hashes (Argon2, bcrypt)** — unnecessary for 256-bit random
  tokens, and they would add a per-request cost. The proxy cannot enforce
  token entropy anyway, since it only ever sees digests.

## Consequences

Token strength is an operator obligation, documented here and in the README.
A non-loopback bind is visible in the startup log but not prevented.
