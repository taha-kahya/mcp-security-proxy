# 0002 — V1 targets stdio and Streamable HTTP as two independent full configs

Status: Accepted

## Context

`docs/architecture.md` asks for an initial transport to be selected for V1, and
notes that "Authentication depends on deployment and transport; do not assume an
HTTP authorization design applies unchanged to local stdio." Two transports were
wanted in scope from the start rather than deferring the second to a later phase.

## Decision

V1 implements **two full, independent end-to-end configurations** rather than
mixing transports within a single run:

- **Config A:** Agent &lt;-&gt; Proxy &lt;-&gt; ServerA/ServerB, entirely over stdio.
- **Config B:** Agent &lt;-&gt; Proxy &lt;-&gt; ServerA/ServerB, entirely over Streamable HTTP.

Both mock servers support both transports (selected by a `--transport` flag). The
acceptance test suite runs against both configs, parametrized over the same
assertions. Config A ships first (MR4); Config B is added after (MR5), reusing the
routing/codec/correlation core unchanged — see 0001 and the MR4/MR5 ADRs for the
adapter-separation rationale and the "zero diff" verification this enables.

## Alternatives considered

- Mixed/independent transport per connection leg (e.g. Agent&lt;-&gt;Proxy over HTTP,
  Proxy&lt;-&gt;Servers over stdio) — rejected for V1 as unnecessary surface area; nothing
  in the V1 acceptance criteria requires mixed-transport configs.
- stdio-only for V1, deferring HTTP to a later phase (the architecture doc's
  default framing) — rejected; HTTP support was wanted now rather than later.

## Consequences

Streamable HTTP's session-id and stream-resumption (`Last-Event-ID`) mechanism is
explicitly out of scope for V1 (see the MR5 ADR) — supporting it is meaningful
added infrastructure not required by the V1 acceptance text.
