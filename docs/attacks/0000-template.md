# Attack doc template

Copy this file to `docs/attacks/<category>.md`, where `<category>` is one of
`direct`, `indirect`, `cross-tool`, `temporal`, `environment`. Add the new
page to the `nav` in `mkdocs.yml`. Each category's doc is that track's
phase 0 MR (D0, I0, C0, T0, E0) in the
[V4 Defense Plan](../design/v4-defense-plan.md).

Write it only from the attack taxonomy and public descriptions of the
attacks. Never take examples, payloads, thresholds or results from the
held-out research experiments.

Delete everything above the line below.

---

# <Category> attacks

Status: Draft | Reviewed. Owner: <name>.

One sentence: what this category covers, and what it leaves to other
categories.

## Attacks

One subsection per attack type. Keep the attack types from the plan's
Part 1 table, and add any new ones here first.

### <Attack type>

- **How it works.** What the attacker controls, what the agent does as a
  result, and what harm follows. Two or three sentences.
- **Malicious example.** One short, concrete example written for this doc.
- **Benign twin.** A legitimate case that looks similar and must stay clean.
- **Where the proxy sees it.** Stage (`discovery`, `before_execution`,
  `before_delivery`) and the exact fields, as JSON Pointers
  (`/inputSchema/properties/path/description`, `/arguments/url`,
  `/content/0/text`).
- **Evasions to expect.** Encodings, splitting across fields or calls,
  rewording, lookalike characters.
- **Public sources.** Links to the papers, posts or advisories this is based
  on.

## Detection

| Rule (planned id) | Attack | Evidence it uses | Severity | MR |
| --- | --- | --- | --- | --- |
| `<defense_id>.<rule>` | <Attack type> | Scan, History, Registry, signal | high | D2 |

- **Signals produced or consumed**, and what the consumer does when the
  signal is missing (unknown, never safe).
- **Capabilities needed** that the SDK does not have yet, with the plan MR
  that adds them.

## Not covered

What this category deliberately leaves out, and where it is handled instead
(another category, V5, or the operator's runbook).

## Test cases

Each rule needs malicious cases and their matched benign twins. List them
here as one line each, so the defense's parametrized tests can follow this
list.
