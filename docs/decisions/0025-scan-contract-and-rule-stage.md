# 0025 — Scan: an async, stage-aware contract and its rule stage

Status: Accepted

## Context

Plan MR S2 ([V4 Defense Plan](../design/v4-defense-plan.md)) adds Scan's
rule-based stage: decoding, hidden content, lookalike characters and
secrets. Six later MRs depend on it, so its contract has to hold as
stages are added: a local classifier (S4) and, later, a model check that
confirms only what earlier stages flagged.

Constraints that shaped it:

- A defense has no I/O and a 2 s deadline; Scan is a core service and may
  do I/O in a later stage.
- Evidence must not quote inspected text, so nothing sensitive reaches logs.
- Missing evidence means unknown, never safe.
- Arbitus matches decoded variants but blocks on every phrase match;
  SkillSpector cuts false positives with prohibition context and a hosted
  LLM, which a runtime proxy can't call inline (Part 1 of the plan).

## Decision

**Contract.** A defense declares `Capability.SCAN` and calls
`context.scan`, a `ScanView` with one async method per detector:
`hidden`, `instructions`, `lookalikes`, `secrets`. Each method takes a
string or any JSON value, walks it at any depth (mapping keys included),
and returns a `ScanResult` of `ScanMatch`es. SDK version 1.0.0 → 1.1.0.

- **Async and stage-aware from day one.** Every match carries `stage`
  (`rules` today) and `confidence`, so a classifier or model stage can be
  added behind the same methods without breaking defenses.
- **Scan finds, the defense reports.** A match is neutral evidence: kind,
  JSON Pointer, character range, `decoded_by`, `concealed`, `in_key`,
  `label`. It never contains the text. The defense maps matches to
  findings under its own rule ids, and policy decides.
- **Unknown is never clean.** A scan that can't complete raises
  `ScanError`, and the Runner reports the inspection as failed. Values over
  1M characters, or one string with more than 256 base64 or tag segments,
  raise `ScanLimitError` instead of being partly scanned.

**Rule stage** (`services/scan/`):

- Every detector matches against views that undo disguises: NFKC with
  invisible characters removed, lookalike letters folded to ASCII, and
  decoded Unicode tags, base64 and percent-encoding, recursively. Each
  match records which decodings revealed it.
- **Concealment** is decided once, in Scan: a match is `concealed` when
  base64, tags, lookalike folding, double percent-encoding or obfuscating
  normalization revealed it, or when it lies inside hidden content
  (comments, invisible text, after padding). Single percent-encoding and
  ordinary spacing changes don't count, since URLs and web text use them.
- **Narrow instruction list.** Override phrases need a scoping word ("all
  previous"), and a negation in front suppresses them. Role switches,
  chat-template tokens and fake authority markers complete the list.
  Reworded injections are left to the classifier stage.
- **Severity by context, in the defense.** A concealed instruction is
  high; a plain one in a tool result is low (results quote such phrases);
  in tool metadata, plain phrases belong to D3.
- **Lookalikes** follow UTS #39. A word is reported only when it mixes
  scripts through confusable letters, so `5 μs` and Han+Latin text stay
  clean.
- **Secrets** are well-known formats only, with no entropy guessing.
- **Unicode data is vendored**: `confusables.txt` and `Scripts.txt` from
  Unicode 17.0.0, unchanged, under the Unicode License v3, with pinned
  hashes. Python's `unicodedata` has no script property.
- Results are cached per detector and content digest. They hold no
  content, so the cache is shared safely across principals.

**First consumers**, shipped in the same MR as ADR 0024 requires:
`direct_hidden_metadata` (D2) and `indirect_result_injection` (I1).

## Alternatives considered

- **A synchronous API.** Simpler today, but a network-backed stage later
  would be a breaking SDK change.
- **Strings only.** Every defense (D2, D3, I2, C3) would repeat the walk
  and pointer building.
- **One call returning every detector's matches.** Every caller would pay
  for every detector.
- **A broad phrase list, blocking on every match (Arbitus).** Results that
  merely discuss prompt injection would be blocked.
- **A third-party confusables package.** It saves a few hours, but its
  bundled data is often versions behind and adds a dependency to vet. The
  false-positive rules are ours to write either way.
- **An LLM inside a defense.** Defenses have no I/O. A model check belongs
  behind Scan, as a later stage.

## Consequences

- D3, D4, I2, C3 and S4 can start. D4 will expose `skeleton()` (already
  implemented) through the SDK.
- Defense unit tests script Scan with `sdk.testing.FakeScan`. What Scan
  detects is tested in `tests/contracts/test_scan_*.py`, and the defenses
  against the real rule stage in `tests/contracts/test_scan_defenses.py`.
- Scan runs on the event loop. Each detector stays under about 0.5 s at
  the 1M-character limit, but a large scan still delays other requests.
  Running scans in a worker thread is deferred until it is needed.
- The model stage will need its own time budget (today the defense's 2 s
  deadline includes Scan), explicit deployment opt-in before content
  leaves the proxy, and hardening against the judged content injecting the
  judge. Its unavailability must mean unknown, never clean.
- Updating the Unicode data is a documented file swap
  (`services/scan/data/unicode-17.0.0/README.md`). It changes Scan's
  version, which invalidates cached results.
