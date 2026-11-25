# 0026 — Scan's classifier stage: a local model that grades tool definitions

Status: Accepted

## Context

Plan MR S4 ([V4 Defense Plan](../design/v4-defense-plan.md)) adds a local
classifier behind Scan to catch reworded tool poisoning that the rule stage
([0025](0025-scan-contract-and-rule-stage.md)) misses. ADR 0023 §8 parked
the classifier and fixed its shape: it runs once per definition version,
outside the defense deadline. Its result is cached, and a read-only defense
reports it. A missing result is `failed`, never clean.

The goal is a deployable classifier now. The checkpoint is provisional and
can be replaced without changing the stage.

Constraints:

- A defense has no I/O and a 2 s deadline. The model takes well under a
  second per short definition on CPU, with multi-second outliers on long
  ones.
- Thresholds hold only for the exact weights, tokenizer and serialization
  they were fitted with.
- The proxy must run without torch when no classifier is configured.
- The held-out experiments are the evaluation of the proxy. Nothing here
  may be fitted to them.

## Decision

**Checkpoint.** `definition-v1` is a fine-tuned transformer encoder with a
3-output CORN ordinal head.

- It reads `ser-1`, a fixed text serialization of the definition: name,
  titles, description, and each parameter's path, type, enum, default,
  const and description. Input is truncated to 8192 tokens.
- It outputs cut scores `s_k = P(level > k)` for LOW, MEDIUM and HIGH.
- The serialization is pinned by golden strings from the serializer the
  checkpoint was trained with. The weights, config and tokenizer files are
  pinned by SHA-256 in `services/scan/classifier/checkpoints.py`. A bundle
  that does not match is refused at startup.

**Grading rule (gated).** Each definition gets one grade:

- clean when `s0 <= gate`;
- otherwise `critical` when `s2 >= critical`;
- otherwise `high` when `s1 >= high`;
- otherwise `medium`.

The thresholds were fitted for this checkpoint and are not transferable.
There are two operating points, which share the gate and differ in the
high and critical cuts:

- `high_recall` grades more tools high or critical, so fewer poisoned
  tools pass. It is the default.
- `balanced` grades fewer medium tools high.

The operator chooses one with `scan.classifier.operating_point`.

**Enforcement.** The operator's priority is that high and critical
poisoning is blocked; how medium is handled does not matter for this
choice.

- A finding's severity is its grade, and policy decides what it does. The
  default `by_severity` blocks high and critical. Medium needs approval,
  which blocks until approval is wired (V5).
- This supersedes ADR 0023 §8's "classifier findings map to
  `require_approval`".
- No `findings` override is added to the reference policy.

**Shape** (as ADR 0023 §8):

- *Contract.* `ScanView.poisoning(definition)` returns at most one match:
  detector `poisoning`, kind `poisoned_definition`, stage `classifier`, and
  the grade in `label`. Its pointer is `""` (the whole definition), because
  the model does not localise. SDK 1.1.0 → 1.2.0. Without a configured
  classifier, `poisoning` raises `ScanError`.
- *Prescan.* `ProxyControl` calls `Scan.prepare` before the Runner. A
  listing is scored in one batch. A call that arrives without a listing,
  for example after a restart, is scored on its own. Scoring runs in a
  worker thread, outside every defense deadline, and only when a discovery
  defense is enabled.
- *Cache.* An in-memory LRU keyed by the definition's canonical digest. The
  scorer, checkpoint and operating point are fixed for the process, and the
  result's `version` names them, for example
  `classifier-definition-v1+ser-1+high_recall`. Entries hold a grade and
  three numbers, never content.
- *Failure.* A scorer error is logged by exception type only, and the
  definitions stay unscored. A read of an unscored definition raises
  `ScanError`, so the Runner reports the inspection as `failed` and policy
  `on_failure` blocks. Failed reports are not cached (ADR 0020), so the
  next listing retries.
- *Defense.* `direct_definition_classifier` declares only `scan`, so ADR
  0020's discovery caching applies. It maps grades to the rules `.critical`,
  `.high` and `.medium`. Its reference config has `enabled: false`, because
  it needs the bundle.

**Dependencies.** The classifier dependencies are an optional extra,
`uv sync --extra classifier`:

- torch (PyTorch Foundation): locked at 2.15.0;
- transformers (Hugging Face): locked at 5.24.1;
- safetensors (Hugging Face): locked at 0.8.0;
- tokenizers (Hugging Face): locked at 0.23.3.

Only `torch_scorer.py` imports them, and only when a scorer is built. A
contract test checks that importing the app does not import torch. Weights
load from safetensors with strict state-dict matching, never from pickle.

**Bundle.** The model is about 600 MB and is not committed. It is
distributed separately, and installed at `models/definition-classifier/`
(git-ignored); see [Scan classifier runbook](../runbooks/scan-classifier.md).

## Alternatives considered

- **Run the model inside the defense.** Rejected in ADR 0023 §8: it breaks
  the deadline and the no-I/O rule.
- **A hosted LLM judge.** It costs money for each definition, sends tool
  text off the proxy, and the judged text can inject the judge. A later
  confirmation stage may still use one, for flagged definitions only
  (ADR 0025).
- **Improve the model first.** Not now. The checkpoint and its thresholds
  are frozen and treated as provisional.
- **`balanced` as the default.** It grades fewer medium tools high, but
  lets more poisoned tools through, against the operator's priority.
- **Map classifier findings to `require_approval` (ADR 0023 §8).**
  Superseded by the operator's priority above.

## Consequences

- **Choice of default.** `high_recall` was chosen as the default after
  evaluation results for both operating points were available. The choice
  is therefore not independently validated. At `high_recall`, most tools
  past the gate are graded critical, so the high/critical split carries
  little information.
- **Scores are not calibrated probabilities.** Every match therefore has
  the same confidence.
- **Not a sole control.** The classifier misses some reworded and
  adversarially written poisoning. The rule stage and the other direct
  defenses still run alongside it.
- **Parity.** `test_scan_classifier_model.py` pins reference scores for a
  few handwritten definitions, so a library upgrade that moves the scores
  fails a test.
- **Cost.** Loading the model at startup takes about 10 s. A listing of a
  few short definitions scores in a fraction of a second on CPU, and later
  listings are served from the cache.

Deferred or known limitations:

- **Coverage.** Text after token 8192 is never seen. Tool results and
  `initialize` instructions are not classified (definitions only).
- **No timeout on scoring.** A stuck model holds the classifier's lock, and
  every listing waits behind it.
- **Cache eviction.** A listing larger than `cache_entries` can evict its
  own scores before they are read. Those tools then fail closed for that
  listing and are rescored on the next one.
- **Scoring without the defense.** A configured classifier scores
  definitions whenever any discovery defense is enabled, even if
  `direct_definition_classifier` is disabled. That wastes work but is not
  unsafe.
- **Defense without a classifier.** If `direct_definition_classifier` is
  enabled but `scan.classifier` is not configured, every tool fails
  inspection and is hidden. This is fail-closed by design.
- **Replacing the checkpoint.** A new checkpoint must come with new pinned
  hashes and newly fitted operating points. If its serialization changes,
  it also needs a new `SERIALIZATION_VERSION`.
