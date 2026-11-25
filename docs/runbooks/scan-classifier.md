# Scan classifier: installing and enabling it

The classifier stage ([ADR 0026](../decisions/0026-scan-classifier-stage.md))
grades every tool definition as clean, `medium`, `high` or `critical`.
`direct_definition_classifier` reports the grade, and policy decides what
it does. With the default policy, high and critical are blocked. Without
these steps the proxy runs as before, without torch.

## 1. Install the extra

```sh
uv sync --extra classifier
```

This installs torch, transformers, safetensors and tokenizers at the
versions in `uv.lock`.

## 2. Install the bundle

The model files are not in this repository. They are published as a
release of a separate model repository, which is private for now; ask the
maintainers for access. With access, download them into
`models/definition-classifier/` (git-ignored) and check them:

```sh
gh release download definition-classifier/definition-v1 \
  -R WhiteRow33/mcp-security-proxy-models -D models/definition-classifier
(cd models/definition-classifier && shasum -a 256 -c SHA256SUMS)
```

The proxy also checks each file's SHA-256 against
`services/scan/classifier/checkpoints.py`, and refuses to start if a file
is missing, altered or unknown:

| File | SHA-256 |
| --- | --- |
| `model.safetensors` | `c22a8e0a19ed8efc242cd2edfa658c3efc4ae9f4bf0cf341bdba028f06326a68` |
| `config.json` | `1609d59e627c33eaed524b4f01e546d42e84190a079a5a5ded84b212c41c324f` |
| `tokenizer.json` | `9fd55248d51d33976b324fc11592e28071da7d41e0e9401dfb7082e30574b7b1` |
| `tokenizer_config.json` | `3cd2017ff46d0a527e5d39cae39272eccfa1f19bb9f89b05d166aab2e38354e2` |
| `special_tokens_map.json` | `ea97ecdbcc73713039d8d64dbb05e3689495c96657fbd9a18f5bed381be81049` |

Check that the installed libraries reproduce the reference scores:

```sh
uv run --extra classifier pytest tests/contracts/test_scan_classifier_model.py
```

These tests are skipped when the bundle is absent.

## 3. Configure the proxy

In the proxy config:

```yaml
scan:
  classifier:
    model_dir: models/definition-classifier   # relative to the start directory
    operating_point: high_recall               # or balanced (fewer medium tools graded high)
    device: cpu                                # cuda / mps are untested
    token_budget: 8192                         # padded tokens per batch
    cache_entries: 10000                       # graded definitions kept in memory
    timeout_seconds: 120                       # longer scoring calls fail closed
```

Then set `enabled: true` in `config/defenses/direct_definition_classifier.yaml`.
Enable both or neither: the defense without the classifier stops the proxy
at startup, and the classifier without the defense does nothing useful
(startup logs a warning).

At startup the proxy logs
`scan classifier stage: classifier-definition-v1+ser-1+high_recall`.
Model loading takes about 10 s on CPU. At startup the pinned files are
copied into a private temporary directory and loaded from there, so the
temporary directory needs about 600 MB free; other files in `model_dir`,
such as `SHA256SUMS`, are ignored.

## Troubleshooting

- **`ClassifierLoadError: scan.classifier needs the classifier extra`.**
  Run step 1.
- **`... is not a known checkpoint` or `... does not match its pinned hash`.**
  The bundle is wrong. Thresholds are valid only for the pinned files.
- **Every tool is hidden.** Check the log for `classifier failed on N
  definitions`, `classifier timed out` or `classifier busy after a
  timeout`. Scoring failed, so each inspection is reported `failed` and
  blocked by `on_failure`. The next listing retries.
- **One tool is always hidden.** A definition longer than the model's
  8192-token window is never graded, so it always fails inspection.
