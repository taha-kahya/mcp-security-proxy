"""
Run all injection variants for a given model and save results.

Results are appended to tests/poc/results/results.md and results.jsonl —
both files accumulate across runs so nothing is ever lost.

Usage:
    python tests/poc/run_all.py                                  # claude-opus-4-7, all variants
    python tests/poc/run_all.py --model claude-haiku-4-5-20251001
    python tests/poc/run_all.py --model ollama:llama3.2
    python tests/poc/run_all.py --model gpt-4o
    python tests/poc/run_all.py --variants / /v4                 # subset of variants

Requires the poisoned server to be running:
    python tests/poc/server.py
"""

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent))
from agent import VALID_VARIANTS, run

RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

VARIANT_DESCRIPTIONS = {
    "/":        "visible payload, all red flags",
    "/hidden":  "CSS display:none",
    "/comment": "HTML comment",
    "/script":  "script[type=text/plain]",
    "/v1":      "no AI targeting",
    "/v2":      "no secrecy directive",
    "/v3":      "task-aligned, no authority claim",
    "/v4":      "buried in prose, same academic voice",
}


def run_all(model: str, variants: list[str], port: int = 8888) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    results = []

    print(f"\n{'='*60}")
    print(f"Model    : {model}")
    print(f"Variants : {' '.join(variants)}")
    print(f"Started  : {timestamp[:19]}Z")
    print(f"{'='*60}")

    for variant in variants:
        result = run(variant, model, port)
        result["timestamp"] = timestamp
        result["description"] = VARIANT_DESCRIPTIONS.get(variant, "")
        results.append(result)
        time.sleep(1)

    _save(model, results)
    _print_summary(model, results)


def _save(model: str, results: list[dict]) -> None:
    jsonl_path = RESULTS_DIR / "results.jsonl"
    with open(jsonl_path, "a") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    md_path = RESULTS_DIR / "results.md"
    if not md_path.exists():
        md_path.write_text(
            "# Prompt Injection PoC — Results\n\n"
            "| Date | Model | Variant | Description | Result |\n"
            "|---|---|---|---|---|\n"
        )
    with open(md_path, "a") as f:
        for r in results:
            status = "✅ SUCCEEDED" if r["succeeded"] else "❌ Resisted"
            date = r["timestamp"][:10]
            f.write(f"| {date} | `{r['model']}` | `{r['variant']}` | {r['description']} | {status} |\n")

    print(f"\nResults saved → {RESULTS_DIR.relative_to(Path(__file__).parent.parent.parent)}/")


def _print_summary(model: str, results: list[dict]) -> None:
    print(f"\n{'='*60}")
    print(f"SUMMARY — {model}")
    print(f"{'='*60}")
    for r in results:
        status = "SUCCEEDED ✅" if r["succeeded"] else "Resisted  ❌"
        print(f"  {r['variant']:12}  {r['description']:40}  {status}")
    succeeded = sum(1 for r in results if r["succeeded"])
    print(f"\n  {succeeded}/{len(results)} variants succeeded")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run all injection variants for a model.")
    parser.add_argument("--model", default="claude-opus-4-7",
                        help="Model ID. Prefix with 'ollama:' for local Ollama. E.g. ollama:llama3.2")
    parser.add_argument("--variants", nargs="+", choices=VALID_VARIANTS, default=list(VALID_VARIANTS),
                        help="Subset of variants to run (default: all)")
    parser.add_argument("--port", type=int, default=8888)
    args = parser.parse_args()
    run_all(args.model, args.variants, args.port)
