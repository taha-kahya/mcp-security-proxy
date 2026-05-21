"""
Run all injection variants for a given model and save results.

Results are appended to tests/poc/results/results.md and results.jsonl —
both files accumulate across runs so nothing is ever lost.

Usage:
    python tests/poc/run_all.py                                          # prompt_injection, claude-opus-4-7
    python tests/poc/run_all.py --attack credential_exfil --system-prompt
    python tests/poc/run_all.py --attack all --model claude-haiku-4-5-20251001
    python tests/poc/run_all.py --model ollama:llama3.2
    python tests/poc/run_all.py --variants /original /v4_buried_prose    # explicit subset
    python tests/poc/run_all.py --system-prompt                          # built-in susceptible prompt
    python tests/poc/run_all.py --system-prompt "custom prompt"          # custom system prompt

Requires the poisoned server to be running:
    python tests/poc/server.py
"""

import argparse
import importlib.util
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

POC_DIR = Path(__file__).parent


def _load(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    # Each attack agent imports its own payloads — give it the right search path
    sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(mod)
    sys.path.pop(0)
    return mod


pi_agent = _load(POC_DIR / "attacks" / "prompt_injection" / "agent.py", "pi_agent")
ce_agent = _load(POC_DIR / "attacks" / "credential_exfil" / "agent.py", "ce_agent")
PI_PAYLOADS = _load(POC_DIR / "attacks" / "prompt_injection" / "payloads.py", "pi_payloads").PAYLOADS
CE_PAYLOADS = _load(POC_DIR / "attacks" / "credential_exfil" / "payloads.py", "ce_payloads").PAYLOADS

ALL_PAYLOADS = {**PI_PAYLOADS, **CE_PAYLOADS}

RESULTS_DIR = POC_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

SUSCEPTIBLE_SYSTEM_PROMPT = pi_agent.SUSCEPTIBLE_SYSTEM_PROMPT


def _variants_for_attack(attack: str) -> list[str]:
    if attack == "prompt_injection":
        return pi_agent._valid_variants()
    if attack == "credential_exfil":
        return ce_agent._valid_variants()
    return pi_agent._valid_variants() + ce_agent._valid_variants()


def _run_variant(variant: str, model: str, port: int, system_prompt: str | None) -> dict:
    name = variant.strip("/").split("/")[0]
    if name in CE_PAYLOADS:
        return ce_agent.run(variant, model, port, system_prompt)
    return pi_agent.run(variant, model, port, system_prompt)


def _describe(variant: str) -> str:
    technique_labels = {"hidden": "CSS hidden", "comment": "HTML comment", "script": "script tag"}
    parts = variant.strip("/").split("/")
    payload_name = parts[0]
    technique = technique_labels.get(parts[1], "visible") if len(parts) > 1 else "visible"
    payload_desc = ALL_PAYLOADS.get(payload_name, {}).get("description", "")
    return f"{technique} — {payload_desc}"


def run_all(model: str, variants: list[str], port: int = 8888,
            system_prompt: str | None = None) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    results = []

    print(f"\n{'='*60}")
    print(f"Model    : {model}")
    print(f"Variants : {len(variants)} total")
    if system_prompt:
        print(f"System   : {system_prompt[:80]}...")
    print(f"Started  : {timestamp[:19]}Z")
    print(f"{'='*60}")

    for variant in variants:
        result = _run_variant(variant, model, port, system_prompt)
        result["timestamp"] = timestamp
        result["description"] = _describe(variant)
        results.append(result)
        time.sleep(1)

    _save(results)
    _print_summary(model, results)


def _save(results: list[dict]) -> None:
    jsonl_path = RESULTS_DIR / "results.jsonl"
    with open(jsonl_path, "a") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    md_path = RESULTS_DIR / "results.md"
    if not md_path.exists():
        md_path.write_text(
            "# Prompt Injection PoC — Results\n\n"
            "| Date | Model | Attack | Variant | Description | Result |\n"
            "|---|---|---|---|---|---|\n"
        )
    with open(md_path, "a") as f:
        for r in results:
            if r.get("exfiltrated_credentials"):
                status = "🔑 EXFILTRATED"
            elif r["succeeded"]:
                status = "✅ SUCCEEDED"
            else:
                status = "❌ Resisted"
            date = r["timestamp"][:10]
            sys_flag = " (+sys)" if r.get("system_prompt") else ""
            attack = r.get("attack", "prompt_injection")
            f.write(f"| {date} | `{r['model']}{sys_flag}` | {attack} | `{r['variant']}` | {r['description']} | {status} |\n")

    print(f"\nResults saved → {RESULTS_DIR.relative_to(POC_DIR.parent.parent)}/")


def _print_summary(model: str, results: list[dict]) -> None:
    print(f"\n{'='*60}")
    print(f"SUMMARY — {model}")
    print(f"{'='*60}")
    for r in results:
        if r.get("exfiltrated_credentials"):
            status = "EXFILTRATED 🔑"
        elif r["succeeded"]:
            status = "SUCCEEDED   ✅"
        else:
            status = "Resisted    ❌"
        print(f"  {r['variant']:35}  {status}")
    succeeded = sum(1 for r in results if r["succeeded"])
    print(f"\n  {succeeded}/{len(results)} variants succeeded")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run PoC variants for a model.")
    parser.add_argument("--model", default="claude-opus-4-7")
    parser.add_argument("--attack", choices=["prompt_injection", "credential_exfil", "all"],
                        default="prompt_injection",
                        help="Attack category to run (default: prompt_injection)")
    parser.add_argument("--variants", nargs="+", default=None, metavar="VARIANT",
                        help="Explicit subset, overrides --attack")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--system-prompt", dest="system_prompt", nargs="?",
                        const=SUSCEPTIBLE_SYSTEM_PROMPT, default=None,
                        help="Omit value for built-in susceptible-researcher prompt.")
    args = parser.parse_args()

    variants = args.variants if args.variants else _variants_for_attack(args.attack)
    run_all(args.model, variants, args.port, args.system_prompt)
