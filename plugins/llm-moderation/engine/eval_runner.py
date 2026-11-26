# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Offline JSONL comparative evaluator for Local Guard vs Canary Inducement Probe."""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from .canary_probe import run_inducement_canary
from .router import evaluate_inspection


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(math.ceil(pct * len(ordered))) - 1))
    return round(ordered[idx], 3)


def evaluate_dataset(
    samples: List[Dict[str, Any]],
    *,
    base_config: Dict[str, Any],
) -> Dict[str, Any]:
    modes_to_eval = ["local-only"]
    if base_config.get("canary", {}).get("endpoint"):
        modes_to_eval.extend(["canary-only", "guard-plus-canary"])

    report: Dict[str, Any] = {"sampleCount": len(samples), "modes": {}}
    for eval_mode in modes_to_eval:
        tp = fp = tn = fn = 0
        latencies: List[float] = []
        decisions = {}
        for idx, sample in enumerate(samples):
            text = str(sample.get("text") or "")
            label = str(sample.get("label") or "safe").lower()
            expected_unsafe = label in ("unsafe", "block", "inducement", "malicious")
            stage = str(sample.get("stage") or "input")
            t0 = time.monotonic()

            if eval_mode == "canary-only":
                out = run_inducement_canary(text, canary_cfg=base_config.get("canary") or {})
                predicted_unsafe = bool(out.canary_induced)
            else:
                cfg = dict(base_config)
                cfg["mode"] = "local-only" if eval_mode == "local-only" else "guard-plus-canary"
                if eval_mode == "guard-plus-canary":
                    canary_cfg = dict(cfg.get("canary") or {})
                    canary_cfg["enabled"] = True
                    canary_cfg["shadowMode"] = False
                    cfg["canary"] = canary_cfg
                req = {
                    "protocolVersion": 2,
                    "stage": stage,
                    "requestId": str(sample.get("id") or f"eval-{idx}"),
                    "toolName": str(sample.get("toolName") or "eval_tool"),
                    "payload": {"text": text},
                    "modalityPackets": [{"modality": "text", "refKind": "inline", "inlineData": text}],
                }
                res = evaluate_inspection(inspect_request=req, config=cfg)
                predicted_unsafe = res["verdict"]["decision"] in ("block", "escalate")

            sample_id = str(sample.get("id") or f"eval-{idx}")
            if sample_id in decisions:
                raise ValueError(f"Duplicate sample id: {sample_id}")
            decisions[sample_id] = "block" if predicted_unsafe else "allow"
            latencies.append((time.monotonic() - t0) * 1000.0)
            if expected_unsafe and predicted_unsafe:
                tp += 1
            elif not expected_unsafe and predicted_unsafe:
                fp += 1
            elif not expected_unsafe and not predicted_unsafe:
                tn += 1
            else:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        report["modes"][eval_mode] = {
            "decisions": decisions,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "p50LatencyMs": _percentile(latencies, 0.50),
            "p95LatencyMs": _percentile(latencies, 0.95),
        }
    return report


def load_jsonl_samples(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            rows.append(json.loads(stripped))
    return rows


def compare_baseline(baseline: dict, decisions: dict) -> dict:
    if not isinstance(baseline, dict) or not baseline or any(
        verdict not in ("allow", "block") for verdict in baseline.values()
    ):
        raise ValueError("Baseline must map sample IDs to allow or block")
    common = baseline.keys() & decisions.keys()
    return {
        "allowToBlock": sorted(i for i in common if baseline[i] == "allow" and decisions[i] == "block"),
        "blockToAllow": sorted(i for i in common if baseline[i] == "block" and decisions[i] == "allow"),
        "added": sorted(decisions.keys() - baseline.keys()),
        "removed": sorted(baseline.keys() - decisions.keys()),
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Guard vs Canary Probe comparative benchmark runner")
    parser.add_argument("--dataset", required=True, help="Path to JSONL evaluation samples")
    parser.add_argument("--guard-endpoint", default=None, help="Optional loopback Local Guard HTTP endpoint")
    parser.add_argument("--guard-model", default="llama-guard-3", help="Local Guard model name")
    parser.add_argument("--canary-endpoint", default=None, help="Optional loopback Canary small model HTTP endpoint")
    parser.add_argument("--canary-model", default="qwen2.5-0.5b", help="Canary small model name")
    parser.add_argument("--baseline", help="Compare local-only decisions against a reviewed JSON map of sample IDs")
    args = parser.parse_args(argv)

    samples = load_jsonl_samples(Path(args.dataset))
    base_config: Dict[str, Any] = {
        "mode": "guard-plus-canary" if args.canary_endpoint else "local-only",
        "policyProfile": "balanced",
        "localGuard": {
            "kind": "http",
            "endpoint": args.guard_endpoint,
            "model": args.guard_model,
            "timeoutMs": 8000,
        },
        "canary": {
            "enabled": bool(args.canary_endpoint),
            "endpoint": args.canary_endpoint,
            "model": args.canary_model,
            "maxTokens": 96,
            "temperature": 0.1,
            "shadowMode": False,
            "escalateOnInduced": True,
        },
        "thresholds": {"grayZoneLow": 0.25, "grayZoneHigh": 0.80},
    }
    report = evaluate_dataset(samples, base_config=base_config)
    if args.baseline:
        if any(not isinstance(row.get("id"), str) or not row["id"].strip() for row in samples):
            parser.error("Baseline comparison requires explicit nonempty sample IDs")
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        report["baselineDiff"] = compare_baseline(baseline, report["modes"]["local-only"]["decisions"])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return int(any(report.get("baselineDiff", {}).values()))


if __name__ == "__main__":
    raise SystemExit(main())
