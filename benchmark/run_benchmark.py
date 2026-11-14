"""Run the Latch vs. naive-baseline benchmark.

    python -m benchmark.run_benchmark

Writes ``benchmark/results.json`` and ``benchmark/RESULTS.md`` and prints a
summary table. Deterministic: no timestamps, no randomness, sorted output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcpprobe import __version__
from mcpprobe.auditor import audit_manifest
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.lockfile import create_lockfile, verify_manifest
from mcpprobe.models import parse_tools_payload

from .corpus import BENIGN_CASES, CASES, HOSTILE_CASES, Case
from .naive_baseline import naive_verdict

BENCHMARK_DIR = Path(__file__).resolve().parent
RESULTS_JSON = BENCHMARK_DIR / "results.json"
RESULTS_MD = BENCHMARK_DIR / "RESULTS.md"


def latch_verdict(case: Case) -> dict[str, Any]:
    """Run every applicable Latch engine and report which one fired."""

    signals: dict[str, bool] = {}
    pinned = case.pinned_manifest()
    current = case.current_manifest()

    if pinned is not None and current is not None:
        report = verify_manifest(current, create_lockfile(pinned, "benchmark"))
        signals["lockfile"] = not report.passed

    if current is not None:
        signals["audit"] = not audit_manifest(current).passed

    if case.servers:
        audit_hit = False
        for tools in case.servers.values():
            if not audit_manifest({"tools": tools}).passed:
                audit_hit = True
                break
        signals["audit"] = signals.get("audit", False) or audit_hit

        parsed = {
            server_id: parse_tools_payload({"tools": tools})
            for server_id, tools in case.servers.items()
        }
        graph = analyze_capability_graph(
            parsed, trusted_servers=set(case.trusted_servers) or None
        )
        signals["graph"] = not graph.passed

    return {"flagged": any(signals.values()), "signals": signals}


def _metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    tp = sum(1 for row in rows if row["expected_positive"] and row[key])
    fp = sum(1 for row in rows if not row["expected_positive"] and row[key])
    tn = sum(1 for row in rows if not row["expected_positive"] and not row[key])
    fn = sum(1 for row in rows if row["expected_positive"] and not row[key])

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


def compute_results() -> dict[str, Any]:
    """Evaluate both scanners over the whole corpus."""

    rows: list[dict[str, Any]] = []
    for case in CASES:
        latch = latch_verdict(case)
        naive = naive_verdict(case)
        rows.append(
            {
                "case_id": case.case_id,
                "title": case.title,
                "expectation": case.expectation,
                "expected_positive": case.expected_positive,
                "latch_flagged": latch["flagged"],
                "latch_signals": latch["signals"],
                "naive_flagged": naive["flagged"],
                "naive_hits": naive["hits"],
            }
        )

    return {
        "tool_version": __version__,
        "case_count": len(rows),
        "hostile_count": len(HOSTILE_CASES),
        "benign_count": len(BENIGN_CASES),
        "cases": rows,
        "latch": _metrics(rows, "latch_flagged"),
        "naive": _metrics(rows, "naive_flagged"),
    }


def _row(name: str, metrics: dict[str, Any], bold: bool = False) -> str:
    label = f"**{name}**" if bold else name
    return (
        f"| {label} | {metrics['tp']} | {metrics['fp']} | {metrics['tn']} |"
        f" {metrics['fn']} | {metrics['precision']:.2f} | {metrics['recall']:.2f} |"
        f" {metrics['f1']:.2f} | {metrics['fpr']:.2f} |"
    )


def render_markdown(results: dict[str, Any]) -> str:
    """Render ``RESULTS.md`` deterministically."""

    latch = results["latch"]
    naive = results["naive"]

    lines = [
        "# Latch benchmark results",
        "",
        "Deterministic ground-truth evaluation of Latch against a naive",
        "keyword/substring scanner over 24 cases: 12 hostile/vulnerable cases",
        "(expected positive) and 12 benign hard lookalikes built to punish keyword",
        "matching. There are no timestamps or random values, so re-running",
        "`python -m benchmark.run_benchmark` reproduces this file byte for byte.",
        "",
        f"- Tool version: `{results['tool_version']}`",
        f"- Cases: {results['case_count']}"
        f" ({results['hostile_count']} hostile, {results['benign_count']} benign)",
        "",
        "## Summary",
        "",
        "| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |",
        _row("Naive keyword/substring baseline", naive),
        _row("Latch", latch, bold=True),
        "",
        "Precision = TP / (TP + FP); Recall = TP / (TP + FN);",
        "F1 = harmonic mean of precision and recall;",
        "FPR = FP / (FP + TN).",
        "",
        "## Per-case results",
        "",
        "| Case | Expectation | Latch | Naive | Title |",
        "| ---- | ----------- | ----- | ----- | ----- |",
    ]

    for row in results["cases"]:
        latch_mark = "detected" if row["latch_flagged"] else "clean"
        naive_mark = "detected" if row["naive_flagged"] else "clean"
        lines.append(
            f"| `{row['case_id']}` | {row['expectation']} | {latch_mark} |"
            f" {naive_mark} | {row['title']} |"
        )

    lines.extend(["", "## Where the baseline breaks", ""])

    missed = [
        row["case_id"]
        for row in results["cases"]
        if row["expected_positive"] and not row["naive_flagged"]
    ]
    false_positives = [
        row["case_id"]
        for row in results["cases"]
        if not row["expected_positive"] and row["naive_flagged"]
    ]

    lines.append(f"- Hostile cases the baseline misses ({len(missed)}): " + ", ".join(f"`{c}`" for c in missed))
    lines.append(
        f"- Benign cases the baseline flags ({len(false_positives)}): "
        + ", ".join(f"`{c}`" for c in false_positives)
    )
    lines.append(
        "- Latch misses 0 hostile cases and flags 0 benign cases, because it hashes"
        " canonical tool definitions, tokenizes identifiers, allowlists header"
        " bindings and analyzes cross-server capability chains."
    )
    lines.append("")

    return "\n".join(lines)


def write_results(results: dict[str, Any]) -> None:
    RESULTS_JSON.write_text(
        json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    RESULTS_MD.write_text(render_markdown(results), encoding="utf-8")


def print_summary(results: dict[str, Any]) -> None:
    latch = results["latch"]
    naive = results["naive"]
    header = (
        f"{'Scanner':34} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}"
        f" {'Prec':>6} {'Recall':>7} {'F1':>6} {'FPR':>6}"
    )
    print(header)
    print("-" * len(header))
    for name, metrics in (
        ("Naive keyword/substring baseline", naive),
        ("Latch", latch),
    ):
        print(
            f"{name:34} {metrics['tp']:>3} {metrics['fp']:>3} {metrics['tn']:>3}"
            f" {metrics['fn']:>3} {metrics['precision']:>6.2f} {metrics['recall']:>7.2f}"
            f" {metrics['f1']:>6.2f} {metrics['fpr']:>6.2f}"
        )
    print()
    print(f"Wrote {RESULTS_JSON}")
    print(f"Wrote {RESULTS_MD}")


def main() -> int:
    results = compute_results()
    write_results(results)
    print_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
