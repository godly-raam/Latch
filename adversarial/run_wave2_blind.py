"""Run Wave 2 against the unmodified engines and freeze the first-run score.

    python -m adversarial.run_wave2_blind                    # verify vs frozen
    python -m adversarial.run_wave2_blind --freeze-new-baseline

The frozen record is ``adversarial/wave2_frozen_baseline.json``. On the first
run it is created. Afterwards the runner recomputes every probe and refuses to
overwrite the baseline; a mismatch means either an engine changed or a probe
was edited, and the report must be regenerated deliberately.

Writes ``adversarial/WAVE2_BLIND_REPORT.md`` with the frozen metrics, every
catch and every miss. No timestamps: re-runs reproduce both files byte for
byte.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from mcpprobe.auditor import audit_manifest
from mcpprobe.chain_prober import verify_trifecta_chains
from mcpprobe.config_loader import ServerSpec
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.models import ToolDefinition
from mcpprobe.oauth_audit import run_auth_audit
from mcpprobe.shadow import analyze_shadowing

from .run_evasion import _parse_tools, _redacted
from .wave2_blind import BLIND_PROBES, BlindProbe

EVAL_DIR = Path(__file__).resolve().parent
BASELINE_JSON = EVAL_DIR / "wave2_frozen_baseline.json"
REPORT_MD = EVAL_DIR / "WAVE2_BLIND_REPORT.md"

SCHEMA_VERSION = 1


def evaluate_probe(probe: BlindProbe) -> dict[str, Any]:
    """Run the engine(s) this probe targets, exactly as shipped."""

    signals: dict[str, bool] = {}
    live: dict[str, Any] | None = None

    if probe.audit_payload is not None:
        signals["audit"] = not audit_manifest(probe.audit_payload).passed

    if probe.graph_servers:
        graph = analyze_capability_graph(_parse_tools(probe.graph_servers))
        signals["graph"] = not graph.passed

    if probe.shadow_servers:
        shadow = analyze_shadowing(_parse_tools(probe.shadow_servers))
        signals["shadow"] = not shadow.passed

    if probe.auth_specs:
        auth = run_auth_audit(
            [ServerSpec.model_validate(spec) for spec in probe.auth_specs]
        )
        signals["auth-audit"] = not auth.passed

    if probe.live_chain_specs:
        report = asyncio.run(
            verify_trifecta_chains(
                [ServerSpec.model_validate(spec) for spec in probe.live_chain_specs],
                timeout=10.0,
            )
        )
        signals["probe-chain"] = report.confirmed_exploitable > 0
        live = {
            "server_count": report.server_count,
            "paths_tested": report.paths_tested,
            "confirmed_exploitable": report.confirmed_exploitable,
            "statuses": [result.status for result in report.results],
            "sink_request_summaries": [
                _redacted(summary, result.canary_token)
                for result in report.results
                if (summary := result.sink_request_summary)
            ],
        }

    flagged = any(signals.values())
    return {"flagged": flagged, "signals": signals, "live": live}


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    positive = [row for row in rows if row["expected_positive"]]
    negative = [row for row in rows if not row["expected_positive"]]

    tp = sum(1 for row in positive if row["latch_flagged"])
    fn = len(positive) - tp
    fp = sum(1 for row in negative if row["latch_flagged"])
    tn = len(negative) - fp

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 1.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0

    return {
        "probe_count": len(rows),
        "hostile_probe_count": len(positive),
        "benign_probe_count": len(negative),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "blind_misses": sorted(
            row["probe_id"] for row in positive if not row["latch_flagged"]
        ),
        "blind_catches": sorted(row["probe_id"] for row in positive if row["latch_flagged"]),
        "benign_violations": sorted(
            row["probe_id"] for row in negative if row["latch_flagged"]
        ),
    }


def compute_results() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for probe in BLIND_PROBES:
        verdict = evaluate_probe(probe)
        rows.append(
            {
                "probe_id": probe.probe_id,
                "title": probe.title,
                "category": probe.category,
                "attack_technique": probe.attack_technique,
                "expected_positive": probe.expected_positive,
                "expectation_note": probe.expectation_note,
                "engines_used": probe.engines_used,
                "latch_flagged": verdict["flagged"],
                "latch_signals": verdict["signals"],
                "live": verdict["live"],
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "wave": 2,
        "frozen": True,
        "metrics": _metrics(rows),
        "probes": rows,
    }


def _dump(results: dict[str, Any]) -> str:
    return json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _signals_text(row: dict[str, Any]) -> str:
    fired = [engine for engine, hit in sorted(row["latch_signals"].items()) if hit]
    return ", ".join(fired) if fired else "—"


def render_report(results: dict[str, Any]) -> str:
    metrics = results["metrics"]
    catches = [row for row in results["probes"] if row["latch_flagged"]]
    misses = [
        row
        for row in results["probes"]
        if row["expected_positive"] and not row["latch_flagged"]
    ]
    benign = [row for row in results["probes"] if not row["expected_positive"]]
    benign_clean = [row for row in benign if not row["latch_flagged"]]

    lines = [
        "# Wave 2: Pre-Registered Blind Evaluation (Frozen First Run)",
        "",
        "Wave 1 in [`EVASION_REPORT.md`](EVASION_REPORT.md) is an *iterative*",
        "corpus: every probe there was a real bypass that the engines were then",
        "hardened against, so its `19/19` is a post-tuning regression result.",
        "Wave 2 is the blind complement. These sixteen probes were written",
        "against the shipped rule inventory, run once against unmodified",
        "`mcpprobe/`, and their first-run verdict was frozen in",
        "[`wave2_frozen_baseline.json`](wave2_frozen_baseline.json). No",
        "detection rule in `mcpprobe/` was changed in this chunk.",
        "",
        "| Metric | Frozen value |",
        "| ------ | ------------ |",
        f"| Probes | {metrics['probe_count']}"
        f" ({metrics['hostile_probe_count']} hostile +"
        f" {metrics['benign_probe_count']} benign controls) |",
        f"| True positives | {metrics['true_positives']} |",
        f"| False negatives (blind misses) | {metrics['false_negatives']} |",
        f"| True negatives | {metrics['true_negatives']} |",
        f"| False positives | {metrics['false_positives']} |",
        f"| Precision | {metrics['precision']:.2f} |",
        f"| Recall | {metrics['recall']:.2f} |",
        f"| False-positive rate (benign controls) |"
        f" {metrics['false_positive_rate']:.2f} |",
        "",
        "## Blind catches",
        "",
        "These sixteen were scored without a single rule edit, so a catch here",
        "means the shipped heuristics generalized to a technique they were not",
        "tuned on.",
        "",
        "| Probe | Category | Fired | Technique |",
        "| ----- | -------- | ----- | --------- |",
    ]

    for row in catches:
        lines.append(
            f"| `{row['probe_id']}` | `{row['category']}` |"
            f" {_signals_text(row)} | {row['attack_technique']} |"
        )

    lines.extend(
        [
            "",
            "## Blind misses",
            "",
            "Every one of these was expected to be caught when the corpus was",
            "written, and is reported as a miss. They are the honest floor of a",
            "token-level, manifest-only analyzer; nothing was relabeled after the",
            "fact to turn them into \"boundaries\".",
            "",
            "| Probe | Category | Reason | What would be needed |",
            "| ----- | -------- | ------ | -------------------- |",
        ]
    )

    for row in misses:
        lines.append(
            f"| `{row['probe_id']}` | `{row['category']}` |"
            f" {row['expectation_note']} | {row['attack_technique']} |"
        )

    lines.extend(
        [
            "",
            "## Benign hard negatives",
            "",
            f"{len(benign_clean)}/{len(benign)} controls stayed clean, so the"
            " false-positive rate on this wave is"
            f" {metrics['false_positive_rate']:.2f}.",
            "",
            "| Probe | Verdict | Note |",
            "| ----- | ------- | ---- |",
        ]
    )

    for row in benign:
        verdict = "flagged (false positive)" if row["latch_flagged"] else "clean"
        lines.append(
            f"| `{row['probe_id']}` | {verdict} | {row['expectation_note']} |"
        )

    lines.extend(
        [
            "",
            "## Per-probe results",
            "",
            "| Probe | Expected | Latch | Fired | Engines |",
            "| ----- | -------- | ----- | ----- | ------- |",
        ]
    )

    for row in results["probes"]:
        expected = "positive" if row["expected_positive"] else "negative"
        verdict = "detected" if row["latch_flagged"] else "clean"
        lines.append(
            f"| `{row['probe_id']}` | {expected} | {verdict} |"
            f" {_signals_text(row)} | {', '.join(row['engines_used'])} |"
        )

    live_rows = [row for row in results["probes"] if row["live"]]
    if live_rows:
        lines.extend(
            [
                "",
                "## Live probe detail",
                "",
                "Sink summaries have the random canary redacted, so the frozen",
                "record is reproducible.",
                "",
            ]
        )
        for row in live_rows:
            live = row["live"]
            lines.append(
                f"- `{row['probe_id']}`: paths_tested={live['paths_tested']},"
                f" confirmed={live['confirmed_exploitable']},"
                f" statuses={live['statuses']}"
            )
            for summary in live["sink_request_summaries"]:
                lines.append(f"  - sink: {summary}")

    lines.extend(
        [
            "",
            "## Freezing rules",
            "",
            "- `python -m adversarial.run_wave2_blind` recomputes every probe and",
            "  compares the result with",
            "  [`wave2_frozen_baseline.json`](wave2_frozen_baseline.json). It exits",
            "  `1` on any difference and never silently rewrites the baseline.",
            "- `--freeze-new-baseline` is the only way to replace the frozen",
            "  record, and it is meant for starting a new wave, not for making a",
            "  failing score go away.",
            "- Wave 1 results stay in",
            "  [`EVASION_REPORT.md`](EVASION_REPORT.md) and are never merged into",
            "  this number.",
            "",
        ]
    )

    return "\n".join(lines)


def write_results(results: dict[str, Any]) -> None:
    REPORT_MD.write_text(render_report(results), encoding="utf-8")


def load_baseline() -> dict[str, Any] | None:
    if not BASELINE_JSON.exists():
        return None
    return json.loads(BASELINE_JSON.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--freeze-new-baseline",
        action="store_true",
        help="replace wave2_frozen_baseline.json with this run's results",
    )
    args = parser.parse_args(argv)

    results = compute_results()
    write_results(results)

    frozen = load_baseline()
    if frozen is None or args.freeze_new_baseline:
        BASELINE_JSON.write_text(_dump(results), encoding="utf-8")
        action = "Froze new baseline" if frozen is not None else "Froze first-run baseline"
        print(f"{action}: {BASELINE_JSON}")
    elif _dump(frozen) != _dump(results):
        differing = [
            row["probe_id"]
            for row, before in zip(
                results["probes"], frozen.get("probes", []), strict=False
            )
            if row["latch_flagged"] != before.get("latch_flagged")
            or row["latch_signals"] != before.get("latch_signals")
        ]
        print("Wave 2 results differ from the frozen first-run baseline.")
        print(f"  differing probes: {', '.join(differing) or '(metrics only)'}")
        print("  re-run with --freeze-new-baseline only to start a new wave.")
        print(f"Wrote {REPORT_MD}")
        return 1
    else:
        print(f"Verified against frozen baseline: {BASELINE_JSON}")

    metrics = results["metrics"]
    print(
        f"  Blind score: TP={metrics['true_positives']}"
        f" FP={metrics['false_positives']}"
        f" TN={metrics['true_negatives']}"
        f" FN={metrics['false_negatives']}"
        f" (precision {metrics['precision']:.2f}, recall"
        f" {metrics['recall']:.2f}, FPR {metrics['false_positive_rate']:.2f})"
    )
    print(f"Wrote {REPORT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
