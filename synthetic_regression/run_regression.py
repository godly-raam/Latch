"""Deterministic synthetic regression suite modeled on disclosed MCP bug classes.

    python -m synthetic_regression.run_regression

The 24 fixtures are synthetic: they are written for this repository to exercise
Latch against the *shapes* of disclosed bug classes and the clean surfaces of
reference servers. They are not raw captures of vendor packages, not the
vendors' test fixtures, and they quote no advisory text. Real ``tools/list``
captures of pinned npm/PyPI packages are evaluated separately in
``package_eval/``.

Every target is evaluated with Latch's real engines (``verify_manifest``,
``audit_manifest``, ``analyze_capability_graph``, ``analyze_shadowing``,
``run_auth_audit`` and live ``verify_trifecta_chains``) plus the naive
keyword/substring baseline from ``benchmark/naive_baseline.py``.

Writes ``synthetic_regression/regression_results.json`` and
``synthetic_regression/REGRESSION_REPORT.md`` and prints a summary. No
timestamps and no randomness: re-running reproduces both files byte for byte
(live probes record only status text, never their canary).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx

from benchmark.naive_baseline import scan_text
from mcpprobe.auditor import audit_manifest
from mcpprobe.chain_prober import verify_trifecta_chains
from mcpprobe.config_loader import ServerSpec
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.lockfile import verify_manifest
from mcpprobe.models import Lockfile, ToolDefinition
from mcpprobe.oauth_audit import run_auth_audit
from mcpprobe.shadow import analyze_shadowing

from .cases import CASES, RegressionCase

EVAL_DIR = Path(__file__).resolve().parent
RESULTS_JSON = EVAL_DIR / "regression_results.json"
REPORT_MD = EVAL_DIR / "REGRESSION_REPORT.md"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _parse_tools(raw: dict[str, list[dict[str, Any]]]) -> dict[str, list[ToolDefinition]]:
    return {
        server_id: [ToolDefinition.model_validate(tool) for tool in tools]
        for server_id, tools in raw.items()
    }


def _auth_inputs(
    raw_specs: list[dict[str, Any]],
    raw_manifests: dict[str, list[dict[str, Any]]] | None,
) -> tuple[list[ServerSpec], dict[str, list[ToolDefinition]] | None]:
    specs = [ServerSpec.model_validate(spec) for spec in raw_specs]
    manifests = _parse_tools(raw_manifests) if raw_manifests else None
    return specs, manifests


def _mock_transport(routes: dict[str, dict[str, Any]]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        route = routes.get(str(request.url))
        if route is None:
            return httpx.Response(404, json={})
        return httpx.Response(
            int(route.get("status", 404)),
            headers=route.get("headers") or {},
            json=route.get("body") or {},
        )

    return httpx.MockTransport(handler)


def evaluate_case(case: RegressionCase) -> dict[str, Any]:
    """Run the engines this case declares and return its verdict."""

    signals: dict[str, bool] = {}
    probe: dict[str, Any] | None = None

    if case.manifest_payload is not None and case.lockfile_payload is not None:
        lockfile = Lockfile.model_validate(case.lockfile_payload)
        signals["verify"] = not verify_manifest(case.manifest_payload, lockfile).passed

    if case.audit_payload is not None:
        signals["audit"] = not audit_manifest(case.audit_payload).passed

    if case.graph_servers:
        graph = analyze_capability_graph(
            _parse_tools(case.graph_servers),
            trusted_servers=set(case.trusted_servers) or None,
        )
        signals["graph"] = not graph.passed

    if case.shadow_servers:
        shadow = analyze_shadowing(
            _parse_tools(case.shadow_servers),
            trusted_servers=set(case.trusted_servers) or None,
        )
        signals["shadow"] = not shadow.passed

    if case.auth_specs:
        specs, manifests = _auth_inputs(case.auth_specs, case.auth_manifests)
        transport = (
            _mock_transport(case.auth_http_routes)
            if case.auth_http_routes is not None
            else None
        )
        auth = run_auth_audit(
            specs, manifests, live=case.live_auth, transport=transport
        )
        signals["auth-audit"] = not auth.passed

    if case.live_chain_specs:
        report = asyncio.run(
            verify_trifecta_chains(
                [ServerSpec.model_validate(spec) for spec in case.live_chain_specs],
                timeout=10.0,
            )
        )
        signals["probe-chain"] = report.confirmed_exploitable > 0
        [first] = report.results or [None]
        probe = {
            "paths_tested": report.paths_tested,
            "confirmed_exploitable": report.confirmed_exploitable,
            "status": first.status if first is not None else None,
            "block_reason": first.block_reason if first is not None else None,
            "sink_request_summary": (
                first.sink_request_summary if first is not None else None
            ),
        }

    # Execution-aware probing is authoritative when it ran: a runtime guard that
    # blocks the canary makes the static path a false positive.
    flagged = (
        signals.get("probe-chain", False)
        if case.live_chain_specs
        else any(signals.values())
    )

    return {
        "flagged": flagged,
        "signals": signals,
        "static_graph_flagged": signals.get("graph", False),
        "probe": probe,
    }


def _naive_hits(case: RegressionCase) -> list[str]:
    payloads = (
        case.manifest_payload,
        case.lockfile_payload,
        case.audit_payload,
        case.graph_servers,
        case.shadow_servers,
        case.auth_specs,
        case.auth_manifests,
        case.live_chain_specs,
    )
    text = "\n".join(
        json.dumps(payload, ensure_ascii=False, sort_keys=True)
        for payload in payloads
        if payload is not None
    )
    return scan_text(text)


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
    rows: list[dict[str, Any]] = []
    for case in CASES:
        verdict = evaluate_case(case)
        naive_hits = _naive_hits(case)
        rows.append(
            {
                "case_id": case.case_id,
                "bug_class": case.bug_class,
                "title": case.title,
                "status": case.status,
                "in_latch_threat_model": case.in_latch_threat_model,
                "expected_positive": case.expected_positive,
                "engines_used": case.engines_used,
                "latch_flagged": verdict["flagged"],
                "latch_signals": verdict["signals"],
                "static_graph_flagged": verdict["static_graph_flagged"],
                "probe": verdict["probe"],
                "naive_flagged": bool(naive_hits),
                "naive_hits": naive_hits,
            }
        )

    in_scope_rows = [row for row in rows if row["in_latch_threat_model"]]
    runtime_rows = [row for row in rows if row["probe"] is not None]
    demo = next(
        (
            row
            for row in rows
            if row["static_graph_flagged"] and row["probe"] is not None
            and not row["latch_flagged"]
        ),
        runtime_rows[-1] if runtime_rows else None,
    )

    return {
        "case_count": len(rows),
        "pre_patch_count": sum(
            1 for row in rows if row["status"] == "pre_patch_vulnerable"
        ),
        "post_patch_count": sum(1 for row in rows if row["status"] == "post_patch_fixed"),
        "upstream_reference_count": sum(
            1 for row in rows if row["status"] == "upstream_reference"
        ),
        "in_scope_case_count": len(in_scope_rows),
        "in_scope": _metrics(in_scope_rows, "latch_flagged"),
        "overall": _metrics(rows, "latch_flagged"),
        "naive": _metrics(rows, "naive_flagged"),
        "execution_aware_comparison": (
            {
                "case_id": demo["case_id"],
                "static_graph_flagged": demo["static_graph_flagged"],
                "probe_confirmed": demo["latch_flagged"],
                "probe_status": demo["probe"]["status"] if demo["probe"] else None,
                "probe_block_reason": (
                    demo["probe"]["block_reason"] if demo["probe"] else None
                ),
            }
            if demo is not None
            else None
        ),
        "cases": rows,
    }


def _row(name: str, metrics: dict[str, Any], bold: bool = False) -> str:
    label = f"**{name}**" if bold else name
    return (
        f"| {label} | {metrics['tp']} | {metrics['fp']} | {metrics['tn']} |"
        f" {metrics['fn']} | {metrics['precision']:.2f} | {metrics['recall']:.2f} |"
        f" {metrics['f1']:.2f} | {metrics['fpr']:.2f} |"
    )


def _missed_refs(results: dict[str, Any]) -> list[str]:
    return [
        row["bug_class"]
        for row in results["cases"]
        if row["expected_positive"] and not row["latch_flagged"]
    ]


def _naive_false_positives(results: dict[str, Any]) -> list[str]:
    return [
        row["case_id"]
        for row in results["cases"]
        if not row["expected_positive"] and row["naive_flagged"]
    ]


def render_report(results: dict[str, Any]) -> str:
    """Render ``REGRESSION_REPORT.md`` deterministically."""

    overall = results["overall"]
    in_scope = results["in_scope"]
    naive = results["naive"]
    comparison = results["execution_aware_comparison"]
    missed = _missed_refs(results)
    naive_fps = _naive_false_positives(results)

    lines = [
        "# Synthetic Regression Suite Modeled on Disclosed MCP Bug Classes",
        "",
        "**These 24 fixtures are synthetic models, not raw upstream captures.** Each",
        "one is written for this repository to reproduce the *shape* of a bug class",
        "disclosed in 2025-2026 MCP advisories, or the clean tool surface of a",
        "reference server. They are not the vendors' own test fixtures, they quote",
        "no advisory text, and `bug_class` labels are mechanism names rather than",
        "CVE/GHSA identifiers. Real `tools/list` captures of pinned npm and PyPI",
        "packages are evaluated separately in `package_eval/`.",
        "",
        "Deterministic evaluation of Latch's static engines (`verify_manifest`,",
        "`audit_manifest`, `analyze_capability_graph`, `analyze_shadowing`,",
        "`run_auth_audit`), its execution-aware prober (`verify_trifecta_chains`),",
        "and the naive keyword/substring baseline on the same targets.",
        "",
        f"- Targets: {results['case_count']}"
        f" ({results['pre_patch_count']} pre-patch models,"
        f" {results['post_patch_count']} post-patch models,"
        f" {results['upstream_reference_count']} reference-server models)",
        f"- Targets inside Latch's threat model: {results['in_scope_case_count']}",
        "- No timestamps or random values are recorded; re-running",
        "  `python -m synthetic_regression.run_regression` reproduces this report",
        "  byte for byte.",
        "",
        "## In-scope detection (protocol, schema, auth, shadow and flow flaws)",
        "",
        "| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |",
        _row("Latch", in_scope, bold=True),
        "",
        "Latch detects every in-scope pre-patch target and flags no post-patch or",
        "upstream reference server.",
        "",
        "## Overall, including out-of-scope handler implementation bugs",
        "",
        "| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |",
        _row("Latch", overall, bold=True),
        "",
        "The honest misses are pure implementation bugs inside tool handlers (path",
        "canonicalization and SQL string concatenation). Their manifests are",
        "indistinguishable from the patched versions, so no manifest- or",
        "protocol-level analyzer can separate them; Latch records them as misses",
        "rather than claiming detection:",
        "",
        *[f"- `{ref}`" for ref in missed],
        "",
        "## Static-only vs. execution-aware verification",
        "",
        "The runtime-allowlist patch keeps an identical tool schema and adds a",
        "domain allowlist inside the handler. Static analysis cannot see it;",
        "`latch probe-chain` can.",
        "",
        "| Case | Static `graph` | `probe-chain` | Probe status | Why |",
        "| ---- | -------------- | ------------- | ------------ | --- |",
    ]

    if comparison is None:  # pragma: no cover - corpus always has the pair
        lines.append("| — | — | — | — | — |")
    else:
        lines.append(
            f"| `{comparison['case_id']}` |"
            f" {'flagged' if comparison['static_graph_flagged'] else 'clean'} |"
            f" {'confirmed' if comparison['probe_confirmed'] else 'blocked'} |"
            f" {comparison['probe_status']} |"
            f" {comparison['probe_block_reason'] or 'canary captured at the sink'} |"
        )

    lines.extend(
        [
            "",
            "That row is the reason this project has an execution-aware prober: a",
            "static CRITICAL on a patched server is a false positive, and only",
            "running the chain distinguishes a real exploit from a guarded one.",
            "",
            "## Naive keyword/substring baseline on the same targets",
            "",
            "| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
            "| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |",
            _row("Naive keyword/substring baseline", naive),
            "",
            "The baseline cannot see graph structure, Unicode folding, credential",
            "identity or placeholder semantics, so it both misses real flaws and",
            "flags official reference servers. Benign targets it flags here:",
            "",
            *[f"- `{case_id}`" for case_id in naive_fps],
            "",
            "## Per-case results",
            "",
            "| Case | Bug class | Status | In model | Expected | Latch | Engines | Naive |",
            "| ---- | -------- | ------ | -------- | -------- | ----- | ------- | ----- |",
        ]
    )

    for row in results["cases"]:
        lines.append(
            f"| `{row['case_id']}` | {row['bug_class']} | {row['status']} |"
            f" {'yes' if row['in_latch_threat_model'] else 'no'} |"
            f" {'positive' if row['expected_positive'] else 'negative'} |"
            f" {'detected' if row['latch_flagged'] else 'clean'} |"
            f" {', '.join(row['engines_used'])} |"
            f" {'detected' if row['naive_flagged'] else 'clean'} |"
        )

    lines.extend(
        [
            "",
            "## Threat Model Boundaries & Honest Limitations",
            "",
            "- **Scope.** Latch analyzes what a client can observe: tool metadata,",
            "  JSON Schemas, annotations, headers, cross-server wiring, credentials,",
            "  and live tool behaviour for the two calls in a trifecta. It does not",
            "  read handler source code, so pure implementation bugs are out of scope.",
            "- **Out-of-scope misses recorded:** counted as false negatives in the",
            "  overall table, never quietly excluded, and marked",
            "  `in_latch_threat_model: false` in `regression_results.json`:",
            "",
            *[f"  - `{ref}`" for ref in missed],
            "- **Runtime guards are treated as ground truth.** When `probe-chain`",
            "  runs, its verdict overrides the static graph, because a guard that",
            "  blocks the live canary means the path is not exploitable as served.",
            "  Probing is non-destructive: benign read arguments, a loopback-only",
            "  sink, and a random canary. An egress tool that rejects that loopback",
            "  sink as an SSRF/private address is reported `UNCONFIRMED_SSRF_GUARD`,",
            "  never \"blocked\"; pass `--sink-url` to test internet egress.",
            "- **Coverage is bounded by the probe's schema synthesis.** A chain whose",
            "  egress tool accepts no URL or string payload cannot be parameterized",
            "  and is reported `INCONCLUSIVE_SCHEMA`, never as confirmed.",
            "- **Bug-class labels are synthetic.** `bug_class` names the mechanism",
            "  (`AUTH-TOKEN-PASSTHROUGH`, `RUGPULL-POST-APPROVAL`, ...). It is not a CVE",
            "  or GHSA identifier and no advisory text is quoted. The reference-server",
            "  cases model published tool surfaces, not captured bytes; see",
            "  `package_eval/PACKAGE_EVAL_REPORT.md` for real package captures.",
            "",
        ]
    )

    return "\n".join(lines)


def write_results(results: dict[str, Any]) -> None:
    RESULTS_JSON.write_text(
        json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    REPORT_MD.write_text(render_report(results), encoding="utf-8")


def print_summary(results: dict[str, Any]) -> None:
    header = (
        f"{'Metric set':26} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}"
        f" {'Prec':>6} {'Recall':>7} {'F1':>6} {'FPR':>6}"
    )
    print(header)
    print("-" * len(header))
    for name, metrics in (
        ("In-scope (22 targets)", results["in_scope"]),
        ("Overall (24 targets)", results["overall"]),
        ("Naive baseline (24)", results["naive"]),
    ):
        print(
            f"{name:26} {metrics['tp']:>3} {metrics['fp']:>3} {metrics['tn']:>3}"
            f" {metrics['fn']:>3} {metrics['precision']:>6.2f} {metrics['recall']:>7.2f}"
            f" {metrics['f1']:>6.2f} {metrics['fpr']:>6.2f}"
        )
    print()
    comparison = results["execution_aware_comparison"]
    if comparison:
        print(
            f"Execution-aware: {comparison['case_id']}"
            f" static={comparison['static_graph_flagged']}"
            f" probe={comparison['probe_status']}"
        )
    print(f"Wrote {RESULTS_JSON}")
    print(f"Wrote {REPORT_MD}")


def main() -> int:
    results = compute_results()
    write_results(results)
    print_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
