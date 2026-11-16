"""Tests for the real-world CVE & upstream reference evaluation suite."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cve_eval.cases import CASES, POST_PATCH_CASES, PRE_PATCH_CASES, CveEvalCase
from cve_eval.run_cve_eval import (
    REPORT_MD,
    RESULTS_JSON,
    compute_results,
    main,
    render_report,
)

ROOT = Path(__file__).resolve().parents[1]

OUT_OF_SCOPE_REFS = {"CVE-2025-FILESYSTEM-TRAVERSAL", "CVE-2025-POSTGRES-SQLI"}


@pytest.fixture(scope="module")
def results() -> dict:
    return compute_results()


def test_corpus_size_and_status_split() -> None:
    assert len(CASES) == 24
    assert len(PRE_PATCH_CASES) == 12
    assert len(POST_PATCH_CASES) == 12
    assert len({case.case_id for case in CASES}) == 24

    pre = [case for case in CASES if case.status == "pre_patch_vulnerable"]
    post = [case for case in CASES if case.status == "post_patch_fixed"]
    upstream = [case for case in CASES if case.status == "upstream_reference"]
    assert len(pre) == 12
    assert len(post) == 8
    assert len(upstream) == 4

    # Every pre-patch target is expected to be a real vulnerability; every
    # post-patch and upstream reference target must stay clean.
    assert all(case.expected_positive for case in pre)
    assert all(not case.expected_positive for case in post + upstream)

    # 22 of the 24 targets sit inside Latch's protocol/flow threat model: 10
    # pre-patch positives plus all 12 non-positive counterparts.
    in_scope = [case for case in CASES if case.in_latch_threat_model]
    assert len(in_scope) == 22
    assert len([case for case in in_scope if case.expected_positive]) == 10


def test_corpus_declares_out_of_scope_implementation_bugs() -> None:
    out_of_scope = [
        case
        for case in CASES
        if not case.in_latch_threat_model and case.expected_positive
    ]
    assert {case.advisory_ref for case in out_of_scope} == OUT_OF_SCOPE_REFS
    assert all(case.status == "pre_patch_vulnerable" for case in out_of_scope)


def test_each_case_carries_payloads_for_its_engines() -> None:
    for case in CASES:
        assert isinstance(case, CveEvalCase)
        assert case.engines_used, case.case_id
        assert case.notes, case.case_id

        if "verify" in case.engines_used:
            assert case.manifest_payload is not None, case.case_id
            assert case.lockfile_payload is not None, case.case_id
        if "audit" in case.engines_used:
            assert case.audit_payload is not None, case.case_id
        if "graph" in case.engines_used:
            assert case.graph_servers, case.case_id
        if "shadow" in case.engines_used:
            assert case.shadow_servers, case.case_id
        if "auth-audit" in case.engines_used:
            assert case.auth_specs, case.case_id
        if "probe-chain" in case.engines_used:
            assert case.live_chain_specs, case.case_id
            assert case.graph_servers, case.case_id


def test_in_scope_metrics_are_perfect(results: dict) -> None:
    metrics = results["in_scope"]
    assert results["in_scope_case_count"] == 22
    assert (metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]) == (
        10,
        0,
        12,
        0,
    )
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["fpr"] == 0.0


def test_overall_metrics_record_honest_misses(results: dict) -> None:
    metrics = results["overall"]
    assert (metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]) == (
        10,
        0,
        12,
        2,
    )
    assert metrics["recall"] == pytest.approx(10 / 12, abs=1e-4)
    assert metrics["f1"] == pytest.approx(0.9091, abs=1e-4)
    assert metrics["fpr"] == 0.0

    missed = [
        row["advisory_ref"]
        for row in results["cases"]
        if row["expected_positive"] and not row["latch_flagged"]
    ]
    assert set(missed) == OUT_OF_SCOPE_REFS


def test_no_false_positives_on_post_patch_or_upstream(results: dict) -> None:
    non_positives = [row for row in results["cases"] if not row["expected_positive"]]
    assert len(non_positives) == 12
    assert [row["case_id"] for row in non_positives if row["latch_flagged"]] == []

    upstream = [row for row in results["cases"] if row["status"] == "upstream_reference"]
    assert len(upstream) == 4
    assert all(row["latch_signals"] == {"audit": False, "graph": False} for row in upstream)


def test_detections_come_from_the_declared_engines(results: dict) -> None:
    for row in results["cases"]:
        assert set(row["latch_signals"]) == set(row["engines_used"]), row["case_id"]

    positives = [row for row in results["cases"] if row["expected_positive"]]
    for row in positives:
        if row["in_latch_threat_model"]:
            assert row["latch_flagged"], row["case_id"]
            assert any(row["latch_signals"].values()), row["case_id"]


def test_execution_aware_probe_confirms_pre_patch_exploit(results: dict) -> None:
    [row] = [row for row in results["cases"] if row["case_id"] == "MCP-RUNTIME-ALLOWLIST-pre"]
    assert row["static_graph_flagged"] is True
    assert row["latch_flagged"] is True
    probe = row["probe"]
    assert probe is not None
    assert probe["status"] == "CONFIRMED_EXPLOITABLE"
    assert probe["confirmed_exploitable"] == 1
    assert probe["sink_request_summary"] == "POST /exfil (matched body)"


def test_probe_chain_eliminates_static_false_positive_on_allowlist_patch(
    results: dict,
) -> None:
    [row] = [row for row in results["cases"] if row["case_id"] == "MCP-RUNTIME-ALLOWLIST-post"]
    # Identical schema, so static graph still reports the theoretical path...
    assert row["static_graph_flagged"] is True
    # ...but execution-aware probing proves the runtime guard blocks it.
    assert row["latch_flagged"] is False
    probe = row["probe"]
    assert probe is not None
    assert probe["status"] == "BLOCKED_AT_EGRESS"
    assert probe["confirmed_exploitable"] == 0
    assert "allowlist" in (probe["block_reason"] or "")

    comparison = results["execution_aware_comparison"]
    assert comparison == {
        "case_id": "MCP-RUNTIME-ALLOWLIST-post",
        "static_graph_flagged": True,
        "probe_confirmed": False,
        "probe_status": "BLOCKED_AT_EGRESS",
        "probe_block_reason": probe["block_reason"],
    }


def test_naive_baseline_is_worse_on_the_same_targets(results: dict) -> None:
    naive = results["naive"]
    latch = results["overall"]
    assert naive["fp"] > latch["fp"]
    assert naive["recall"] < latch["recall"]
    assert naive["tp"] < latch["tp"]

    flagged_names = {
        row["case_id"] for row in results["cases"] if row["naive_flagged"]
    }
    # Keywords in benign copy fool the baseline on official reference servers.
    assert {"UPSTREAM-FS", "UPSTREAM-GIT", "UPSTREAM-POSTGRES"} <= flagged_names
    assert {"UPSTREAM-FS", "UPSTREAM-GIT", "UPSTREAM-POSTGRES"} - {
        row["case_id"] for row in results["cases"] if row["latch_flagged"]
    } == {"UPSTREAM-FS", "UPSTREAM-GIT", "UPSTREAM-POSTGRES"}


def test_artifacts_match_deterministic_recomputation(results: dict) -> None:
    assert RESULTS_JSON.exists()
    assert REPORT_MD.exists()

    assert json.loads(RESULTS_JSON.read_text(encoding="utf-8")) == results
    assert REPORT_MD.read_text(encoding="utf-8") == render_report(results)
    # Recomputing from scratch must reproduce the same verdicts (live probes
    # included: only deterministic fields are recorded).
    assert compute_results() == results


def test_writing_artifacts_twice_is_byte_identical(results: dict) -> None:
    before_json = RESULTS_JSON.read_bytes()
    before_md = REPORT_MD.read_bytes()
    main()
    assert RESULTS_JSON.read_bytes() == before_json
    assert REPORT_MD.read_bytes() == before_md


def test_module_cli_runs_and_reports_metrics() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "cve_eval.run_cve_eval"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    assert "In-scope (22 targets)" in completed.stdout
    assert "10   0  12   0" in completed.stdout
    assert "Overall (24 targets)" in completed.stdout
    assert "MCP-RUNTIME-ALLOWLIST-post" in completed.stdout


def test_report_documents_boundaries_and_limitations(results: dict) -> None:
    report = REPORT_MD.read_text(encoding="utf-8")
    assert "## Threat Model Boundaries & Honest Limitations" in report
    assert "## Static-only vs. execution-aware verification" in report
    assert "BLOCKED_AT_EGRESS" in report
    for ref in OUT_OF_SCOPE_REFS:
        assert ref in report
    assert "| **Latch** | 10 | 0 | 12 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |" in report
    assert "| **Latch** | 10 | 0 | 12 | 2 | 1.00 | 0.83 | 0.91 | 0.00 |" in report
    for case in CASES:
        assert f"| `{case.case_id}` | {case.advisory_ref} |" in report, case.case_id
