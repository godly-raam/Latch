"""Tests for the head-to-head scanner comparison."""

from __future__ import annotations

import json
from pathlib import Path

from head_to_head.run_comparison import (
    RESULTS_JSON,
    REPORT_MD,
    compute_results,
    main,
    render_report,
)

ROOT = Path(__file__).resolve().parents[1]


def test_artifacts_match_recomputation() -> None:
    assert RESULTS_JSON.exists()
    assert REPORT_MD.exists()

    results = compute_results()
    assert json.loads(RESULTS_JSON.read_text(encoding="utf-8")) == results
    assert REPORT_MD.read_text(encoding="utf-8") == render_report(results)
    assert compute_results() == results


def test_live_scanner_metrics() -> None:
    metrics = compute_results()["metrics"]

    assert metrics["package_count"] == 5
    assert metrics["latch_flagged_packages"] == ["npm-server-everything"]
    assert metrics["latch_package_false_positive_rate"] == 0.2
    assert metrics["naive_package_false_positive_rate"] == 0.8
    assert set(metrics["naive_flagged_packages"]) == {
        "npm-server-everything",
        "npm-server-filesystem",
        "pypi-mcp-server-fetch",
        "pypi-mcp-server-git",
    }

    assert metrics["scenario_count"] == 10
    assert metrics["latch_scenarios_detected"] == 10
    assert metrics["latch_scenario_recall"] == 1.0
    assert metrics["latch_scenarios_missed"] == []
    assert metrics["naive_scenarios_detected"] == 7


def test_every_protocol_scenario_declares_what_fired() -> None:
    results = compute_results()
    scenarios = {row["scenario_id"]: row for row in results["scenarios"]}

    assert set(scenarios) == {
        "post_approval_schema_rug_pull",
        "live_list_changed_drift",
        "unicode_tag_smuggling",
        "x_mcp_header_authorization",
        "cyrillic_homoglyph_shadow",
        "cross_tool_hijack",
        "cross_server_lethal_trifecta",
        "runtime_ssrf_guard_vs_confirmed_exfil",
        "rfc9728_prm_resource_mismatch",
        "cross_server_bearer_reuse",
    }
    for row in scenarios.values():
        assert row["latch_detected"] is True
        assert row["latch_rules"], row["scenario_id"]

    live = scenarios["runtime_ssrf_guard_vs_confirmed_exfil"]["live"]
    statuses = [status for run in live["runs"] for status in run["statuses"]]
    assert "CONFIRMED_EXPLOITABLE" in statuses
    assert "UNCONFIRMED_SSRF_GUARD" in statuses

    drift = scenarios["live_list_changed_drift"]
    assert "watch:MODIFIED_TOOL" in drift["latch_rules"]


def test_third_party_rows_are_explicit_about_measurement() -> None:
    results = compute_results()
    third_party = {row["tool"]: row for row in results["third_party"]}
    assert set(third_party) == {"mcp-scan", "agent-latch"}
    for row in third_party.values():
        assert row["status"] in {"installed", "not_installed_in_env"}
        if row["status"] == "installed":
            assert row["path"]
        else:
            assert row["path"] is None

    assert len(results["architectural_matrix"]) == 3
    for row in results["architectural_matrix"]:
        for key in (
            "tool",
            "lockfiles",
            "live_drift",
            "manifest_audit",
            "cross_server",
            "active_probe",
            "shadowing",
            "auth",
            "output",
            "dependency",
            "source",
        ):
            assert row[key], (row["tool"], key)


def test_report_separates_measured_from_documented() -> None:
    report = REPORT_MD.read_text(encoding="utf-8")
    assert "# Head-to-head" in report
    assert "documented architecture" in report
    assert "Architectural and detection matrix" in report
    assert "AgentLatch" in report
    assert "mcp-scan" in report
    assert "Honest limits of this comparison" in report
    assert "not installed" in report or not any(
        row["status"] != "installed" for row in compute_results()["third_party"]
    )


def test_writing_twice_is_byte_identical() -> None:
    before_json = RESULTS_JSON.read_bytes()
    before_md = REPORT_MD.read_bytes()
    assert main() == 0
    assert RESULTS_JSON.read_bytes() == before_json
    assert REPORT_MD.read_bytes() == before_md
