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

    assert metrics["package_count"] == 9
    assert metrics["clean_package_count"] == 5
    # `mcp-remote` and `mcp-proxy` are true detections, so only the SDK
    # diagnostics server counts against Latch's false-positive rate.
    assert metrics["latch_flagged_packages"] == [
        "npm-mcp-remote-0-14-3",
        "npm-server-everything",
        "pypi-mcp-proxy-0-8-2",
    ]
    assert metrics["latch_package_false_positive_rate"] == 0.2
    assert metrics["naive_package_false_positive_rate"] >= 0.8
    assert set(metrics["naive_flagged_packages"]) >= {
        "npm-server-everything",
        "npm-server-filesystem",
        "pypi-mcp-server-fetch",
        "pypi-mcp-server-git",
    }
    assert set(metrics["latch_in_model_detected"]) == {
        "npm-mcp-remote-0-14-3",
        "pypi-mcp-proxy-0-8-2",
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

    peer = third_party["mcp-scan"]
    assert peer["status"] in {
        "measured",
        "measured_unparsed",
        "credentials_required",
        "blocked_unauthorized",
        "blocked_network_error",
        "blocked_timeout",
        "not_installed_in_env",
    }
    measurement = peer["measurement"]
    assert measurement["tool"] == "mcp-scan"
    assert measurement["status"] == peer["status"]
    assert isinstance(measurement["version"], str) and measurement["version"]
    assert isinstance(measurement["cache_key"], str) and len(measurement["cache_key"]) == 64
    if measurement["status"] == "not_installed_in_env":
        assert peer["path"] is None
        assert measurement["command"] is None
    else:
        assert peer["path"]
        assert measurement["command"][:2] == ["snyk-agent-scan", "scan"]
        assert isinstance(measurement["exit_code"], int)
        assert measurement["remote_api_required"] is True

    if measurement["status"] in {"measured", "measured_unparsed"}:
        assert measurement["parsed"] is True
        assert set(measurement["package_flags"]) <= set(measurement["packages"])
        assert isinstance(measurement["clean_false_positive_rate"], float)
    else:
        assert measurement["package_flags"] == {}
        assert measurement["clean_false_positive_rate"] is None
        assert measurement["reason"], measurement
        for row in results["packages"]:
            assert row["peer_flagged"] is None

    latch = third_party["agent-latch"]
    assert latch["status"] in {"installed", "architectural_comparison_only"}
    if latch["status"] == "installed":
        assert latch["path"]
    else:
        assert latch["path"] is None

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


def test_report_leads_with_the_measured_comparison() -> None:
    results = compute_results()
    report = REPORT_MD.read_text(encoding="utf-8")

    assert report.startswith("# mcpprobe (Latch): measured real-package comparison")
    assert "## Headline: measured on real captured packages" in report
    assert "0.20 (1/5)" in report
    assert "0.80 (4/5)" in report
    assert "Architectural and detection matrix" in report
    assert "AgentLatch" in report
    assert "Honest limits of this comparison" in report

    measurement = results["mcp_scan_measurement"]
    assert f"`{measurement['status']}`" in report
    assert "snyk-agent-scan scan" in report
    if measurement["status"] == "credentials_required":
        assert "SNYK_TOKEN" in report
        assert "could not obtain a **measured** peer verdict" in report


def test_self_authored_scenarios_are_an_appendix() -> None:
    report = REPORT_MD.read_text(encoding="utf-8")
    flat = " ".join(report.replace(">", " ").split())

    appendix = "## Appendix: Self-Authored Protocol Feature Coverage Demo (10/10)"
    assert appendix in report
    assert "Feature Coverage Check, Not a Generalization Benchmark" in flat
    assert report.index(appendix) > report.index("Architectural and detection matrix")
    assert report.index(appendix) > report.index("Honest limits")
    assert "Ten canonical protocol and agentic-risk scenarios" not in report
    assert "Feature coverage: Latch fires on 10/10" in report


def test_measured_peer_column_appears_only_when_measured() -> None:
    results = compute_results()
    measurement = results["mcp_scan_measurement"]
    report = REPORT_MD.read_text(encoding="utf-8")
    assert "| mcp-scan |" in report

    if measurement["parsed"]:
        flagged = measurement["flagged_packages"]
        for row in results["packages"]:
            if row["slug"] in measurement["package_flags"]:
                assert row["peer_flagged"] is (row["slug"] in flagged)
    else:
        assert all(row["peer_flagged"] is None for row in results["packages"])
        assert "produced a parseable live verdict" in report


def test_writing_twice_is_byte_identical() -> None:
    before_json = RESULTS_JSON.read_bytes()
    before_md = REPORT_MD.read_bytes()
    assert main() == 0
    assert RESULTS_JSON.read_bytes() == before_json
    assert REPORT_MD.read_bytes() == before_md
