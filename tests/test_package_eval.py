"""Tests for the real pinned-package capture and blind evaluation harness."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from package_eval.capture_manifests import (
    MANIFEST_DIR,
    manifest_digest,
)
from package_eval.run_package_eval import (
    REPORT_MD,
    RESULTS_JSON,
    compute_results,
    main,
    render_report,
    write_results,
)

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_REPORT = ROOT / "package_eval" / "capture_report.json"

REFERENCE_SLUGS = {
    "npm-mcp-remote-0-14-3",
    "npm-mcp-remote-0-14-3-static-header",
    "npm-server-everything",
    "npm-server-filesystem",
    "npm-server-filesystem-0-6-2",
    "npm-server-github-2025-4-8",
    "npm-server-memory",
    "npm-server-puppeteer-2025-5-12",
    "npm-server-slack-2025-4-25",
    "npm-supergateway-3-1-0",
    "pypi-mcp-proxy-0-8-2",
    "pypi-mcp-server-fetch",
    "pypi-mcp-server-git",
    "pypi-mcp-server-git-2025-9-25",
}

CLEAN_SLUGS = {
    "npm-server-filesystem",
    "npm-server-memory",
    "npm-server-puppeteer-2025-5-12",
    "pypi-mcp-server-fetch",
    "pypi-mcp-server-git",
}

#: Real servers whose own published surface is a complete trifecta.
TRIFECTA_SLUGS = {
    "npm-server-github-2025-4-8",
    "npm-server-slack-2025-4-25",
}

HANDLER_CVE_SLUGS = {
    "npm-server-filesystem-0-6-2": ["CVE-2025-53109", "CVE-2025-53110"],
    "pypi-mcp-server-git-2025-9-25": ["CVE-2025-68145", "CVE-2025-68143"],
}


@pytest.fixture(scope="module")
def results() -> dict:
    return compute_results()


def test_captured_manifests_have_real_provenance() -> None:
    paths = sorted(MANIFEST_DIR.glob("*.json"))
    assert len(paths) == len(REFERENCE_SLUGS)
    assert {path.stem for path in paths} == REFERENCE_SLUGS

    for path in paths:
        capture = json.loads(path.read_text(encoding="utf-8"))
        assert capture["capture_source"] in {
            "live_subprocess",
            "live_proxy_metadata",
            "pinned_package_capture",
        }
        for key in (
            "package_name",
            "package_version",
            "ecosystem",
            "kind",
            "launch_command",
            "protocol_version",
            "manifest_sha256",
            "tools",
            "tool_count",
            "in_latch_threat_model",
            "expected_positive",
            "vulnerability_class",
            "cve_refs",
            "note",
        ):
            assert key in capture, (path.name, key)
        assert capture["package_version"] not in ("", "unknown")
        assert isinstance(capture["launch_command"], list)
        assert capture["package_name"]
        assert capture["tool_count"] == len(capture["tools"])
        # The digest is over the captured bytes, so it proves the record is intact.
        assert capture["manifest_sha256"] == manifest_digest(capture["tools"])
        names = [tool["name"] for tool in capture["tools"]]
        assert len(names) == len(set(names)), path.name

        if capture["kind"] == "proxy_metadata":
            # A proxy exposes no tools of its own; its real transport is recorded.
            assert capture["tools"] == []
            assert capture["exposed_url"].startswith(("http://", "https://"))
            assert "Authorization" in capture["exposed_headers"]
        else:
            assert capture["tools"], path.name


def test_prepatch_captures_are_pinned_to_the_vulnerable_release() -> None:
    for slug, cves in HANDLER_CVE_SLUGS.items():
        capture = json.loads(
            (MANIFEST_DIR / f"{slug}.json").read_text(encoding="utf-8")
        )
        assert capture["cve_refs"] == cves
        assert capture["in_latch_threat_model"] is False
        assert capture["vulnerability_class"] == "handler_implementation_cve"
        assert capture["expected_positive"] is True
        pinned = next(
            part
            for part in capture["launch_command"]
            if capture["package_name"] in part
        )
        expected_version = (
            "0.6.2" if slug.startswith("npm-") else "2025.9.25"
        )
        assert expected_version in pinned
        assert capture["package_version"] == expected_version


def test_capture_report_matches_the_captures_on_disk() -> None:
    report = json.loads(CAPTURE_REPORT.read_text(encoding="utf-8"))
    captured_files = sorted(MANIFEST_DIR.glob("*.json"))
    assert report["captured"] == len(captured_files)
    assert report["captured"] + report["skipped"] == len(report["captures"])
    captured_slugs = {
        row["slug"] for row in report["captures"] if row["status"] == "captured"
    }
    assert captured_slugs == {path.stem for path in captured_files}
    assert {row["slug"] for row in report["captures"]} == REFERENCE_SLUGS


def test_clean_reference_servers_stay_clean(results: dict) -> None:
    rows = {row["slug"]: row for row in results["packages"]}
    assert set(rows) == REFERENCE_SLUGS

    for slug in CLEAN_SLUGS:
        assert rows[slug]["latch_flagged"] is False, slug
        assert rows[slug]["findings"] == [], slug
        assert rows[slug]["outcome"] == "true_negative", slug


def test_transport_targets_are_detected_with_the_cleartext_rule(results: dict) -> None:
    rows = {row["slug"]: row for row in results["packages"]}

    for slug in ("npm-mcp-remote-0-14-3", "pypi-mcp-proxy-0-8-2"):
        row = rows[slug]
        assert row["kind"] == "proxy_metadata"
        assert row["in_latch_threat_model"] is True
        assert row["outcome"] == "detected"
        assert row["detected_rule_ids"] == ["INSECURE_HTTP_AUTH_TRANSPORT"]
        assert row["severity_counts"] == {"CRITICAL": 1}
        assert row["exposed_url"].startswith("http://")

    probe = rows["pypi-mcp-proxy-0-8-2"]["transport_probe"]
    cli = probe["cli"]
    assert cli["status"] == "ok"
    transport = probe.get("transport") or {}
    if transport.get("status") == "ok":
        assert transport["http_status"] == 200
        assert transport["content_type"] == "text/event-stream"
        assert transport["authentication_challenge"] is False
        assert transport["cleartext"] is True


def test_handler_cves_are_honest_misses_outside_the_threat_model(
    results: dict,
) -> None:
    rows = {row["slug"]: row for row in results["packages"]}

    for slug in HANDLER_CVE_SLUGS:
        row = rows[slug]
        assert row["in_latch_threat_model"] is False
        assert row["expected_positive"] is True
        assert row["latch_flagged"] is False
        assert row["outcome"] == "missed"

    detection = results["detection"]
    assert set(detection["out_of_model_targets"]) == set(HANDLER_CVE_SLUGS)
    assert detection["out_of_model_detected"] == []


def test_detection_recall_separates_in_scope_from_overall(results: dict) -> None:
    detection = results["detection"]

    assert set(detection["in_scope_targets"]) == {
        "npm-mcp-remote-0-14-3",
        "npm-mcp-remote-0-14-3-static-header",
        "npm-server-github-2025-4-8",
        "npm-server-slack-2025-4-25",
        "npm-supergateway-3-1-0",
        "pypi-mcp-proxy-0-8-2",
        "B",
        "D",
    }
    assert set(detection["in_scope_detected"]) == {
        "npm-mcp-remote-0-14-3",
        "npm-mcp-remote-0-14-3-static-header",
        "npm-server-github-2025-4-8",
        "npm-server-slack-2025-4-25",
        "npm-supergateway-3-1-0",
        "pypi-mcp-proxy-0-8-2",
        "D",
    }
    # The fetch + filesystem composition is a documented blind miss.
    assert detection["in_scope_missed"] == ["B"]
    assert detection["in_scope_recall"] == 0.875

    assert detection["overall_targets"] == 10
    assert detection["overall_recall"] == 0.7
    assert set(detection["overall_missed"]) == {
        "B",
        *HANDLER_CVE_SLUGS,
    }


def test_everything_is_the_documented_false_positive(results: dict) -> None:
    summary = results["summary"]
    assert summary["false_positive_packages"] == ["npm-server-everything"]
    assert summary["clean_package_count"] == 6
    assert summary["latch_false_positive_rate"] == 0.1667
    assert summary["naive_false_positive_rate"] > summary["latch_false_positive_rate"]


def test_graph_precision_fix_collapses_paths(results: dict) -> None:
    compositions = {row["composition_id"]: row for row in results["compositions"]}
    assert set(compositions) == {
        "filesystem-plus-memory",
        "filesystem-plus-git",
        "filesystem-plus-fetch",
        "puppeteer-plus-filesystem",
        "everything-plus-filesystem",
    }

    clean = compositions["filesystem-plus-memory"]
    assert clean["trifecta_path_count"] == 0
    assert clean["latch_flagged"] is False

    git = compositions["filesystem-plus-git"]
    assert git["trifecta_path_count"] == 0
    assert git["severity_counts"].get("CRITICAL", 0) == 0
    assert git["legacy_path_count"] == 27
    assert git["legacy_critical_count"] == 27
    assert "pypi-mcp-server-git:git_commit" in git["local_write_tools"]
    assert "npm-server-filesystem:write_file" in git["local_write_tools"]

    everything = compositions["everything-plus-filesystem"]
    assert everything["trifecta_path_count"] == 11
    assert everything["legacy_path_count"] == 314
    assert everything["trifecta_path_count"] < everything["legacy_path_count"]
    # Every emitted path stands for several read tools instead of one row each.
    assert everything["collapsed_read_tools"] > everything["trifecta_path_count"]
    for path in everything["trifecta_paths"]:
        assert path["collapsed_read_count"] >= 1
        assert len(path["read_tools"]) == path["collapsed_read_count"]


def test_single_server_trifectas_are_detected(results: dict) -> None:
    rows = {row["slug"]: row for row in results["packages"]}

    for slug in TRIFECTA_SLUGS:
        row = rows[slug]
        assert row["expected_positive"] is True
        assert row["in_latch_threat_model"] is True
        assert row["outcome"] == "detected", slug
        assert row["detected_rule_ids"] == ["LETHAL_TRIFECTA"], slug
        # One server is not cross-server and has no caller-chosen URL sink, so
        # every path is HIGH rather than CRITICAL.
        assert set(row["severity_counts"]) == {"HIGH"}, slug
        assert row["severity_counts"]["HIGH"] >= 1, slug

    github = rows["npm-server-github-2025-4-8"]
    assert {
        "get_issue",
        "list_issues",
        "get_file_contents",
        "create_issue",
        "add_issue_comment",
    } <= set(github["tool_names"])
    slack = rows["npm-server-slack-2025-4-25"]
    assert {
        "slack_get_channel_history",
        "slack_get_thread_replies",
        "slack_post_message",
    } <= set(slack["tool_names"])


def test_credential_and_transport_targets_name_their_rule(results: dict) -> None:
    rows = {row["slug"]: row for row in results["packages"]}

    gateway = rows["npm-supergateway-3-1-0"]
    assert gateway["outcome"] == "detected"
    assert gateway["detected_rule_ids"] == ["INSECURE_HTTP_AUTH_TRANSPORT"]
    assert gateway["exposed_url"].startswith("http://")

    static = rows["npm-mcp-remote-0-14-3-static-header"]
    assert static["outcome"] == "detected"
    assert static["detected_rule_ids"] == ["HARDCODED_STATIC_CREDENTIAL"]
    assert static["exposed_url"].startswith("https://")


def test_puppeteer_composition_is_a_cross_server_trifecta(results: dict) -> None:
    compositions = {row["composition_id"]: row for row in results["compositions"]}

    target = compositions["puppeteer-plus-filesystem"]
    assert target["target_id"] == "D"
    assert target["expected_positive"] is True
    assert target["in_latch_threat_model"] is True
    assert target["outcome"] == "detected"
    assert target["trifecta_path_count"] >= 1
    assert target["cross_server_path_count"] == target["trifecta_path_count"]
    assert any(
        path["egress_tool"] == "npm-server-puppeteer-2025-5-12:puppeteer_navigate"
        and "npm-server-filesystem:read_file" in path["read_tools"]
        for path in target["trifecta_paths"]
    )


def test_target_b_composition_records_the_miss(results: dict) -> None:
    compositions = {row["composition_id"]: row for row in results["compositions"]}

    target = compositions["filesystem-plus-fetch"]
    assert target["target_id"] == "B"
    assert target["in_latch_threat_model"] is True
    assert target["expected_positive"] is True
    assert target["trifecta_path_count"] == 0
    assert target["outcome"] == "missed"
    assert target["miss_rationale"]
    assert "GET-only" in target["miss_rationale"]


def test_artifacts_match_deterministic_recomputation(results: dict) -> None:
    assert RESULTS_JSON.exists()
    assert REPORT_MD.exists()
    assert json.loads(RESULTS_JSON.read_text(encoding="utf-8")) == results
    assert REPORT_MD.read_text(encoding="utf-8") == render_report(results)
    assert compute_results() == results


def test_writing_artifacts_twice_is_byte_identical(
    results: dict, tmp_path: Path
) -> None:
    before_json = RESULTS_JSON.read_bytes()
    before_md = REPORT_MD.read_bytes()

    first_json, first_md = write_results(results, tmp_path)
    first_bytes = first_json.read_bytes()
    first_report = first_md.read_bytes()
    second_json, second_md = write_results(results, tmp_path)

    assert second_json.read_bytes() == first_bytes
    assert second_md.read_bytes() == first_report
    # Writing to a scratch directory never touches the tracked artifacts.
    assert RESULTS_JSON.read_bytes() == before_json
    assert REPORT_MD.read_bytes() == before_md


def test_module_cli_runs(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "package_eval.run_package_eval",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Packages: 14" in completed.stdout
    assert "In-scope recall: 0.88 (7/8)" in completed.stdout
    assert "overall recall: 0.70 (7/10)" in completed.stdout
    assert (tmp_path / RESULTS_JSON.name).exists()
    assert (tmp_path / REPORT_MD.name).exists()


def test_report_documents_the_real_findings(results: dict) -> None:
    report = REPORT_MD.read_text(encoding="utf-8")
    assert "## What the real-package findings are telling us" in report
    assert "## Before vs. after the static graph precision fix" in report
    assert "## Real-package targets" in report
    assert "over-approximation" in report
    assert "`latch probe-chain`" in report
    assert "MCP ecosystem" in report
    assert "14 packages" in report
    assert "server-everything" in report
    assert "27 CRITICAL" in report
    assert "0 CRITICAL" in report
    assert "314" in report
    for row in results["packages"]:
        assert f"`{row['package_name']}`" in report


def test_before_after_table_matches_the_recorded_measurements(results: dict) -> None:
    rows = {row["composition_id"]: row for row in results["precision_before_after"]}

    git = rows["filesystem-plus-git"]
    assert (git["before_paths"], git["before_critical"]) == (27, 27)
    assert (git["after_paths"], git["after_critical"]) == (0, 0)

    everything = rows["everything-plus-filesystem"]
    assert everything["before_paths"] == 314
    # MCP sampling/elicitation callbacks no longer become egress sinks, which
    # removed 21 of the 32 paths this composition used to produce.
    assert everything["after_paths"] == 11
    assert everything["after_paths"] < everything["before_paths"]
