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
)

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_REPORT = ROOT / "package_eval" / "capture_report.json"

REFERENCE_SLUGS = {
    "npm-server-everything",
    "npm-server-filesystem",
    "npm-server-memory",
    "pypi-mcp-server-fetch",
    "pypi-mcp-server-git",
}


@pytest.fixture(scope="module")
def results() -> dict:
    return compute_results()


def test_captured_manifests_have_real_provenance() -> None:
    paths = sorted(MANIFEST_DIR.glob("*.json"))
    assert len(paths) >= 4
    assert {path.stem for path in paths} >= REFERENCE_SLUGS - {
        "npm-server-everything"
    }

    for path in paths:
        capture = json.loads(path.read_text(encoding="utf-8"))
        assert capture["capture_source"] in {
            "live_subprocess",
            "pinned_package_capture",
        }
        for key in (
            "package_name",
            "package_version",
            "ecosystem",
            "launch_command",
            "protocol_version",
            "manifest_sha256",
            "tools",
            "tool_count",
        ):
            assert key in capture, (path.name, key)
        assert capture["package_version"] not in ("", "unknown")
        assert isinstance(capture["launch_command"], list)
        assert capture["package_name"]
        assert capture["tools"]
        assert capture["tool_count"] == len(capture["tools"])
        # The digest is over the captured bytes, so it proves the record is intact.
        assert capture["manifest_sha256"] == manifest_digest(capture["tools"])
        names = [tool["name"] for tool in capture["tools"]]
        assert len(names) == len(set(names)), path.name


def test_capture_report_matches_the_captures_on_disk() -> None:
    report = json.loads(CAPTURE_REPORT.read_text(encoding="utf-8"))
    captured_files = sorted(MANIFEST_DIR.glob("*.json"))
    assert report["captured"] == len(captured_files)
    assert report["captured"] + report["skipped"] == len(report["captures"])
    captured_slugs = {
        row["slug"] for row in report["captures"] if row["status"] == "captured"
    }
    assert captured_slugs == {path.stem for path in captured_files}


def test_latch_is_clean_on_reference_servers(results: dict) -> None:
    rows = {row["slug"]: row for row in results["packages"]}
    assert set(rows) == REFERENCE_SLUGS

    for slug in (
        "npm-server-filesystem",
        "npm-server-memory",
        "pypi-mcp-server-fetch",
        "pypi-mcp-server-git",
    ):
        assert rows[slug]["latch_flagged"] is False, slug
        assert rows[slug]["findings"] == [], slug

    # The everything server is the SDK's diagnostics surface; Latch's static
    # heuristics over-approximate it and the report says so explicitly.
    assert rows["npm-server-everything"]["latch_flagged"] is True
    assert rows["npm-server-everything"]["finding_count"] > 0
    assert results["summary"]["latch_flagged_packages"] == [
        "npm-server-everything"
    ]


def test_naive_baseline_is_much_noisier_than_latch(results: dict) -> None:
    summary = results["summary"]
    assert summary["naive_false_positive_rate"] > summary["latch_false_positive_rate"]
    assert len(summary["naive_flagged_packages"]) >= 3
    assert "npm-server-filesystem" in summary["naive_flagged_packages"]


def test_compositions_built_from_unmodified_captures(results: dict) -> None:
    compositions = {row["composition_id"]: row for row in results["compositions"]}
    assert set(compositions) == {
        "filesystem-plus-memory",
        "filesystem-plus-git",
        "filesystem-plus-fetch",
        "everything-plus-filesystem",
    }

    clean = compositions["filesystem-plus-memory"]
    assert clean["trifecta_path_count"] == 0
    assert clean["latch_flagged"] is False
    assert compositions["filesystem-plus-fetch"]["trifecta_path_count"] == 0

    git = compositions["filesystem-plus-git"]
    assert git["trifecta_path_count"] > 0
    assert git["cross_server_path_count"] > 0
    assert all(
        path["egress_tool"].startswith("pypi-mcp-server-git:")
        for path in git["trifecta_paths"]
    )

    for row in compositions.values():
        assert row["tool_count"] > 0
        assert row["trifecta_path_count"] >= len(row["trifecta_paths"])
        assert row["severity_counts"].get("CRITICAL", 0) <= row["trifecta_path_count"]


def test_artifacts_match_deterministic_recomputation(results: dict) -> None:
    assert RESULTS_JSON.exists()
    assert REPORT_MD.exists()
    assert json.loads(RESULTS_JSON.read_text(encoding="utf-8")) == results
    assert REPORT_MD.read_text(encoding="utf-8") == render_report(results)
    assert compute_results() == results


def test_writing_artifacts_twice_is_byte_identical(results: dict) -> None:
    before_json = RESULTS_JSON.read_bytes()
    before_md = REPORT_MD.read_bytes()
    main()
    assert RESULTS_JSON.read_bytes() == before_json
    assert REPORT_MD.read_bytes() == before_md


def test_module_cli_runs() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "package_eval.run_package_eval"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Packages: 5" in completed.stdout
    assert "Latch flagged: 1" in completed.stdout


def test_report_documents_the_real_findings(results: dict) -> None:
    report = REPORT_MD.read_text(encoding="utf-8")
    assert "## What the real-package findings are telling us" in report
    assert "over-approximation" in report
    assert "`latch probe-chain`" in report.replace("latch probe-chain", "`latch probe-chain`")
    assert "not the MCP ecosystem" in report
    assert "server-everything" in report
    for row in results["packages"]:
        assert f"`{row['package_name']}`" in report
