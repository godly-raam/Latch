"""Tests for the head-to-head scanner comparison.

Every test here is read-only against the tracked artifacts: recomputation gets
the recorded peer measurement handed to it instead of invoking the scanner, and
anything that writes goes to ``tmp_path``. That keeps a plain
``pip install -e ".[dev]"`` environment (no ``snyk-agent-scan``) green, and
keeps ``pytest`` from mutating tracked JSON/Markdown.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from head_to_head import mcp_scan_probe
from head_to_head.mcp_scan_probe import (
    PACKAGE_SLUGS,
    cache_key,
    resolve_binary,
    reusable_key,
    run_measurement,
)
from head_to_head.run_comparison import (
    REPORT_MD,
    RESULTS_JSON,
    compute_results,
    main,
    render_report,
    write_results,
)
from package_eval.run_package_eval import load_captures

ROOT = Path(__file__).resolve().parents[1]

PEER_STATUSES = {
    "measured",
    "measured_unparsed",
    "credentials_required",
    "unauthorized",
    "rate_limited",
    "api_error",
    "blocked_unauthorized",
    "blocked_network_error",
    "blocked_timeout",
    "not_installed_in_env",
}


def recorded_measurement() -> dict:
    """The peer record committed in ``comparison_results.json``."""

    return json.loads(RESULTS_JSON.read_text(encoding="utf-8"))[
        "mcp_scan_measurement"
    ]


def results() -> dict:
    """Recompute with the recorded measurement: no CLI, no cache write."""

    return compute_results(measurement=recorded_measurement())


def test_artifacts_match_recomputation() -> None:
    assert RESULTS_JSON.exists()
    assert REPORT_MD.exists()

    comparison = results()
    assert json.loads(RESULTS_JSON.read_text(encoding="utf-8")) == comparison
    assert REPORT_MD.read_text(encoding="utf-8") == render_report(comparison)
    assert results() == comparison


def test_live_scanner_metrics() -> None:
    metrics = results()["metrics"]

    assert metrics["package_count"] == 14
    assert metrics["clean_package_count"] == 6
    # `mcp-remote`, the pinned static-header config, GitHub, Slack,
    # `supergateway` and `mcp-proxy` are true detections, so only the SDK
    # diagnostics server counts against Latch's false-positive rate.
    assert metrics["latch_flagged_packages"] == [
        "npm-mcp-remote-0-14-3",
        "npm-mcp-remote-0-14-3-static-header",
        "npm-server-everything",
        "npm-server-github-2025-4-8",
        "npm-server-slack-2025-4-25",
        "npm-supergateway-3-1-0",
        "pypi-mcp-proxy-0-8-2",
    ]
    assert metrics["latch_package_false_positive_rate"] == 0.1667
    assert metrics["naive_package_false_positive_rate"] >= 0.83
    assert set(metrics["naive_flagged_packages"]) >= {
        "npm-server-everything",
        "npm-server-filesystem",
        "npm-server-puppeteer-2025-5-12",
        "pypi-mcp-server-fetch",
        "pypi-mcp-server-git",
    }
    assert metrics["in_model_package_count"] == 6
    assert set(metrics["latch_in_model_detected"]) == {
        "npm-mcp-remote-0-14-3",
        "npm-mcp-remote-0-14-3-static-header",
        "npm-server-github-2025-4-8",
        "npm-server-slack-2025-4-25",
        "npm-supergateway-3-1-0",
        "pypi-mcp-proxy-0-8-2",
    }

    assert metrics["scenario_count"] == 10
    assert metrics["latch_scenarios_detected"] == 10
    assert metrics["latch_scenario_recall"] == 1.0
    assert metrics["latch_scenarios_missed"] == []
    assert metrics["naive_scenarios_detected"] == 7


def test_every_protocol_scenario_declares_what_fired() -> None:
    comparison = results()
    scenarios = {row["scenario_id"]: row for row in comparison["scenarios"]}

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
    comparison = results()
    third_party = {row["tool"]: row for row in comparison["third_party"]}
    assert set(third_party) == {"mcp-scan", "agent-latch"}

    peer = third_party["mcp-scan"]
    assert peer["status"] in PEER_STATUSES
    measurement = peer["measurement"]
    assert measurement["tool"] == "mcp-scan"
    assert measurement["status"] == peer["status"]
    assert isinstance(measurement["cache_key"], str)
    assert len(measurement["cache_key"]) == 64
    assert measurement["remote_api_required"] is True

    if measurement["status"] == "not_installed_in_env":
        # The plain `.[dev]` install: nothing was run, and nothing is claimed.
        assert peer["path"] is None
        assert measurement["version"] is None
        assert measurement["command"] is None
        assert measurement["exit_code"] is None
    else:
        assert peer["path"]
        assert isinstance(measurement["version"], str) and measurement["version"]
        assert measurement["command"][:2] == ["snyk-agent-scan", "scan"]
        assert isinstance(measurement["exit_code"], int)

    if measurement["status"] in {"measured", "measured_unparsed"}:
        assert measurement["parsed"] is True
        assert set(measurement["package_flags"]) <= set(measurement["packages"])
        assert isinstance(measurement["clean_false_positive_rate"], float)
    else:
        assert measurement["package_flags"] == {}
        assert measurement["clean_false_positive_rate"] is None
        assert measurement["reason"], measurement
        for row in comparison["packages"]:
            assert row["peer_flagged"] is None

    latch = third_party["agent-latch"]
    assert latch["status"] in {"installed", "architectural_comparison_only"}
    if latch["status"] == "installed":
        assert latch["path"]
    else:
        assert latch["path"] is None

    assert len(comparison["architectural_matrix"]) == 3
    for row in comparison["architectural_matrix"]:
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


def _server_risk(slug: str, **risk_indexes: object) -> dict:
    """One ``server_risks[]`` entry from ``snyk-agent-scan`` 0.6.11."""

    return {
        "name": slug,
        "entities": [{"name": "read_file", "type": "tool"}],
        "risk_indexes": risk_indexes,
    }


def _analysis_error(
    *, message: str, exception: str, traceback: str = ""
) -> dict:
    """The ``error`` object 0.6.11 attaches to a path it could not analyze."""

    return {
        "message": message,
        "exception": exception,
        "traceback": traceback,
        "is_failure": True,
        "category": "analysis_error",
    }


def _mocked_scan(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict,
    *,
    token: str | None = None,
) -> dict:
    """Run ``_run`` against mocked 0.6.11 stdout: no binary, no network."""

    if token is None:
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
    else:
        monkeypatch.setenv("SNYK_TOKEN", token)
    monkeypatch.setattr(
        "head_to_head.mcp_scan_probe.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    return mcp_scan_probe._run(
        "/bin/true", "0.6.11", load_captures(), "cache-key", "reuse-key"
    )


def test_a_401_scan_path_response_is_unauthorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """0.6.11 exits 0 on a rejected token and reports it inside the payload."""

    token = "3f0c1e4a-1111-4222-8333-444455556666"
    payload = {
        "scan_path_responses": [
            {
                "client": "claude",
                "path": "/tmp/latch-mcp-scan-abc/mcp-scan-config.json",
                "server_risks": [],
                "skill_risks": [],
                "error": _analysis_error(
                    message=(
                        "Unauthorized. Please check your SNYK_TOKEN environment"
                        " variable or your push key."
                    ),
                    exception=(
                        "ClientResponseError(RequestInfo(url=URL("
                        "'https://api.snyk.io/hidden/mcp-scan/cli/analysis-machine'),"
                        f" headers={{'Authorization': 'token {token}'}}),"
                        " (), status=401, message='Unauthorized')"
                    ),
                    traceback=(
                        "Traceback (most recent call last):\n  File"
                        ' "/tmp/latch-mcp-scan-abc/agent_scan/verify_api.py",'
                        " line 600, in analyze"
                    ),
                ),
            }
        ]
    }

    row = _mocked_scan(monkeypatch, payload, token=token)

    assert row["status"] == "unauthorized"
    assert row["parsed"] is True
    assert row["clean_false_positive_rate"] is None
    assert row["reason"] == "401 Unauthorized from Snyk analysis-machine API"
    assert row["package_flags"] == {}
    assert row["flagged_packages"] == []
    assert row["api_error_category"] == "analysis_error"
    # Neither the credential nor the raw traceback may reach the artifact.
    dumped = json.dumps(row)
    assert token not in dumped
    assert "Traceback" not in dumped
    assert "/tmp" not in dumped


def test_a_429_scan_path_response_is_rate_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public daily limit is a distinct outcome, not a scan error."""

    payload = {
        "scan_path_responses": [
            {
                "client": "claude",
                "path": "/tmp/latch-mcp-scan-abc/mcp-scan-config.json",
                "server_risks": [],
                "skill_risks": [],
                "error": _analysis_error(
                    message=(
                        "Daily usage limit reached for the public version of"
                        " Agent-Scan."
                    ),
                    exception=(
                        "ClientResponseError(RequestInfo(...), (), status=429,"
                        " message='Too Many Requests')"
                    ),
                ),
            }
        ]
    }

    row = _mocked_scan(monkeypatch, payload)

    assert row["status"] == "rate_limited"
    assert row["parsed"] is True
    assert row["clean_false_positive_rate"] is None
    assert row["reason"] == (
        "429 Daily usage limit reached on Snyk public analysis-machine API"
    )
    assert row["package_flags"] == {}
    assert row["scanned_servers"] == []


def test_a_clean_scan_path_response_is_measured_at_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``risk_indexes`` empty for every server is the peer's clean verdict."""

    payload = {
        "scan_path_responses": [
            {
                "client": "claude",
                "path": "/tmp/latch-mcp-scan-abc/mcp-scan-config.json",
                "server_risks": [_server_risk(slug) for slug in PACKAGE_SLUGS],
                "skill_risks": [],
            }
        ]
    }

    row = _mocked_scan(monkeypatch, payload)

    assert row["status"] == "measured"
    assert row["parsed"] is True
    assert row["clean_false_positive_rate"] == 0.0
    assert row["flagged_packages"] == []
    assert set(row["package_flags"]) == set(PACKAGE_SLUGS)
    assert row["scanned_servers"] == list(PACKAGE_SLUGS)
    assert row["clean_package_count"] == len(PACKAGE_SLUGS)


def test_a_flagged_server_risk_is_measured_with_its_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``server_risks[]`` flag maps back to the configured package id."""

    payload = {
        "scan_path_responses": [
            {
                "client": "claude",
                "path": "/tmp/latch-mcp-scan-abc/mcp-scan-config.json",
                "server_risks": [
                    _server_risk(
                        "npm-server-everything",
                        prompt_injection_tool_desc={
                            "score": 900,
                            "evidence": "the tool description instructs the model",
                        },
                        destructive_capabilities={"score": 250, "evidence": "delete"},
                    ),
                    _server_risk("npm-server-filesystem"),
                    _server_risk("npm-server-memory"),
                    _server_risk("pypi-mcp-server-fetch"),
                    _server_risk("pypi-mcp-server-git"),
                ],
                "skill_risks": [],
            }
        ]
    }

    row = _mocked_scan(monkeypatch, payload)

    assert row["status"] == "measured"
    assert row["parsed"] is True
    assert row["flagged_packages"] == ["npm-server-everything"]
    assert row["clean_false_positive_rate"] == 0.2
    assert row["clean_package_count"] == len(PACKAGE_SLUGS) - 1
    assert row["package_flags"]["npm-server-memory"] is False
    assert row["package_flags"]["npm-server-everything"] is True


def test_measurement_never_persists_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The committed cache is scrubbed even when the CLI echoes the token."""

    token = "3f0c1e4a-1111-4222-8333-444455556666"
    monkeypatch.setenv("SNYK_TOKEN", token)
    monkeypatch.setattr(
        "head_to_head.mcp_scan_probe.resolve_binary", lambda: "/bin/true"
    )
    monkeypatch.setattr(
        "head_to_head.mcp_scan_probe.scanner_version", lambda binary: "0.6.11"
    )
    monkeypatch.setattr(
        "head_to_head.mcp_scan_probe._run",
        lambda binary, version, captures, key, reuse_key: {
            "tool": "mcp-scan",
            "status": "measured",
            "reason": f"echoed Authorization: Bearer {token}",
            "package_flags": {"npm-server-memory": False},
            "flagged_packages": [],
            "cache_key": key,
            "reuse_key": reuse_key,
        },
    )
    cache_path = tmp_path / "mcp_scan_measurement.json"

    row = run_measurement(load_captures(), cache_path=cache_path)

    persisted = cache_path.read_text(encoding="utf-8")
    assert token not in persisted
    assert token not in json.dumps(row)
    assert "[REDACTED]" in row["reason"]
    assert row["status"] == "measured"


def test_a_measured_record_is_reused_without_a_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CI and a fresh clone read a measured verdict instead of losing it."""

    captures = load_captures()
    token = "3f0c1e4a-1111-4222-8333-444455556666"
    monkeypatch.setattr(
        "head_to_head.mcp_scan_probe.resolve_binary", lambda: "/bin/true"
    )
    monkeypatch.setattr(
        "head_to_head.mcp_scan_probe.scanner_version", lambda binary: "0.6.11"
    )
    monkeypatch.setenv("SNYK_TOKEN", token)
    measured_key = cache_key(captures, "/bin/true", "0.6.11")
    monkeypatch.delenv("SNYK_TOKEN")

    cache_path = tmp_path / "mcp_scan_measurement.json"
    cache_path.write_text(
        json.dumps(
            {
                "tool": "mcp-scan",
                "version": "0.6.11",
                "status": "measured",
                "token_present": True,
                "package_flags": {"npm-server-memory": False},
                "flagged_packages": [],
                "clean_false_positive_rate": 0.0,
                "cache_key": measured_key,
                "reuse_key": reusable_key(captures, "/bin/true", "0.6.11"),
            }
        ),
        encoding="utf-8",
    )

    def _must_not_run(*args: object, **kwargs: object) -> dict:
        raise AssertionError(
            "the CLI must not run while a measured record matches"
        )

    monkeypatch.setattr("head_to_head.mcp_scan_probe._run", _must_not_run)
    reused = run_measurement(captures, cache_path=cache_path)
    assert reused["status"] == "measured"
    assert reused["clean_false_positive_rate"] == 0.0
    assert json.loads(cache_path.read_text(encoding="utf-8"))["status"] == (
        "measured"
    )

    # `--force-refresh` is the only path that replaces it.
    monkeypatch.setattr(
        "head_to_head.mcp_scan_probe._run",
        lambda binary, version, captures, key, reuse_key: {
            "tool": "mcp-scan",
            "status": "credentials_required",
            "reason": "snyk-agent-scan requires SNYK_TOKEN; no token is present",
            "package_flags": {},
            "flagged_packages": [],
            "cache_key": key,
            "reuse_key": reuse_key,
        },
    )
    forced = run_measurement(captures, force=True, cache_path=cache_path)
    assert forced["status"] == "credentials_required"
    assert json.loads(cache_path.read_text(encoding="utf-8"))["status"] == (
        "credentials_required"
    )


def test_measurement_without_the_peer_binary_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `.[dev]`-only environment records the absence instead of a verdict."""

    monkeypatch.setattr("head_to_head.mcp_scan_probe.resolve_binary", lambda: None)
    cache_path = tmp_path / "mcp_scan_measurement.json"

    measurement = run_measurement(load_captures(), cache_path=cache_path)

    assert measurement["status"] == "not_installed_in_env"
    assert measurement["version"] is None
    assert measurement["command"] is None
    assert measurement["exit_code"] is None
    assert measurement["package_flags"] == {}
    assert measurement["flagged_packages"] == []
    assert measurement["clean_false_positive_rate"] is None
    assert json.loads(cache_path.read_text(encoding="utf-8")) == measurement

    comparison = compute_results(measurement=measurement)
    peer = next(row for row in comparison["third_party"] if row["tool"] == "mcp-scan")
    assert peer["status"] == "not_installed_in_env"
    assert peer["path"] is None
    assert all(row["peer_flagged"] is None for row in comparison["packages"])
    assert comparison["metrics"]["mcp_scan_status"] == "not_installed_in_env"


@pytest.mark.skipif(
    resolve_binary() is None,
    reason="snyk-agent-scan is not installed (plain [dev] environment)",
)
def test_installed_peer_measurement_records_the_invocation() -> None:
    measurement = recorded_measurement()
    if measurement["status"] == "not_installed_in_env":
        pytest.skip("the recorded artifact predates installing the peer extra")

    assert measurement["version"]
    assert measurement["command"][:2] == ["snyk-agent-scan", "scan"]
    assert isinstance(measurement["exit_code"], int)


def test_report_leads_with_the_measured_comparison() -> None:
    comparison = results()
    report = REPORT_MD.read_text(encoding="utf-8")

    assert report.startswith("# mcpprobe (Latch): measured real-package comparison")
    assert "## Headline: measured on real captured packages" in report
    assert "0.17 (1/6)" in report
    assert "0.83 (5/6)" in report
    assert "All 14 upstream captures" in report
    assert "Architectural and detection matrix" in report
    assert "AgentLatch" in report
    assert "Honest limits of this comparison" in report

    # The two stages are reported side by side, and the blind row is not
    # presented as the post-tuning row.
    assert "## Two evaluation stages, side by side" in report
    assert "First-Run Blind Baseline" in report
    assert "Post-Tuning Corpus" in report
    assert "0.20 (1/5)" in report
    assert "0.67 (2/3)" in report
    assert "0.88 (7/8)" in report
    # The headline table carries the stage on every row, and its in-scope
    # denominator is the full 7/8 rather than the package-manifest subset.
    assert (
        "| Scanner | Stage | Clean-package FPR | In-scope real targets |"
        " Evidence |"
    ) in report
    assert "| **mcpprobe (Latch)** | Post-tuning | 0.17 (1/6) | 0.88 (7/8) | measured |" in report
    assert "Narrowed to package manifests only" in report
    assert "would have missed on first run" in report
    assert "unseen" in report.lower()
    stages = comparison["evaluation_stages"]
    assert stages["first_run_blind"]["clean_package_count"] == 5
    assert stages["first_run_blind"]["latch_package_false_positive_rate"] == 0.2
    assert stages["post_tuning"]["clean_false_positive_rate"] == 0.1667
    assert len(stages["post_tuning"]["detector_fingerprint_sha256"]) == 64

    measurement = comparison["mcp_scan_measurement"]
    assert f"`{measurement['status']}`" in report
    assert "snyk-agent-scan scan" in report
    if measurement["status"] == "credentials_required":
        assert "SNYK_TOKEN" in report
        assert "could not obtain a **measured** peer verdict" in report


def test_a_measured_peer_verdict_populates_the_column() -> None:
    """A measured record fills the peer column with real counts.

    No token exists in this environment, so the measured branch is exercised
    with a record shaped exactly like the one ``--force-refresh`` writes.
    """

    measurement = {
        **recorded_measurement(),
        "status": "measured",
        "parsed": True,
        "reason": None,
        "package_flags": {
            "npm-server-everything": True,
            "npm-server-filesystem": False,
            "npm-server-memory": False,
            "pypi-mcp-server-fetch": False,
            "pypi-mcp-server-git": False,
        },
        "flagged_packages": ["npm-server-everything"],
        "clean_false_positive_rate": 0.2,
        "clean_package_count": 4,
    }

    comparison = compute_results(measurement=measurement)
    report = render_report(comparison)

    assert (
        "| `mcp-scan` (`snyk-agent-scan`) | Post-tuning | 0.20 (1/5) | n/a |"
        " measured live (v0.6.11) |"
    ) in report
    assert (
        "it flags 1/5 clean packages (FPR 0.2): `npm-server-everything`."
        in report
    )
    assert "reused verbatim" in report

    rows = {row["slug"]: row for row in comparison["packages"]}
    assert rows["npm-server-everything"]["peer_flagged"] is True
    assert rows["npm-server-memory"]["peer_flagged"] is False


def test_a_rate_limited_peer_is_not_reported_as_clean() -> None:
    """A 429 means no verdict, and the row says so instead of `0.00`."""

    measurement = {
        **recorded_measurement(),
        "status": "rate_limited",
        "parsed": True,
        "reason": (
            "429 Daily usage limit reached on Snyk public analysis-machine API"
        ),
        "package_flags": {},
        "flagged_packages": [],
        "clean_false_positive_rate": None,
    }

    comparison = compute_results(measurement=measurement)
    report = render_report(comparison)

    assert (
        "| `mcp-scan` (`snyk-agent-scan`) | Post-tuning |"
        " n/a (429 public API daily limit reached) | n/a |"
        " ran (v0.6.11), 429 public API daily limit reached |"
    ) in report
    assert "`429 Too Many Requests`" in report
    # The peer's remote dependency is contrasted with the local engine.
    assert "runs locally with neither" in report
    assert "0.00 (0/5)" not in report
    assert all(row["peer_flagged"] is None for row in comparison["packages"])


def test_an_unauthorized_peer_requires_a_valid_token() -> None:
    measurement = {
        **recorded_measurement(),
        "status": "unauthorized",
        "parsed": True,
        "reason": "401 Unauthorized from Snyk analysis-machine API",
        "package_flags": {},
        "flagged_packages": [],
        "clean_false_positive_rate": None,
    }

    comparison = compute_results(measurement=measurement)
    report = render_report(comparison)

    assert (
        "| `mcp-scan` (`snyk-agent-scan`) | Post-tuning | n/a (SNYK_TOKEN"
        " required) | n/a | ran (v0.6.11), 401 from the analysis API |"
    ) in report
    assert "`401 Unauthorized`" in report
    assert "0.00 (0/5)" not in report
    assert all(row["peer_flagged"] is None for row in comparison["packages"])


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
    comparison = results()
    measurement = comparison["mcp_scan_measurement"]
    report = REPORT_MD.read_text(encoding="utf-8")
    assert "| mcp-scan |" in report

    if measurement["parsed"]:
        flagged = measurement["flagged_packages"]
        for row in comparison["packages"]:
            if row["slug"] in measurement["package_flags"]:
                assert row["peer_flagged"] is (row["slug"] in flagged)
    else:
        assert all(row["peer_flagged"] is None for row in comparison["packages"])
        assert "produced a parseable live verdict" in report


def test_writing_twice_is_byte_identical(tmp_path: Path) -> None:
    comparison = results()

    first_json, first_report = write_results(comparison, tmp_path)
    before_json = first_json.read_bytes()
    before_report = first_report.read_bytes()
    second_json, second_report = write_results(comparison, tmp_path)

    assert second_json.read_bytes() == before_json
    assert second_report.read_bytes() == before_report


def test_main_writes_only_where_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("head_to_head.mcp_scan_probe.resolve_binary", lambda: None)
    tracked_json = RESULTS_JSON.read_bytes()
    tracked_report = REPORT_MD.read_bytes()

    exit_code = main(
        [
            "--output-dir",
            str(tmp_path),
            "--cache-path",
            str(tmp_path / "cache.json"),
            "--force-refresh",
        ]
    )

    assert exit_code == 0
    assert (tmp_path / RESULTS_JSON.name).exists()
    assert (tmp_path / REPORT_MD.name).exists()
    assert (tmp_path / "cache.json").exists()
    assert RESULTS_JSON.read_bytes() == tracked_json
    assert REPORT_MD.read_bytes() == tracked_report
