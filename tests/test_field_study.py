"""Offline tests for the unseen-package field study harness."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import field_study.discover_targets as discovery
from field_study.discover_targets import (
    PYPI_JSON_URL,
    PYPI_SIMPLE_URL,
    discover_targets,
    file_sha256,
    package_eval_exclusions,
)
import pytest

from field_study.run_field_study import (
    COMPOSITION_TRIAGE,
    COMPOSITION_TRIAGE_BUCKETS,
    PLACEHOLDER_CREDENTIAL_ENV,
    analyze,
    analyze_compositions,
    build_compositions,
    classify_harvest,
    harvest_target,
    main,
    render_disclosure_log,
    render_report,
    sanitize_text,
    scratch_environment,
    write_results,
)
from field_study.triage_compositions import sample_details
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.models import ToolDefinition
from mcpprobe.transport import TransportTimeout
from package_eval.capture_manifests import manifest_digest
from package_eval.run_package_eval import detector_fingerprint

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / "field_study" / "captures"
DISCOVERED_AT = "2026-11-23T00:00:00Z"

MOCK_STDIO = """\
import json
import os
import sys

REPORT = sys.argv[1]
WATCHED = (
    "PATH",
    "HOME",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "npm_config_cache",
    "npm_config_update_notifier",
    "UV_CACHE_DIR",
    "UV_TOOL_DIR",
    "UV_NO_PROGRESS",
    "SECRET_HOST_SENTINEL",
    "SNYK_TOKEN",
)

with open(REPORT, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "env_keys": sorted(os.environ),
            "env": {key: os.environ.get(key) for key in WATCHED},
            "writable": {
                key: bool(value)
                and os.path.isdir(value)
                and os.access(value, os.W_OK)
                for key, value in (
                    (key, os.environ.get(key))
                    for key in (
                        "HOME",
                        "npm_config_cache",
                        "UV_CACHE_DIR",
                        "UV_TOOL_DIR",
                    )
                )
            },
        },
        handle,
    )

if os.environ.get("LATCH_LEAK_SENTINEL") or os.environ.get("SECRET_HOST_SENTINEL"):
    sys.stderr.write("host secret leaked into the child environment\\n")
    raise SystemExit(3)

sys.stderr.write("scratch home: " + os.environ["HOME"] + "\\n")

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "server/discover":
        result = {
            "protocolVersion": "2026-07-28",
            "serverInfo": {"name": "mock-field", "version": "9.9.9"},
            "capabilities": {"tools": {}},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "echo",
                    "description": "Echo text back.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                    },
                }
            ]
        }
    elif method == "notifications/initialized":
        continue
    else:
        result = None
    if result is not None:
        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result})
            + "\\n"
        )
        sys.stdout.flush()
"""


def _npm_entry(name: str, version: str, repository: str | None = None) -> dict:
    return {
        "package": {
            "name": name,
            "version": version,
            "description": f"{name} description",
            "links": {"repository": repository} if repository else {},
        }
    }


def test_discovery_excludes_package_eval_and_pins_versions() -> None:
    exclusions = package_eval_exclusions()
    assert len(exclusions["capture_slugs"]) == 14
    assert "@modelcontextprotocol/server-filesystem" in exclusions["package_names"]
    assert "mcp-server-git" in exclusions["package_names"]

    npm_payload = {
        "objects": [
            _npm_entry(
                "@modelcontextprotocol/server-filesystem",
                "2.3.0",
                "git+https://github.com/modelcontextprotocol/servers.git",
            ),
            _npm_entry(
                "unseen-mcp-server",
                "1.4.2",
                "https://github.com/acme/unseen-mcp-server.git",
            ),
        ]
    }
    pypi_payload = {
        "projects": [
            {"name": "mcp-server-git"},
            {"name": "mcp-server-fresh"},
            {"name": "unrelated-package"},
        ]
    }
    project_payload = {
        "info": {
            "version": "0.9.1",
            "summary": "Fresh MCP server",
            "project_urls": {"Repository": "https://github.com/acme/fresh"},
        }
    }

    def fetch(url: str) -> dict:
        if url.startswith("https://registry.npmjs.org/"):
            return npm_payload
        if url == PYPI_SIMPLE_URL:
            return pypi_payload
        if url == PYPI_JSON_URL.format(package="mcp-server-fresh"):
            return project_payload
        raise AssertionError(f"unexpected registry URL: {url}")

    targets = discover_targets(5, 5, fetch=fetch, discovered_at=DISCOVERED_AT)

    assert [target["package"] for target in targets] == [
        "unseen-mcp-server",
        "mcp-server-fresh",
    ]
    by_package = {target["package"]: target for target in targets}
    assert by_package["unseen-mcp-server"]["version"] == "1.4.2"
    assert by_package["mcp-server-fresh"]["version"] == "0.9.1"
    assert by_package["unseen-mcp-server"]["repository_url"] == (
        "https://github.com/acme/unseen-mcp-server"
    )
    assert by_package["mcp-server-fresh"]["repository_url"] == (
        "https://github.com/acme/fresh"
    )
    assert {target["ecosystem"] for target in targets} == {"npm", "pypi"}
    assert all(target["discovered_at_utc"] == DISCOVERED_AT for target in targets)
    assert by_package["unseen-mcp-server"]["slug"] == (
        "npm-unseen-mcp-server-1-4-2"
    )


NPM_ONLY = ["alpha-mcp-server", "beta-mcp-server", "gamma-mcp-server"]


def _single_ecosystem_fetch(packages: list[str]):
    def fetch(url: str) -> dict:
        if url.startswith("https://registry.npmjs.org/"):
            return {"objects": [_npm_entry(name, "1.0.0") for name in packages]}
        raise AssertionError(f"unexpected registry URL: {url}")

    return fetch


def _write_exclusions(path: Path, *packages: str) -> Path:
    path.write_text(
        json.dumps({"targets": [{"package": name} for name in packages]}),
        encoding="utf-8",
    )
    return path


def test_discovery_does_not_exclude_its_own_output(
    tmp_path: Path, monkeypatch
) -> None:
    """A split is defined by its named sources, never by files on disk."""

    output = tmp_path / "targets.json"
    monkeypatch.setattr(discovery, "TARGETS_JSON", output)
    argv = ["--npm-limit", "10", "--pypi-limit", "0", "--output", str(output)]
    fetch = _single_ecosystem_fetch(NPM_ONLY)

    assert discovery.main(argv, fetch=fetch) == 0
    first = json.loads(output.read_text(encoding="utf-8"))
    assert [target["package"] for target in first["targets"]] == NPM_ONLY

    # A pinned round is not replaced without --force...
    before = output.read_bytes()
    assert discovery.main(argv, fetch=fetch) == 1
    assert output.read_bytes() == before

    # ...and once forced, the packages already in the output are still unseen
    # targets: only --exclude-targets and the package_eval pins exclude.
    assert discovery.main([*argv, "--force"], fetch=fetch) == 0
    again = json.loads(output.read_text(encoding="utf-8"))
    assert [target["package"] for target in again["targets"]] == NPM_ONLY

    split = json.loads(discovery.split_path(output).read_text(encoding="utf-8"))
    assert [source["kind"] for source in split["exclusion_sources"]] == [
        "package_eval_pins"
    ]
    assert split["output"] == str(output)  # a temp dir is outside the repo
    assert split["discovered_count"] == len(NPM_ONLY)
    assert split["overlap_with_exclusions"] == []
    assert split["excluded_name_count"] == len(
        package_eval_exclusions()["package_names"]
    )


def test_split_audit_differs_with_the_exclusion_source(tmp_path: Path) -> None:
    """Two draws that exclude different rounds cannot share a split record."""

    output = tmp_path / "round" / "targets.json"
    output.parent.mkdir()
    fetch = _single_ecosystem_fetch(NPM_ONLY)
    exclude_a = _write_exclusions(tmp_path / "a.json", "alpha-mcp-server")
    exclude_b = _write_exclusions(tmp_path / "b.json", "beta-mcp-server")

    def run(exclude: Path, *, force: bool) -> int:
        argv = [
            "--npm-limit",
            "10",
            "--pypi-limit",
            "0",
            "--output",
            str(output),
            "--exclude-targets",
            str(exclude),
        ]
        return discovery.main([*argv, "--force"] if force else argv, fetch=fetch)

    assert run(exclude_a, force=False) == 0
    first_split = discovery.split_path(output).read_text(encoding="utf-8")
    first_packages = [
        target["package"]
        for target in json.loads(output.read_text(encoding="utf-8"))["targets"]
    ]

    assert run(exclude_b, force=True) == 0
    second_split = discovery.split_path(output).read_text(encoding="utf-8")
    second_packages = [
        target["package"]
        for target in json.loads(output.read_text(encoding="utf-8"))["targets"]
    ]

    assert first_split != second_split
    assert first_packages == ["beta-mcp-server", "gamma-mcp-server"]
    assert second_packages == ["alpha-mcp-server", "gamma-mcp-server"]

    first = json.loads(first_split)
    second = json.loads(second_split)
    assert [source["path"] for source in first["exclusion_sources"]] == [
        "package_eval/captured_manifests",
        str(exclude_a),
    ]
    assert first["exclusion_sources"][1]["sha256"] == file_sha256(exclude_a)
    assert second["exclusion_sources"][1]["sha256"] == file_sha256(exclude_b)
    assert first["overlap_with_exclusions"] == []
    assert second["overlap_with_exclusions"] == []
    assert first["excluded_name_count"] == second["excluded_name_count"]


def test_overlapping_target_fails_the_run_and_is_recorded(
    tmp_path: Path, monkeypatch
) -> None:
    """A leak past the filter is a failed split, not a quietly written list."""

    output = tmp_path / "targets.json"
    exclude = _write_exclusions(tmp_path / "exclude.json", "gamma-mcp-server")
    leaked = {
        "slug": "npm-gamma-mcp-server-1-0-0",
        "ecosystem": "npm",
        "package": "gamma-mcp-server",
        "version": "1.0.0",
        "repository_url": None,
        "description": "",
        "discovered_at_utc": DISCOVERED_AT,
    }
    # Simulate a filtering regression: an excluded package reaches discovery.
    monkeypatch.setattr(discovery, "discover_targets", lambda *args, **kwargs: [leaked])

    status = discovery.main(
        [
            "--npm-limit",
            "10",
            "--pypi-limit",
            "0",
            "--output",
            str(output),
            "--exclude-targets",
            str(exclude),
        ],
        fetch=_single_ecosystem_fetch(NPM_ONLY),
    )

    assert status == 1
    assert not output.exists()
    split = json.loads(discovery.split_path(output).read_text(encoding="utf-8"))
    assert split["overlap_with_exclusions"] == ["gamma-mcp-server"]
    assert split["discovered_count"] == 1


ALLOWED_ENV_KEYS = {
    "PATH",
    "HOME",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "npm_config_cache",
    "npm_config_update_notifier",
    "UV_CACHE_DIR",
    "UV_TOOL_DIR",
    "UV_NO_PROGRESS",
}


def test_scratch_environment_is_isolated_writable_and_cleaned_up() -> None:
    real_home = Path.home()
    with scratch_environment() as (env, root):
        assert "latch-harvest-" in root.name
        assert set(env) == ALLOWED_ENV_KEYS
        assert real_home not in root.parents
        assert env["PATH"]
        for key in ("HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_DATA_HOME", "npm_config_cache", "UV_CACHE_DIR", "UV_TOOL_DIR"):
            path = Path(env[key])
            assert path.parent == root
            assert path.is_dir()
            assert os.access(path, os.W_OK)
    assert not root.exists()


def test_harvest_uses_a_mocked_stdio_server_with_an_isolated_scratch_home(
    tmp_path: Path, monkeypatch
) -> None:
    script = tmp_path / "mock_mcp.py"
    script.write_text(MOCK_STDIO, encoding="utf-8")
    report_path = tmp_path / "child-env.json"
    monkeypatch.setenv("LATCH_LEAK_SENTINEL", "1")
    monkeypatch.setenv("SECRET_HOST_SENTINEL", "host-only-value")
    monkeypatch.setenv("SNYK_TOKEN", "host-only-token")

    target = {
        "slug": "pypi-mock-field-9-9-9",
        "ecosystem": "pypi",
        "package": "mock-field",
        "version": "9.9.9",
        "repository_url": None,
        "description": "offline fixture",
        "launch_argv": [sys.executable, str(script), str(report_path)],
    }

    capture = harvest_target(target, timeout=10.0)

    assert capture["harvest_status"] == "harvested", capture["stderr_summary"]
    assert capture["protocol_version"] == "2026-07-28"
    assert capture["tool_count"] == 1
    assert capture["manifest_sha256"] == manifest_digest(capture["tools"])
    assert [tool["name"] for tool in capture["tools"]] == ["echo"]

    report = json.loads(report_path.read_text(encoding="utf-8"))
    # CPython itself injects LC_CTYPE into its own environment (PEP 538 locale
    # coercion); everything else must be exactly the allowlisted scratch set.
    assert set(report["env_keys"]) - {"LC_CTYPE"} == ALLOWED_ENV_KEYS
    assert report["env"]["SECRET_HOST_SENTINEL"] is None
    assert report["env"]["SNYK_TOKEN"] is None

    scratch_root = Path(report["env"]["HOME"]).parent
    assert "latch-harvest-" in scratch_root.name
    assert Path.home() not in scratch_root.parents
    assert not str(scratch_root).startswith(str(Path.home()))
    for key in ("HOME", "npm_config_cache", "UV_CACHE_DIR", "UV_TOOL_DIR"):
        assert Path(report["env"][key]).parent == scratch_root
        assert report["writable"][key] is True

    # The scratch tree is gone once the harvest returns, and no raw scratch
    # path survives in the capture's stderr summary.
    assert not scratch_root.exists()
    assert "<scratch>" in capture["stderr_summary"]
    assert scratch_root.name not in capture["stderr_summary"]
    assert str(Path.home()) not in capture["stderr_summary"]


def test_harvest_outcome_classification_and_sanitization() -> None:
    assert classify_harvest(None, "", [{"name": "echo"}]) == "harvested"
    assert (
        classify_harvest(
            RuntimeError("GITHUB_TOKEN is required but not set"), "", []
        )
        == "missing_required_env"
    )
    assert classify_harvest(TransportTimeout("timed out after 15s"), "", []) == "timeout"
    assert classify_harvest(RuntimeError("ENOENT: npx not found"), "", []) == (
        "startup_error"
    )

    cleaned = sanitize_text(
        "failed at /home/alice/private/server.py for /tmp/latch-run and TOKEN=abc123"
    )
    assert "/home/alice" not in cleaned
    assert "/tmp/latch-run" not in cleaned
    assert "abc123" not in cleaned
    assert "<redacted>" in cleaned

    scratch_root = Path("/var/folders/latch-harvest-abc")
    with_scratch = sanitize_text(
        f"npm failed in {scratch_root}/npm-cache/log.txt", scratch_root=scratch_root
    )
    assert str(scratch_root) not in with_scratch
    assert with_scratch.startswith("npm failed in <scratch>/npm-cache/log.txt")


def _tree_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digest.update(str(path.relative_to(directory)).encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _capture(slug: str, tools: list[dict], status: str = "harvested") -> dict:
    return {
        "slug": slug,
        "ecosystem": "npm",
        "package": slug,
        "version": "1.0.0",
        "repository_url": f"https://github.com/acme/{slug}",
        "description": "field fixture",
        "harvest_status": status,
        "manifest_sha256": manifest_digest(tools),
        "protocol_version": "2026-07-28" if status == "harvested" else "n/a",
        "stderr_summary": "",
        "tool_count": len(tools),
        "tools": tools,
    }


def test_analyze_records_manifest_errors_instead_of_aborting_the_batch(
    tmp_path: Path,
) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    duplicate_tools = [
        {
            "name": "dup_tool",
            "description": "a",
            "inputSchema": {"type": "object"},
        },
        {
            "name": "dup_tool",
            "description": "b",
            "inputSchema": {"type": "object"},
        },
    ]
    clean_tools = [
        {
            "name": "echo",
            "description": "Echo text back.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
            },
        }
    ]
    for capture in (
        _capture("npm-duplicate-manifest-1-0-0", duplicate_tools),
        _capture("npm-clean-1-0-0", clean_tools),
    ):
        (captures / f"{capture['slug']}.json").write_text(
            json.dumps(capture, sort_keys=True), encoding="utf-8"
        )

    results = analyze(captures, tmp_path / "missing-targets.json")

    assert results["target_count"] == 2
    assert results["analyzed_target_count"] == 2
    assert results["harvest_status_counts"]["harvested"] == 2

    by_slug = {row["slug"]: row for row in results["targets"]}
    malformed = by_slug["npm-duplicate-manifest-1-0-0"]
    clean = by_slug["npm-clean-1-0-0"]
    assert malformed["analysis_status"] == "analyzed"
    assert malformed["rule_ids"] == ["manifest_error"]
    assert malformed["finding_count"] == 1
    assert malformed["harvest_status"] == "harvested"
    assert clean["finding_count"] == 0

    finding = next(
        item
        for item in results["findings"]
        if item["target"] == "npm-duplicate-manifest-1-0-0"
    )
    assert finding["rule_id"] == "manifest_error"
    assert finding["engine"] == "audit"
    assert finding["severity"] == "MEDIUM"
    assert finding["title"] == "Invalid or duplicate tool manifest"
    assert "dup_tool" in finding["detail"]
    assert all(item["target"] != "npm-clean-1-0-0" for item in results["findings"])

    assert results["rule_counts"] == {"manifest_error": 1}
    assert results["flagged_target_count"] == 1


def test_analyze_is_deterministic_offline_and_leaves_other_suites_untouched(
    tmp_path: Path,
) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    hostile_tools = [
        {
            "name": "get_issue",
            "description": "Fetch a GitHub issue for triage.",
            "inputSchema": {
                "type": "object",
                "properties": {"issue_id": {"type": "string"}},
            },
        },
        {
            "name": "read_file",
            "description": "Read a local file from disk.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
        {
            "name": "post_webhook",
            "description": "Post a payload to a webhook.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "payload": {"type": "string"},
                },
            },
        },
        {
            "name": "hidden",
            "description": "Hidden \U000E0041 payload in a tag block.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]
    clean_tools = [
        {
            "name": "echo",
            "description": "Echo text back.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
            },
        }
    ]
    for capture in (
        _capture("npm-hostile-1-0-0", hostile_tools),
        _capture("npm-clean-1-0-0", clean_tools),
        _capture("npm-needs-token-1-0-0", [], status="missing_required_env"),
    ):
        (captures / f"{capture['slug']}.json").write_text(
            json.dumps(capture, sort_keys=True), encoding="utf-8"
        )

    targets_path = tmp_path / "targets.json"
    targets_path.write_text(
        json.dumps({"targets": [{"slug": "npm-hostile-1-0-0"}]}),
        encoding="utf-8",
    )

    before = (
        _tree_digest(ROOT / "package_eval"),
        _tree_digest(ROOT / "adversarial"),
    )

    results = analyze(captures, targets_path)
    first_paths = write_results(results, tmp_path / "out-a")
    first_bytes = [path.read_bytes() for path in first_paths]

    second_results = analyze(captures, targets_path)
    second_paths = write_results(second_results, tmp_path / "out-b")
    assert [path.read_bytes() for path in second_paths] == first_bytes

    after = (
        _tree_digest(ROOT / "package_eval"),
        _tree_digest(ROOT / "adversarial"),
    )
    assert after == before

    assert results["detector_fingerprint_sha256"] == detector_fingerprint()
    assert len(results["detector_fingerprint_sha256"]) == 64
    assert results["target_count"] == 3
    assert results["analyzed_target_count"] == 2
    assert results["harvest_status_counts"] == {
        "harvested": 2,
        "missing_required_env": 1,
        "timeout": 0,
        "startup_error": 0,
    }
    assert results["engine_counts"]["audit"] >= 1
    assert results["engine_counts"]["graph"] >= 1
    assert "LETHAL_TRIFECTA" in results["rule_counts"]
    assert "UNICODE_TAG_BLOCK" in results["rule_counts"]

    hostile = next(
        row for row in results["targets"] if row["slug"] == "npm-hostile-1-0-0"
    )
    clean = next(row for row in results["targets"] if row["slug"] == "npm-clean-1-0-0")
    assert hostile["finding_count"] > 0
    assert clean["finding_count"] == 0
    assert results["triage"]["status"] == "pending_hand_review"

    report = first_paths[1].read_text(encoding="utf-8")
    assert "independent ground-truth labels" in report
    assert "Hand-triage worksheet" in report
    assert "`npm-clean-1-0-0`" in report
    assert "Missing" not in report.split("## Findings by engine")[0]

    disclosure = first_paths[2].read_text(encoding="utf-8")
    # The header may not claim nothing was sent while listing a closed case.
    assert "one case closed without a ticket, none open" in disclosure
    assert "No disclosure has been sent." not in disclosure
    assert "`not_contacted`" in disclosure

    assert (
        main(
            [
                "--analyze",
                "--captures",
                str(captures),
                "--targets",
                str(targets_path),
                "--output-dir",
                str(tmp_path / "out-cli"),
            ]
        )
        == 0
    )


def _capture_graph(slug: str):
    payload = json.loads((CAPTURES / f"{slug}.json").read_text(encoding="utf-8"))
    tools = [
        ToolDefinition.model_validate(tool)
        for tool in payload["tools"]
        if isinstance(tool, dict)
    ]
    return analyze_capability_graph({slug: tools})


def test_compositions_are_the_only_place_shadow_and_cross_server_paths_exist(
    tmp_path: Path,
) -> None:
    """A pair must yield a shadow collision and a cross-server trifecta."""

    captures = tmp_path / "captures"
    captures.mkdir()
    server_a = [
        {
            "name": "get_issue",
            "description": "Fetch a GitHub issue for triage.",
            "inputSchema": {
                "type": "object",
                "properties": {"issue_id": {"type": "string"}},
            },
        },
        {
            "name": "read_file",
            "description": "Read a local file from disk.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
        {
            "name": "echo",
            "description": "Echo text back.",
            "inputSchema": {"type": "object"},
        },
    ]
    server_b = [
        {
            "name": "post_webhook",
            "description": "Post a payload to a webhook.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "payload": {"type": "string"},
                },
            },
        },
        {
            "name": "echo",
            "description": "Echo text back.",
            "inputSchema": {"type": "object"},
        },
    ]
    for capture in (
        _capture("npm-alpha-1-0-0", server_a),
        _capture("npm-beta-1-0-0", server_b),
    ):
        (captures / f"{capture['slug']}.json").write_text(
            json.dumps(capture, sort_keys=True), encoding="utf-8"
        )

    # The kit enumeration is fixed even when an anchor is absent from the tree.
    assert build_compositions(["npm-alpha-1-0-0", "npm-beta-1-0-0"]) == [
        ("npm-alpha-1-0-0", "npm-beta-1-0-0"),
        ("npm-alpha-1-0-0", "npm-server-filesystem", "pypi-mcp-server-fetch"),
        ("npm-alpha-1-0-0", "npm-server-filesystem", "pypi-mcp-server-git"),
        ("npm-alpha-1-0-0", "pypi-mcp-server-fetch", "npm-server-github-2025-4-8"),
        ("npm-beta-1-0-0", "npm-server-filesystem", "pypi-mcp-server-fetch"),
        ("npm-beta-1-0-0", "npm-server-filesystem", "pypi-mcp-server-git"),
        ("npm-beta-1-0-0", "pypi-mcp-server-fetch", "npm-server-github-2025-4-8"),
    ]

    result = analyze_compositions(captures, manifest_dir=tmp_path / "no-anchors")

    assert result["count"] == 1
    assert result["harvested_server_count"] == 2
    assert result["cross_server_path_count"] > 0
    assert result["engine_counts"]["shadow"] > 0
    assert "EXACT_TOOL_SHADOW" in result["rule_counts"]
    # No HTTP/OAuth transport in the corpus: the engine stays untested, and the
    # result says so instead of implying a pass.
    assert result["engine_counts"]["auth-audit"] == 0
    assert "untested engine" in result["auth_audit_note"]
    assert result["flagged_composition_count"] == 1


@pytest.mark.skipif(
    not CAPTURES.is_dir(), reason="field-study captures are not in this checkout"
)
def test_known_out_of_scope_miss_is_labelled_not_clean() -> None:
    """`malicious-mcp-server` is a documented blind spot, never `no_finding`."""

    results = analyze(CAPTURES)
    misses = {miss["slug"]: miss for miss in results["known_out_of_scope_misses"]}
    miss = misses["npm-malicious-mcp-server-1-5-0"]
    assert miss["package"] == "malicious-mcp-server"
    assert "runtime responses" in miss["reason"]

    disclosure = render_disclosure_log(results)
    row = next(
        line
        for line in disclosure.splitlines()
        if "`malicious-mcp-server`" in line
    )
    assert "`known_out_of_scope_miss`" in row
    assert "no_finding" not in row

    report = render_report(results)
    assert "Known out-of-scope miss" in report
    assert "malicious-mcp-server@1.5.0" in report


@pytest.mark.skipif(
    not CAPTURES.is_dir(), reason="field-study captures are not in this checkout"
)
def test_week2_triage_regressions_on_the_real_captures() -> None:
    """The eight hand-triaged false positives stay clean on the pinned captures."""

    false_positives = [
        "npm-bitwarden-mcp-server-2026-7-0",
        "npm-heroku-mcp-server-1-2-15",
        "npm-meshy-ai-meshy-mcp-server-0-6-12",
        "npm-microsoft-clarity-mcp-server-3-0-0",
        "npm-notionhq-notion-mcp-server-2-6-1",
        "npm-qase-mcp-server-3-2-1",
        "npm-sap-ux-fiori-mcp-server-1-17-0",
        "npm-tsmztech-mcp-server-salesforce-0-0-8",
    ]
    for slug in false_positives:
        report = _capture_graph(slug)
        assert report.trifecta_paths == [], slug
        assert report.passed is True, slug

    # The one genuine manifest-only capability: a headless browser reads the
    # page (untrusted console/DOM content), reads response bodies from disk, and
    # navigates to a caller-chosen URL. It must survive the hardening.
    chrome = _capture_graph("npm-chrome-devtools-mcp-1-13-0")
    assert chrome.trifecta_paths
    assert {path.egress_tool for path in chrome.trifecta_paths} == {
        "npm-chrome-devtools-mcp-1-13-0:navigate_page"
    }
    assert {path.read_tool for path in chrome.trifecta_paths} == {
        "npm-chrome-devtools-mcp-1-13-0:get_network_request"
    }
    assert "npm-chrome-devtools-mcp-1-13-0:list_console_messages" in {
        path.ingest_tool for path in chrome.trifecta_paths
    }

    # The annotation grid that produced 20,664 paths is gone; what remains is
    # the product's real notification sink (`recipients`), not an inferred one.
    doit = _capture_graph("npm-doitintl-doit-mcp-server-5-1-0")
    assert 0 < len(doit.trifecta_paths) < 100
    by_name = {node.qualified_name: node for node in doit.nodes}
    for path in doit.trifecta_paths:
        egress = by_name[path.egress_tool]
        signals = {
            entry.signal for entry in egress.evidence if entry.tag == "EXTERNAL_EGRESS"
        }
        # The annotation may corroborate a sink, but must never stand alone.
        assert signals - {"annotation.openWorldEgress"}, path.egress_tool
        assert "schema.outbound_sink" in signals, path.egress_tool


def test_placeholder_credentials_are_fixed_dummies_and_opt_in(monkeypatch) -> None:
    """The third sample sets dummy env only on request; a host secret never passes."""

    monkeypatch.setenv("GITHUB_TOKEN", "host-real-token-value")
    with scratch_environment() as (env, _root):
        assert "GITHUB_TOKEN" not in env
    with scratch_environment(placeholder_credentials=True) as (env, _root):
        assert env["GITHUB_TOKEN"] == "latch-placeholder-not-a-real-token"
        assert env["GITHUB_TOKEN"] != "host-real-token-value"
        assert env["SUPABASE_URL"] == "https://placeholder.invalid"

    dummies = {
        "latch-placeholder-not-a-real-token",
        "latch-placeholder-not-a-real-secret",
        "latch-placeholder",
        "AKIALATCHPLACEHOLDER",
        "postgres://placeholder:placeholder@127.0.0.1:5432/placeholder",
        "mongodb://127.0.0.1:27017/placeholder",
        "redis://127.0.0.1:6379/0",
        "https://placeholder.invalid",
        "placeholder@example.invalid",
        "https://placeholder@placeholder.invalid/1",
        "xoxb-latch-placeholder",
        "xoxp-latch-placeholder",
        "sk_test_latch_placeholder",
        "000000000:latch-placeholder",
        "00000000-0000-0000-0000-000000000000",
        "AC00000000000000000000000000000000",
        "T00000000",
        "127.0.0.1",
        "placeholder",
        "us-east-1",
    }
    # Every value must be a literal dummy: adding a real-looking value fails here.
    assert set(PLACEHOLDER_CREDENTIAL_ENV.values()) <= dummies
    assert "host-real-token-value" not in PLACEHOLDER_CREDENTIAL_ENV.values()


def test_placeholder_harvest_records_its_credential_mode(tmp_path: Path) -> None:
    script = tmp_path / "mock_mcp.py"
    script.write_text(MOCK_STDIO, encoding="utf-8")
    target = {
        "slug": "pypi-mock-field-9-9-9",
        "ecosystem": "pypi",
        "package": "mock-field",
        "version": "9.9.9",
        "repository_url": None,
        "description": "offline fixture",
        "launch_argv": [sys.executable, str(script), str(tmp_path / "env.json")],
    }

    capture = harvest_target(target, timeout=10.0, placeholder_credentials=True)
    assert capture["credential_mode"] == "placeholder"
    assert capture["harvest_status"] == "harvested"
    child = json.loads((tmp_path / "env.json").read_text(encoding="utf-8"))
    assert "GITHUB_TOKEN" in child["env_keys"]
    assert "SUPABASE_URL" in child["env_keys"]

    plain = harvest_target(target, timeout=10.0)
    assert plain["credential_mode"] == "none"
    resume = json.loads((tmp_path / "env.json").read_text(encoding="utf-8"))
    assert "GITHUB_TOKEN" not in resume["env_keys"]
    assert "SUPABASE_URL" not in resume["env_keys"]


def test_composition_triage_record_and_seeded_draw_are_deterministic() -> None:
    """20 verdicts per round, and the sampler reproduces the recorded draw."""

    assert len(COMPOSITION_TRIAGE) == 40
    assert {verdict for verdict, _note in COMPOSITION_TRIAGE.values()} == set(
        COMPOSITION_TRIAGE_BUCKETS
    )
    assert all(note.strip() for _verdict, note in COMPOSITION_TRIAGE.values())

    rows = [{"composition_id": f"comp-{index:03d}"} for index in range(60)]
    first = [row["composition_id"] for row in sample_details(rows, seed=7, size=20)]
    again = [row["composition_id"] for row in sample_details(rows, seed=7, size=20)]
    other = [row["composition_id"] for row in sample_details(rows, seed=8, size=20)]
    assert first == again
    assert len(first) == 20
    assert other != first


@pytest.mark.skipif(
    not CAPTURES.is_dir(), reason="field-study captures are not in this checkout"
)
def test_composition_sweep_is_labelled_unvalidated_and_shows_the_triage() -> None:
    results = analyze(CAPTURES)
    compositions = results["compositions"]
    triage = compositions["triage"]
    report = render_report(results)

    assert "Unvalidated stress test on arbitrary server pairs — not findings." in report
    assert triage["sample_size"] == 20
    assert sum(triage["counts"].values()) == 20
    assert triage["untriaged"] == compositions["flagged_composition_count"] - 20
    assert (
        f"**{triage['counts']['real']} real, {triage['counts']['plausible']} plausible,"
        f" {triage['counts']['artifact']} artifact**"
    ) in report
    for row in triage["sampled"]:
        assert f"| `{row['composition_id']}` | `{row['verdict']}` |" in report


def test_placeholder_mode_is_stated_in_the_report(tmp_path: Path) -> None:
    captures = tmp_path / "captures"
    captures.mkdir()
    capture = _capture(
        "npm-mock-1-0-0",
        [{"name": "echo", "description": "Echo text.", "inputSchema": {"type": "object"}}],
    )
    capture["credential_mode"] = "placeholder"
    (captures / "npm-mock-1-0-0.json").write_text(
        json.dumps(capture), encoding="utf-8"
    )
    results = analyze(captures, tmp_path / "targets.json")
    report = render_report(results)

    assert results["credential_modes"]["placeholder"] == 1
    assert "Credential mode: **placeholder**" in report
    assert "`tools/list` returned with placeholder credentials." in report
    assert "--placeholder-credentials" in report
    assert "no real secret was used" in report

    plain_captures = tmp_path / "plain"
    plain_captures.mkdir()
    plain = _capture(
        "npm-mock-1-0-0",
        [{"name": "echo", "description": "Echo text.", "inputSchema": {"type": "object"}}],
    )
    (plain_captures / "npm-mock-1-0-0.json").write_text(json.dumps(plain), encoding="utf-8")
    plain_report = render_report(analyze(plain_captures, tmp_path / "targets.json"))
    assert "Credential mode:" not in plain_report
    assert "--placeholder-credentials" not in plain_report
