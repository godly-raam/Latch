"""Live measurement of ``mcp-scan`` (``snyk-agent-scan``) on the real captures.

The head-to-head report compares Latch against the naive baseline **and** an
real peer scanner. This module runs the peer CLI for real against the five
clean upstream package captures in ``package_eval/captured_manifests/``, the
same bytes Latch and the baseline are scored on, and records exactly what
happened -- including the case where the scanner cannot run here.

Current releases of ``snyk-agent-scan`` (the package ``mcp-scan`` was renamed
to) require a Snyk API token and send the collected manifest to
``https://api.snyk.io/hidden/mcp-scan/analysis-machine`` for analysis. Without
credentials the CLI stops with an ``Unauthorized`` message and no findings, so
that outcome is recorded as ``credentials_required`` rather than invented as a
clean scan. With ``SNYK_TOKEN`` set, the run is parsed and stored as
``measured``.

The result is cached in ``head_to_head/mcp_scan_measurement.json`` under a
``cache_key`` covering the scanner version, the capture digests, the argument
list and whether a token is present, so a re-run is deterministic and CI does
not hit the network on every ``pytest``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
CACHE_PATH = EVAL_DIR / "mcp_scan_measurement.json"

#: The five clean upstream packages from ``package_eval``, by capture slug.
PACKAGE_SLUGS: tuple[str, ...] = (
    "npm-server-everything",
    "npm-server-filesystem",
    "npm-server-memory",
    "pypi-mcp-server-fetch",
    "pypi-mcp-server-git",
)

SCAN_TIMEOUT_SECONDS = 240.0

#: The endpoint current releases use for deep analysis (from ``--help``).
ANALYSIS_ENDPOINT = (
    "https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10"
)

_MEMO: dict[str, Any] | None = None
_MEMO_SCOPE: str | None = None


def resolve_binary() -> str | None:
    """Find the peer scanner, preferring the renamed binary over the shim."""

    for name in ("snyk-agent-scan", "mcp-scan"):
        path = shutil.which(name)
        if path:
            return path
    # ``pip install mcp-scan`` into a venv does not necessarily put the venv's
    # bin directory on PATH, which is exactly how the test suite runs it.
    for name in ("snyk-agent-scan", "mcp-scan"):
        candidate = Path(sys.executable).parent / name
        if candidate.exists():
            return str(candidate)
    return None


def scanner_version(binary: str) -> str | None:
    for distribution in ("snyk-agent-scan", "mcp-scan"):
        try:
            return distribution_version(distribution)
        except PackageNotFoundError:
            continue
    try:
        completed = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0].strip() if text else None


def build_config(
    captures: list[dict[str, Any]], sandbox: str
) -> dict[str, Any]:
    """An MCP client config that launches the exact pinned captured packages."""

    servers: dict[str, Any] = {}
    for capture in captures:
        if capture["slug"] not in PACKAGE_SLUGS:
            continue
        argv = [
            str(part).replace("{sandbox}", sandbox)
            for part in capture["launch_command"]
        ]
        servers[capture["slug"]] = {"command": argv[0], "args": argv[1:]}
    return {"mcpServers": servers}


def scan_args(config_path: Path, storage_path: Path) -> list[str]:
    return [
        "scan",
        str(config_path),
        "--json",
        "--no-skills",
        "--dangerously-run-mcp-servers",
        "--suppress-mcpserver-io",
        "true",
        "--storage-file",
        str(storage_path),
    ]


def _sha256_json(payload: Any) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def cache_key(
    captures: list[dict[str, Any]], binary: str | None, version: str | None
) -> str:
    return _sha256_json(
        {
            "analysis_endpoint": ANALYSIS_ENDPOINT,
            "binary": Path(binary).name if binary else None,
            "captures": {
                capture["slug"]: capture["manifest_sha256"]
                for capture in captures
                if capture["slug"] in PACKAGE_SLUGS
            },
            "token_present": bool(os.environ.get("SNYK_TOKEN")),
            "version": version,
        }
    )


def extract_flags(
    payload: Any, slugs: tuple[str, ...] = PACKAGE_SLUGS
) -> dict[str, bool]:
    """Best-effort per-server flags from an unknown JSON shape.

    Returns ``{}`` when the structure is not recognised: guessing would let a
    formatting change silently become a "clean" verdict.
    """

    flags: dict[str, bool] = {}

    def _findings(value: Any) -> list[Any] | None:
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for key in ("findings", "issues", "results", "risks"):
                if isinstance(value.get(key), list):
                    return value[key]
        return None

    def _flag(slug: str, container: Any) -> None:
        if slug not in slugs:
            return
        found = _findings(container)
        if found is not None:
            flags[slug] = bool(found)

    if isinstance(payload, dict):
        for key, value in payload.items():
            for slug in slugs:
                if key == slug or slug in key:
                    _flag(slug, value)
        for container_key in ("servers", "results", "scan_results"):
            nested = payload.get(container_key)
            if isinstance(nested, dict):
                for key, value in nested.items():
                    for slug in slugs:
                        if key == slug or slug in key:
                            _flag(slug, value)
            elif isinstance(nested, list):
                for row in nested:
                    if not isinstance(row, dict):
                        continue
                    label = str(
                        row.get("server")
                        or row.get("server_name")
                        or row.get("server_path")
                        or row.get("config_path")
                        or ""
                    )
                    for slug in slugs:
                        if slug in label:
                            _flag(slug, row)
    elif isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict):
                continue
            label = str(
                row.get("server")
                or row.get("server_name")
                or row.get("server_path")
                or row.get("config_path")
                or ""
            )
            for slug in slugs:
                if slug in label:
                    _flag(slug, row)

    return flags


def classify_run(
    *,
    token_present: bool,
    timed_out: bool,
    returncode: int | None,
    stdout: str,
    stderr: str,
) -> tuple[str, str | None]:
    """Map one CLI invocation onto a recorded status and a short reason."""

    combined = f"{stdout}\n{stderr}".lower()
    if timed_out:
        return "blocked_timeout", f"no result within {SCAN_TIMEOUT_SECONDS:.0f}s"
    if not token_present:
        return (
            "credentials_required",
            "snyk-agent-scan requires SNYK_TOKEN; no token is present",
        )
    if "unauthorized" in combined or "check your snyk_token" in combined:
        return "blocked_unauthorized", "the analysis endpoint rejected the token"
    if "connection" in combined or "network" in combined or "getaddrinfo" in combined:
        return "blocked_network_error", "the analysis endpoint was unreachable"
    if returncode is None:
        return "scan_error", "the scanner produced no exit code"
    return "measured", None


def _run(
    binary: str,
    version: str | None,
    captures: list[dict[str, Any]],
    key: str,
) -> dict[str, Any]:
    token_present = bool(os.environ.get("SNYK_TOKEN"))
    row: dict[str, Any] = {
        "tool": "mcp-scan",
        "distribution": "snyk-agent-scan",
        "version": version,
        "binary": Path(binary).name,
        "packages": list(PACKAGE_SLUGS),
        "analysis_endpoint": ANALYSIS_ENDPOINT,
        "remote_api_required": True,
        "token_present": token_present,
        "status": "scan_error",
        "reason": None,
        "exit_code": None,
        "command": None,
        "parsed": False,
        "package_flags": {},
        "flagged_packages": [],
        "clean_false_positive_rate": None,
        "cache_key": key,
    }

    sandbox = tempfile.mkdtemp(prefix="latch-mcp-scan-")
    storage = Path(sandbox) / "scan-state.json"
    config_path = Path(sandbox) / "mcp-scan-config.json"
    config_path.write_text(
        json.dumps(build_config(captures, sandbox), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    args = scan_args(config_path, storage)
    row["command"] = [
        Path(binary).name,
        "scan",
        "<temp>/mcp-scan-config.json",
        "--json",
        "--no-skills",
        "--dangerously-run-mcp-servers",
        "--suppress-mcpserver-io",
        "true",
        "--storage-file",
        "<temp>/scan-state.json",
    ]

    completed: subprocess.CompletedProcess[str] | None = None
    timed_out = False
    try:
        completed = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            env={**os.environ},
        )
        stdout, stderr = completed.stdout, completed.stderr
        row["exit_code"] = completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    except OSError as exc:
        stdout, stderr = "", f"{type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    status, reason = classify_run(
        token_present=token_present,
        timed_out=timed_out,
        returncode=None if completed is None else completed.returncode,
        stdout=stdout,
        stderr=stderr,
    )
    row["status"] = status
    row["reason"] = reason

    if status == "measured":
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = None
        flags = extract_flags(payload) if payload is not None else {}
        if flags:
            row["parsed"] = True
            row["package_flags"] = flags
            row["flagged_packages"] = sorted(
                slug for slug, flagged in flags.items() if flagged
            )
            row["clean_false_positive_rate"] = (
                round(len(row["flagged_packages"]) / len(flags), 4) if flags else 0.0
            )
            row["clean_package_count"] = len(flags) - len(row["flagged_packages"])
        else:
            row["status"] = "measured_unparsed"
            row["reason"] = (
                "the scanner ran but its JSON shape was not recognised; no"
                " per-package verdict is claimed"
            )

    return row


def run_measurement(
    captures: list[dict[str, Any]],
    *,
    force: bool = False,
    cache_path: Path | None = None,
) -> dict[str, Any]:
    """Return the cached measurement, running the CLI only when the key moves.

    ``cache_path`` redirects the cache to another file (tests use a temporary
    directory so a plain ``pytest`` run never rewrites the tracked artifact).
    """

    global _MEMO, _MEMO_SCOPE

    path = Path(cache_path) if cache_path is not None else CACHE_PATH
    scope = str(path.resolve())
    binary = resolve_binary()
    version = scanner_version(binary) if binary else None
    key = cache_key(captures, binary, version)

    if (
        not force
        and _MEMO is not None
        and _MEMO.get("cache_key") == key
        and _MEMO_SCOPE == scope
    ):
        return _MEMO

    if not force and path.exists():
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cached = None
        if cached is not None and cached.get("cache_key") == key:
            _MEMO = cached
            _MEMO_SCOPE = scope
            return cached

    if binary is None:
        row = {
            "tool": "mcp-scan",
            "distribution": "snyk-agent-scan",
            "version": None,
            "binary": None,
            "packages": list(PACKAGE_SLUGS),
            "analysis_endpoint": ANALYSIS_ENDPOINT,
            "remote_api_required": True,
            "token_present": bool(os.environ.get("SNYK_TOKEN")),
            "status": "not_installed_in_env",
            "reason": "neither snyk-agent-scan nor mcp-scan is on PATH",
            "exit_code": None,
            "command": None,
            "parsed": False,
            "package_flags": {},
            "flagged_packages": [],
            "clean_false_positive_rate": None,
            "cache_key": key,
        }
    else:
        row = _run(binary, version, captures, key)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _MEMO = row
    _MEMO_SCOPE = scope
    return row
