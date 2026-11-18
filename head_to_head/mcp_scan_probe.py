"""Live measurement of ``mcp-scan`` (``snyk-agent-scan``) on the real captures.

The head-to-head report compares Latch against the naive baseline **and** an
real peer scanner. This module runs the peer CLI for real against the five
clean upstream package captures in ``package_eval/captured_manifests/``, the
same bytes Latch and the baseline are scored on, and records exactly what
happened -- including the case where the scanner cannot run here.

Current releases of ``snyk-agent-scan`` (the package ``mcp-scan`` was renamed
to) require a Snyk API token and send the collected manifest to
``https://api.snyk.io/hidden/mcp-scan/analysis-machine`` for analysis. Version
``0.6.11`` always exits ``0`` and reports the analysis outcome inside a
``scan_path_responses`` payload: a ``401 Unauthorized`` or ``429 Too Many
Requests`` from the API arrives as ``scan_path_responses[].error`` with
``category: "analysis_error"``, and a completed analysis carries
``server_risks[].risk_indexes``. ``parse_scan_path_responses`` reads that
schema natively, so a rejected or rate-limited run is recorded as
``unauthorized``/``rate_limited`` -- never as a clean scan -- and a real run as
``measured``. Without a token the CLI raises before contacting the API, which
is recorded as ``credentials_required``.

The result is cached in ``head_to_head/mcp_scan_measurement.json`` under a
``cache_key`` covering the scanner version, the capture digests, the argument
list and whether a token is present, so a re-run is deterministic and CI does
not hit the network on every ``pytest``.

Two properties matter for a committed cache file. It must never contain the
token: every record is scrubbed of the ``SNYK_TOKEN`` value and of token-shaped
strings (``Bearer ...``, UUIDs) before it is memoised or written. And a
``measured`` record must survive a token-less environment: its ``reuse_key``
covers the scanner version and capture digests but not the token, so CI and a
contributor's clone reuse the real verdict instead of overwriting it with
``credentials_required``. ``--force-refresh`` is the only way to replace it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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


def _cache_identity(
    captures: list[dict[str, Any]], binary: str | None, version: str | None
) -> dict[str, Any]:
    """What a measurement is about: the scanner, its version and the bytes."""

    return {
        "analysis_endpoint": ANALYSIS_ENDPOINT,
        "binary": Path(binary).name if binary else None,
        "captures": {
            capture["slug"]: capture["manifest_sha256"]
            for capture in captures
            if capture["slug"] in PACKAGE_SLUGS
        },
        "version": version,
    }


def cache_key(
    captures: list[dict[str, Any]], binary: str | None, version: str | None
) -> str:
    """Identity of one live run, including whether a token was present."""

    return _sha256_json(
        {
            **_cache_identity(captures, binary, version),
            "token_present": bool(os.environ.get("SNYK_TOKEN")),
        }
    )


def reusable_key(
    captures: list[dict[str, Any]], binary: str | None, version: str | None
) -> str:
    """Identity that ignores the token, so a measured record outlives it.

    A ``measured`` record produced in a token environment stays valid in CI and
    on a contributor's clone, where ``SNYK_TOKEN`` is absent. The record still
    says which run produced it through its own ``token_present`` field.
    """

    return _sha256_json(_cache_identity(captures, binary, version))


#: Strings that must never reach the committed cache file. The scanner inherits
#: the caller's environment, so the token can surface in an echoed header, an
#: error message or a stack trace even though this module never logs it.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
        "Bearer [REDACTED]",
    ),
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "[REDACTED]",
    ),
)


def scrub_secrets(value: Any, secret: str | None = None) -> Any:
    """Return ``value`` with the token value and token-shaped strings removed.

    Applied to every measurement before it is memoised or written, so a
    committed cache file cannot leak ``SNYK_TOKEN`` regardless of what the peer
    CLI prints.
    """

    if isinstance(value, dict):
        return {key: scrub_secrets(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub_secrets(item, secret) for item in value]
    if isinstance(value, str):
        if secret and len(secret) >= 6 and secret in value:
            value = value.replace(secret, "[REDACTED]")
        for pattern, replacement in _SECRET_PATTERNS:
            value = pattern.sub(replacement, value)
        return value
    return value


#: Statuses derived from a ``scan_path_responses`` payload. The CLI exits ``0``
#: even when Snyk's analysis API rejected the request, so the payload -- not the
#: exit code -- decides the verdict.
STATUS_MEASURED = "measured"
STATUS_UNAUTHORIZED = "unauthorized"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_API_ERROR = "api_error"

_UNAUTHORIZED_RE = re.compile(
    r"(?i)\b401\b|\b403\b|\bunauthorized\b|\bforbidden\b|check your snyk_token"
)
_RATE_LIMIT_RE = re.compile(
    r"(?i)\b429\b|too many requests|daily usage limit|rate.?limit"
)
_WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\s\"']+")
_POSIX_PATH_RE = re.compile(
    r"(?<![\w:/])/(?:tmp|var|home|Users|private|run|root|opt)/[^\s\"'`,;)]+"
)


def sanitize_text(
    value: Any, secret: str | None = None, limit: int = 300
) -> str | None:
    """A short excerpt of peer CLI text with tokens and local paths removed.

    Exception strings and tracebacks are read only to classify a status; what
    is recorded is this excerpt, never the raw text.
    """

    if value is None:
        return None
    text = scrub_secrets(str(value), secret)
    text = _WINDOWS_PATH_RE.sub("<path>", text)
    text = _POSIX_PATH_RE.sub("<path>", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text or None


def _first_failure(entry: dict[str, Any]) -> dict[str, Any] | None:
    """The first failing error on a scanned path or one of its servers."""

    candidates: list[Any] = [entry.get("error")]
    server_risks = entry.get("server_risks")
    if isinstance(server_risks, list):
        candidates.extend(
            server.get("error")
            for server in server_risks
            if isinstance(server, dict)
        )
    for error in candidates:
        # ``is_failure`` is part of the schema and is ``False`` for benign
        # conditions such as a config file that does not exist.
        if (
            isinstance(error, dict)
            and error
            and error.get("is_failure", True) is not False
        ):
            return error
    return None


def classify_api_error(
    error: dict[str, Any], secret: str | None = None
) -> dict[str, Any]:
    """Map one ``scan_path_responses[].error`` onto a recorded verdict."""

    text = " ".join(
        str(error.get(field) or "")
        for field in ("message", "exception", "server_output")
    )
    category = sanitize_text(error.get("category"), secret)
    message = sanitize_text(error.get("message") or error.get("exception"), secret)
    if _RATE_LIMIT_RE.search(text):
        status = STATUS_RATE_LIMITED
        reason = "429 Daily usage limit reached on Snyk public analysis-machine API"
    elif _UNAUTHORIZED_RE.search(text):
        status = STATUS_UNAUTHORIZED
        reason = "401 Unauthorized from Snyk analysis-machine API"
    else:
        status = STATUS_API_ERROR
        reason = "analysis API error"
        if category:
            reason += f" ({category})"
        if message:
            reason += f": {message}"
    return {
        "status": status,
        "reason": reason,
        "parsed": True,
        "package_flags": {},
        "flagged_packages": [],
        "clean_false_positive_rate": None,
        "clean_package_count": None,
        "scanned_servers": [],
        "api_error_category": category,
        "api_error_message": message,
    }


def _package_slug(label: Any, slugs: tuple[str, ...]) -> str | None:
    """The configured capture slug a ``server_risks[].name`` refers to."""

    text = str(label or "")
    if not text:
        return None
    if text in slugs:
        return text
    for slug in slugs:
        if slug in text:
            return slug
    return None


def parse_scan_path_responses(
    payload: Any,
    slugs: tuple[str, ...] = PACKAGE_SLUGS,
    secret: str | None = None,
) -> dict[str, Any] | None:
    """Interpret ``snyk-agent-scan`` 0.6.11's ``scan_path_responses`` payload.

    Returns ``None`` -- never a clean verdict -- for any shape this version does
    not define, so a formatting change cannot be misread as "no findings".
    """

    if not isinstance(payload, dict):
        return None
    responses = payload.get("scan_path_responses")
    if not isinstance(responses, list):
        return None
    entries = [entry for entry in responses if isinstance(entry, dict)]
    if not entries:
        return None

    for entry in entries:
        failure = _first_failure(entry)
        if failure is not None:
            return classify_api_error(failure, secret)

    flags: dict[str, bool] = {}
    scanned: list[str] = []
    for entry in entries:
        server_risks = entry.get("server_risks")
        if not isinstance(server_risks, list):
            continue
        for server in server_risks:
            if not isinstance(server, dict):
                continue
            slug = _package_slug(server.get("name"), slugs)
            if slug is None:
                continue
            if slug not in scanned:
                scanned.append(slug)
            indexes = server.get("risk_indexes")
            # The CLI omits ``None`` indexes, so a non-empty mapping is exactly
            # the peer's own "this server has a risk" condition.
            risky = isinstance(indexes, dict) and any(
                value is not None for value in indexes.values()
            )
            flags[slug] = flags.get(slug, False) or risky
    if not flags:
        return None

    flagged = sorted(slug for slug, hit in flags.items() if hit)
    return {
        "status": STATUS_MEASURED,
        "reason": None,
        "parsed": True,
        "package_flags": flags,
        "flagged_packages": flagged,
        "clean_false_positive_rate": round(len(flagged) / len(flags), 4),
        "clean_package_count": len(flags) - len(flagged),
        "scanned_servers": scanned,
        "api_error_category": None,
        "api_error_message": None,
    }


def _load_payload(stdout: str) -> Any:
    """Parse the CLI's JSON, tolerating a banner line before it."""

    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for match in re.finditer(r"(?m)^\{", text):
        try:
            return json.loads(text[match.start() :])
        except json.JSONDecodeError:
            continue
    return None


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
    reuse_key: str,
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
        "scanned_servers": [],
        "api_error_category": None,
        "api_error_message": None,
        "cache_key": key,
        "reuse_key": reuse_key,
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

    # The payload is authoritative: 0.6.11 exits 0 for a 401/429 and puts the
    # reason in ``scan_path_responses[].error``, so parsing first is what keeps
    # a rejected run from being recorded as "measured".
    payload = _load_payload(stdout)
    verdict = parse_scan_path_responses(
        payload, PACKAGE_SLUGS, os.environ.get("SNYK_TOKEN")
    )
    if verdict is not None:
        row.update(verdict)
        return row

    # Fallback for an unparseable run or another version's output shape.
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
    """Return the cached measurement, running the CLI only when it is needed.

    ``cache_path`` redirects the cache to another file (tests use a temporary
    directory so a plain ``pytest`` run never rewrites the tracked artifact).

    ``force`` (``--force-refresh``) is the only way to replace a matching
    record: a ``measured`` verdict is reused without a token, because CI and a
    fresh clone must not trade a real measurement for ``credentials_required``.
    """

    global _MEMO, _MEMO_SCOPE

    path = Path(cache_path) if cache_path is not None else CACHE_PATH
    scope = str(path.resolve())
    binary = resolve_binary()
    version = scanner_version(binary) if binary else None
    key = cache_key(captures, binary, version)
    reuse_key = reusable_key(captures, binary, version)
    token_present = bool(os.environ.get("SNYK_TOKEN"))
    secret = os.environ.get("SNYK_TOKEN")

    def _is_reusable(cached: dict[str, Any]) -> bool:
        """A measured record survives an environment without the token."""

        return (
            not token_present
            and cached.get("status") == "measured"
            and cached.get("reuse_key") == reuse_key
        )

    def _matches(cached: dict[str, Any]) -> bool:
        return cached.get("cache_key") == key or _is_reusable(cached)

    if (
        not force
        and _MEMO is not None
        and _MEMO_SCOPE == scope
        and _matches(_MEMO)
    ):
        return _MEMO

    if not force and path.exists():
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cached = None
        if cached is not None and _matches(cached):
            # Scrub on read as well: a record written before this guard existed
            # must not keep leaking through a reused measurement.
            cleaned = scrub_secrets(cached, secret)
            if cleaned != cached:
                path.write_text(
                    json.dumps(
                        cleaned, indent=2, sort_keys=True, ensure_ascii=False
                    )
                    + "\n",
                    encoding="utf-8",
                )
            _MEMO = cleaned
            _MEMO_SCOPE = scope
            return cleaned

    if binary is None:
        row: dict[str, Any] = {
            "tool": "mcp-scan",
            "distribution": "snyk-agent-scan",
            "version": None,
            "binary": None,
            "packages": list(PACKAGE_SLUGS),
            "analysis_endpoint": ANALYSIS_ENDPOINT,
            "remote_api_required": True,
            "token_present": token_present,
            "status": "not_installed_in_env",
            "reason": "neither snyk-agent-scan nor mcp-scan is on PATH",
            "exit_code": None,
            "command": None,
            "parsed": False,
            "package_flags": {},
            "flagged_packages": [],
            "clean_false_positive_rate": None,
            "scanned_servers": [],
            "api_error_category": None,
            "api_error_message": None,
            "cache_key": key,
            "reuse_key": reuse_key,
        }
    else:
        row = _run(binary, version, captures, key, reuse_key)

    row = scrub_secrets(row, secret)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _MEMO = row
    _MEMO_SCOPE = scope
    return row
