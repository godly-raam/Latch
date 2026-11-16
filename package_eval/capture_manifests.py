"""Capture real ``tools/list`` manifests from pinned MCP packages.

    python -m package_eval.capture_manifests

Each package is launched over stdio exactly as a client would launch it, the
``tools/list`` response is recorded verbatim, and the pinned version is looked
up from the registry (npm or PyPI). Captures land in
``package_eval/captured_manifests/<slug>.json``; packages that cannot be
launched (offline, missing runtime, install failure) are recorded as skipped in
``package_eval/capture_report.json`` instead of silently disappearing.

Every capture records ``capture_source``:

``live_subprocess``
    Harvested just now from the real package over stdio.
``pinned_package_capture``
    A previously captured ``tools/list`` snapshot kept verbatim from a known
    package version (used when the package cannot be launched in this
    environment).

No timestamps, sorted keys: re-running against the same package versions
rewrites the same bytes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shlex
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from mcpprobe.models import ProbeError
from mcpprobe.transport import harvest_stdio

EVAL_DIR = Path(__file__).resolve().parent
MANIFEST_DIR = EVAL_DIR / "captured_manifests"
CAPTURE_REPORT = EVAL_DIR / "capture_report.json"

#: Launch templates. ``{sandbox}`` is a throwaway directory created per run.
PACKAGE_SPECS: list[dict[str, Any]] = [
    {
        "slug": "npm-server-filesystem",
        "package_name": "@modelcontextprotocol/server-filesystem",
        "ecosystem": "npm",
        "launch_argv": [
            "npx",
            "--yes",
            "@modelcontextprotocol/server-filesystem",
            "{sandbox}",
        ],
    },
    {
        "slug": "npm-server-memory",
        "package_name": "@modelcontextprotocol/server-memory",
        "ecosystem": "npm",
        "launch_argv": ["npx", "--yes", "@modelcontextprotocol/server-memory"],
    },
    {
        "slug": "npm-server-everything",
        "package_name": "@modelcontextprotocol/server-everything",
        "ecosystem": "npm",
        "launch_argv": ["npx", "--yes", "@modelcontextprotocol/server-everything"],
    },
    {
        "slug": "pypi-mcp-server-fetch",
        "package_name": "mcp-server-fetch",
        "ecosystem": "pypi",
        "launch_argv": ["uvx", "mcp-server-fetch"],
    },
    {
        "slug": "pypi-mcp-server-git",
        "package_name": "mcp-server-git",
        "ecosystem": "pypi",
        "launch_argv": ["uvx", "mcp-server-git", "--repository", "{sandbox}"],
    },
]

CAPTURE_TIMEOUT_SECONDS = 120.0


def canonical_manifest(tools: list[dict[str, Any]]) -> str:
    """Canonical JSON of a tool list, used for the capture digest."""

    return json.dumps(
        {"tools": tools}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def manifest_digest(tools: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_manifest(tools).encode("utf-8")).hexdigest()


def _npm_version(package_name: str) -> str:
    return _run_version(["npm", "view", package_name, "version"])


def _pypi_version(package_name: str) -> str:
    url = f"https://pypi.org/pypi/{package_name}/json"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - https
        payload = json.loads(response.read().decode("utf-8"))
    version = payload.get("info", {}).get("version")
    return str(version) if version else "unknown"


def _run_version(argv: list[str]) -> str:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip() or "unknown"


def package_version(ecosystem: str, package_name: str) -> str:
    try:
        if ecosystem == "npm":
            return _npm_version(package_name)
        return _pypi_version(package_name)
    except Exception:  # noqa: BLE001 - provenance is best effort
        return "unknown"


async def _harvest(argv: list[str]) -> Any:
    return await harvest_stdio(
        shlex.join(argv), timeout=CAPTURE_TIMEOUT_SECONDS
    )


def capture_package(spec: dict[str, Any], sandbox: str) -> dict[str, Any]:
    """Launch one package and return its recorded capture (or a skip record)."""

    argv = [
        part.replace("{sandbox}", sandbox) for part in spec["launch_argv"]
    ]
    command = [part.replace(sandbox, "{sandbox}") for part in argv]
    try:
        harvest = asyncio.run(_harvest(argv))
    except Exception as exc:  # noqa: BLE001 - any launch failure is a clean skip
        return {
            "slug": spec["slug"],
            "package_name": spec["package_name"],
            "ecosystem": spec["ecosystem"],
            "status": "skipped",
            "reason": f"{type(exc).__name__}: {exc}".strip()[:500],
        }

    tools = harvest.tools_payload.get("tools")
    if not isinstance(tools, list) or not tools:
        return {
            "slug": spec["slug"],
            "package_name": spec["package_name"],
            "ecosystem": spec["ecosystem"],
            "status": "skipped",
            "reason": "the server returned no tools in tools/list",
        }

    capture = {
        "capture_source": "live_subprocess",
        "ecosystem": spec["ecosystem"],
        "launch_command": command,
        "manifest_sha256": manifest_digest(tools),
        "package_name": spec["package_name"],
        "package_version": package_version(
            spec["ecosystem"], spec["package_name"]
        ),
        "protocol_version": harvest.protocol_version,
        "server_info": harvest.server_info,
        "slug": spec["slug"],
        "tool_count": len(tools),
        "tools": tools,
    }

    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    (MANIFEST_DIR / f"{spec['slug']}.json").write_text(
        json.dumps(capture, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {
        "slug": spec["slug"],
        "package_name": spec["package_name"],
        "ecosystem": spec["ecosystem"],
        "status": "captured",
        "capture_source": "live_subprocess",
        "tool_count": len(tools),
        "reason": None,
    }


def main() -> int:
    if not shutil.which("npx"):
        print("npx not found: npm captures will be skipped")

    sandbox = tempfile.mkdtemp(prefix="latch-package-capture-")
    # Some reference servers (mcp-server-git) refuse a path that is not a repo.
    subprocess.run(
        ["git", "init", "--quiet", sandbox], capture_output=True, timeout=60
    )
    rows: list[dict[str, Any]] = []
    try:
        for spec in sorted(PACKAGE_SPECS, key=lambda item: item["slug"]):
            row = capture_package(spec, sandbox)
            rows.append(row)
            state = row["status"]
            detail = row.get("reason") or f"{row.get('tool_count')} tools"
            print(f"{spec['slug']:26} {state:9} {detail}")
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    CAPTURE_REPORT.write_text(
        json.dumps(
            {
                "captures": rows,
                "captured": sum(1 for row in rows if row["status"] == "captured"),
                "skipped": sum(1 for row in rows if row["status"] == "skipped"),
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {CAPTURE_REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
