"""Capture real ``tools/list`` manifests and transport metadata from MCP packages.

    python -m package_eval.capture_manifests

Each package is launched exactly as a client would launch it. For a real server
the ``tools/list`` response is recorded verbatim; for a proxy/transport package
(``mcp-remote``, ``mcp-proxy``) the package exposes no tools of its own, so its
real CLI surface and the cleartext transport it serves are recorded instead.
The pinned version is resolved from the registry (npm or PyPI). Captures land in
``package_eval/captured_manifests/<slug>.json``; packages that cannot be
launched (offline, missing runtime, install failure) are recorded as skipped in
``package_eval/capture_report.json`` instead of silently disappearing.

Every capture records ``capture_source``:

``live_subprocess``
    Harvested just now from the real package over stdio.
``live_proxy_metadata``
    The package is a proxy: its CLI is invoked for real, its cleartext SSE
    endpoint is probed if it serves one, and the exposed transport is recorded.
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
import http.client
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

from mcpprobe.transport import harvest_stdio

EVAL_DIR = Path(__file__).resolve().parent
MANIFEST_DIR = EVAL_DIR / "captured_manifests"
CAPTURE_REPORT = EVAL_DIR / "capture_report.json"

CAPTURE_TIMEOUT_SECONDS = 180.0
PROXY_PROBE_TIMEOUT_SECONDS = 30.0

#: Launch templates. ``{sandbox}`` is a throwaway directory created per run.
#:
#: ``kind`` separates real tool surfaces from proxy/transport packages, and
#: ``in_latch_threat_model`` states whether the audited failure is something a
#: static manifest auditor can see at all. Handler-level CVEs (path traversal,
#: argument injection) are *not*: they need code or runtime analysis, so they
#: are captured and scored honestly as out of model.
PACKAGE_SPECS: list[dict[str, Any]] = [
    {
        "slug": "npm-server-filesystem",
        "expected_positive": False,
        "package_name": "@modelcontextprotocol/server-filesystem",
        "ecosystem": "npm",
        "version_pin": None,
        "kind": "stdio_tools",
        "launch_argv": [
            "npx",
            "--yes",
            "@modelcontextprotocol/server-filesystem",
            "{sandbox}",
        ],
        "in_latch_threat_model": False,
        "vulnerability_class": "clean_reference_server",
        "cve_refs": [],
        "note": "First-party reference server with no captured advisory.",
    },
    {
        "slug": "npm-server-memory",
        "expected_positive": False,
        "package_name": "@modelcontextprotocol/server-memory",
        "ecosystem": "npm",
        "version_pin": None,
        "kind": "stdio_tools",
        "launch_argv": ["npx", "--yes", "@modelcontextprotocol/server-memory"],
        "in_latch_threat_model": False,
        "vulnerability_class": "clean_reference_server",
        "cve_refs": [],
        "note": "First-party reference server with no captured advisory.",
    },
    {
        "slug": "npm-server-everything",
        "expected_positive": False,
        "package_name": "@modelcontextprotocol/server-everything",
        "ecosystem": "npm",
        "version_pin": None,
        "kind": "stdio_tools",
        "launch_argv": ["npx", "--yes", "@modelcontextprotocol/server-everything"],
        "in_latch_threat_model": False,
        "vulnerability_class": "clean_reference_server",
        "cve_refs": [],
        "note": (
            "SDK diagnostics server: its parameter names and open-world"
            " annotations over-approximate into static capability edges."
        ),
    },
    {
        "slug": "pypi-mcp-server-fetch",
        "expected_positive": False,
        "package_name": "mcp-server-fetch",
        "ecosystem": "pypi",
        "version_pin": None,
        "kind": "stdio_tools",
        "launch_argv": ["uvx", "mcp-server-fetch"],
        "in_latch_threat_model": False,
        "vulnerability_class": "cross_server_composition_member",
        "cve_refs": [],
        "note": (
            "Untrusted web content ingestion used as the ingest half of target"
            " B; on its own it has no egress sink and no advisory."
        ),
    },
    {
        "slug": "pypi-mcp-server-git",
        "expected_positive": False,
        "package_name": "mcp-server-git",
        "ecosystem": "pypi",
        "version_pin": None,
        "kind": "stdio_tools",
        "launch_argv": ["uvx", "mcp-server-git", "--repository", "{sandbox}"],
        "in_latch_threat_model": False,
        "vulnerability_class": "clean_reference_server",
        "cve_refs": [],
        "note": "Current release; local state mutations only.",
    },
    {
        "slug": "npm-server-filesystem-0-6-2",
        "expected_positive": True,
        "package_name": "@modelcontextprotocol/server-filesystem",
        "ecosystem": "npm",
        "version_pin": "0.6.2",
        "kind": "stdio_tools",
        "launch_argv": [
            "npx",
            "--yes",
            "@modelcontextprotocol/server-filesystem@0.6.2",
            "{sandbox}",
        ],
        "in_latch_threat_model": False,
        "vulnerability_class": "handler_implementation_cve",
        "cve_refs": ["CVE-2025-53109", "CVE-2025-53110"],
        "note": (
            "Pre-patch symlink and path-prefix bypass in the file handlers."
            " Handler code is outside a tools/list threat model; 0.6.3 does not"
            " exist on the npm registry, so 0.6.2 is the last pre-patch 0.6.x."
        ),
    },
    {
        "slug": "pypi-mcp-server-git-2025-9-25",
        "expected_positive": True,
        "package_name": "mcp-server-git",
        "ecosystem": "pypi",
        "version_pin": "2025.9.25",
        "kind": "stdio_tools",
        "launch_argv": [
            "uvx",
            "--with",
            "pydantic==2.10.6",
            "--with",
            "mcp==1.9.4",
            "--from",
            "mcp-server-git==2025.9.25",
            "mcp-server-git",
            "--repository",
            "{sandbox}",
        ],
        "in_latch_threat_model": False,
        "vulnerability_class": "handler_implementation_cve",
        "cve_refs": ["CVE-2025-68145", "CVE-2025-68143"],
        "note": (
            "Pre-patch git argument/path injection in the tool handlers. The"
            " 2025.9.25 release needs mcp==1.9.4 and pydantic==2.10.6 pinned to"
            " start at all, and it predates the 2026 ``_meta`` request envelope,"
            " so it is harvested with the plain 2025 initialize handshake; its"
            " own tool metadata is unchanged."
        ),
        "legacy_handshake": True,
    },
    {
        "slug": "npm-mcp-remote-0-14-3",
        "expected_positive": True,
        "package_name": "mcp-remote",
        "ecosystem": "npm",
        "version_pin": "0.14.3",
        "kind": "proxy_metadata",
        "launch_argv": [
            "npx",
            "--yes",
            "mcp-remote@0.14.3",
            "http://remote-mcp.example.com/sse",
            "--allow-http",
        ],
        "in_latch_threat_model": True,
        "vulnerability_class": "cleartext_http_oauth_transport",
        "cve_refs": ["CVE-2026-108716", "CVE-2025-6514"],
        "note": (
            "Pre-0.15.0 accepts a cleartext http remote URL with --allow-http,"
            " so OAuth codes and bearer tokens cross the network in the clear."
        ),
        "exposed_url": "http://remote-mcp.example.com/sse",
        "exposed_headers": {"Authorization": "Bearer ${MCP_TOKEN}"},
    },
    {
        "slug": "pypi-mcp-proxy-0-8-2",
        "expected_positive": True,
        "package_name": "mcp-proxy",
        "ecosystem": "pypi",
        "version_pin": "0.8.2",
        "kind": "proxy_metadata",
        "launch_argv": [
            "uvx",
            "--from",
            "mcp-proxy==0.8.2",
            "mcp-proxy",
            "--port",
            "18008",
            "--host",
            "0.0.0.0",
            "npx",
            "@modelcontextprotocol/server-filesystem@2.3.0",
            "{sandbox}",
        ],
        "in_latch_threat_model": True,
        "vulnerability_class": "unauthenticated_cleartext_sse_bridge",
        "cve_refs": [],
        "note": (
            "Bridges a stdio server to an SSE endpoint with no authentication"
            " and no TLS; version 0.8.2 predates its streamable-http transport."
        ),
        "exposed_url": "http://0.0.0.0:18008/sse",
        "exposed_headers": {"Authorization": "Bearer ${MCP_TOKEN}"},
        "probe_url": "http://127.0.0.1:18008/sse",
    },
]


def canonical_manifest(tools: list[dict[str, Any]]) -> str:
    """Canonical JSON of a tool list, used for the capture digest."""

    return json.dumps(
        {"tools": tools}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def manifest_digest(tools: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_manifest(tools).encode("utf-8")).hexdigest()


def _npm_version(package_name: str, pin: str | None = None) -> str:
    target = f"{package_name}@{pin}" if pin else package_name
    return _run_version(["npm", "view", target, "version"])


def _pypi_version(package_name: str, pin: str | None = None) -> str:
    base = f"https://pypi.org/pypi/{package_name}"
    url = f"{base}/{pin}/json" if pin else f"{base}/json"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - https
        payload = json.loads(response.read().decode("utf-8"))
    version = payload.get("info", {}).get("version")
    return str(version) if version else "unknown"


def _run_version(argv: list[str]) -> str:
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip() or "unknown"


def package_version(
    ecosystem: str, package_name: str, pin: str | None = None
) -> str:
    try:
        if ecosystem == "npm":
            return _npm_version(package_name, pin)
        return _pypi_version(package_name, pin)
    except Exception:  # noqa: BLE001 - provenance is best effort
        return "unknown"


async def _harvest(argv: list[str]) -> Any:
    return await harvest_stdio(
        shlex.join(argv), timeout=CAPTURE_TIMEOUT_SECONDS
    )


async def _legacy_harvest(argv: list[str]) -> dict[str, Any]:
    """Minimal 2025-11-25 style stdio handshake without the ``_meta`` envelope.

    A pinned pre-patch server can ship an SDK whose ``initialize`` params model
    rejects unknown fields (``-32602``). That is a protocol-generation gap, not
    a finding, so the capture speaks the older handshake directly instead of
    changing Latch's transport for every server.
    """

    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def send(payload: dict[str, Any]) -> None:
        assert process.stdin is not None
        process.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
        await process.stdin.drain()

    async def read_response(request_id: int) -> dict[str, Any]:
        assert process.stdout is not None
        while True:
            line = await asyncio.wait_for(
                process.stdout.readline(), timeout=CAPTURE_TIMEOUT_SECONDS
            )
            if not line:
                raise RuntimeError("server closed stdout before replying")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(f"JSON-RPC error {message['error']}")
                return message.get("result") or {}

    try:
        await send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "latch-package-eval",
                        "version": "0.3.2",
                    },
                },
            }
        )
        initialized = await read_response(1)
        await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        await send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listing = await read_response(2)
    finally:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except asyncio.TimeoutError:  # pragma: no cover - defensive
            process.kill()

    return {
        "capabilities": initialized.get("capabilities"),
        "protocol_version": str(initialized.get("protocolVersion") or "2025-06-18"),
        "server_info": initialized.get("serverInfo"),
        "tools": listing.get("tools"),
    }


def _launch_argv(spec: dict[str, Any], sandbox: str) -> list[str]:
    return [part.replace("{sandbox}", sandbox) for part in spec["launch_argv"]]


def _recorded_argv(argv: list[str], sandbox: str) -> list[str]:
    return [part.replace(sandbox, "{sandbox}") for part in argv]


def _spec_metadata(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_refs": list(spec["cve_refs"]),
        "in_latch_threat_model": spec["in_latch_threat_model"],
        "expected_positive": spec["expected_positive"],
        "kind": spec["kind"],
        "note": spec["note"],
        "vulnerability_class": spec["vulnerability_class"],
    }


def _skip(spec: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "slug": spec["slug"],
        "package_name": spec["package_name"],
        "ecosystem": spec["ecosystem"],
        "kind": spec["kind"],
        "status": "skipped",
        "reason": reason,
    }


def _write_capture(slug: str, capture: dict[str, Any]) -> None:
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    (MANIFEST_DIR / f"{slug}.json").write_text(
        json.dumps(capture, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def capture_package(spec: dict[str, Any], sandbox: str) -> dict[str, Any]:
    """Launch one package and return its recorded capture (or a skip record)."""

    if spec["kind"] == "proxy_metadata":
        return _capture_proxy(spec, sandbox)

    argv = _launch_argv(spec, sandbox)
    command = _recorded_argv(argv, sandbox)
    try:
        if spec.get("legacy_handshake"):
            legacy = asyncio.run(_legacy_harvest(argv))
            tools = legacy["tools"]
            protocol_version = legacy["protocol_version"]
            server_info = legacy["server_info"]
        else:
            harvest = asyncio.run(_harvest(argv))
            tools = harvest.tools_payload.get("tools")
            protocol_version = harvest.protocol_version
            server_info = harvest.server_info
    except Exception as exc:  # noqa: BLE001 - any launch failure is a clean skip
        return _skip(
            spec, f"{type(exc).__name__}: {exc}".strip()[:500]
        )

    if not isinstance(tools, list) or not tools:
        return _skip(spec, "the server returned no tools in tools/list")

    capture = {
        "capture_source": "live_subprocess",
        "ecosystem": spec["ecosystem"],
        "launch_command": command,
        "manifest_sha256": manifest_digest(tools),
        "package_name": spec["package_name"],
        "package_version": package_version(
            spec["ecosystem"], spec["package_name"], spec.get("version_pin")
        ),
        "protocol_version": protocol_version,
        "server_info": server_info,
        "slug": spec["slug"],
        "tool_count": len(tools),
        "tools": tools,
        **_spec_metadata(spec),
    }

    _write_capture(spec["slug"], capture)
    return {
        "slug": spec["slug"],
        "package_name": spec["package_name"],
        "ecosystem": spec["ecosystem"],
        "kind": spec["kind"],
        "status": "captured",
        "capture_source": "live_subprocess",
        "tool_count": len(tools),
        "reason": None,
    }


# -- proxy / transport captures --------------------------------------------


def _cli_probe(argv: list[str]) -> dict[str, Any]:
    """Invoke a proxy CLI for real and record its stable usage line."""

    try:
        completed = subprocess.run(
            [*argv, "--help"],
            capture_output=True,
            text=True,
            timeout=CAPTURE_TIMEOUT_SECONDS,
            env={**os.environ, "NPM_CONFIG_YES": "true"},
        )
    except Exception as exc:  # noqa: BLE001 - the probe is best effort
        return {"status": "skipped", "reason": f"{type(exc).__name__}: {exc}"[:300]}

    text = f"{completed.stdout}\n{completed.stderr}"
    usage = next(
        (line.strip() for line in text.splitlines() if "Usage:" in line), None
    )
    return {
        "status": "ok",
        "exit_code": completed.returncode,
        "usage": usage,
    }


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex((host, port)) == 0


def _sse_probe(url: str, timeout: float = PROXY_PROBE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Fetch the SSE response headers from a proxy endpoint."""

    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 80
    path = parts.path or "/sse"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_open(host, port):
            break
        time.sleep(0.5)
    else:
        return {"status": "skipped", "reason": "endpoint never accepted a connection"}

    try:
        connection = http.client.HTTPConnection(host, port, timeout=5.0)
        connection.request("GET", path)
        response = connection.getresponse()
        content_type = response.getheader("content-type") or ""
        status = response.status
        authenticate = response.getheader("www-authenticate")
        connection.close()
    except Exception as exc:  # noqa: BLE001 - the probe is best effort
        return {"status": "skipped", "reason": f"{type(exc).__name__}: {exc}"[:300]}

    return {
        "status": "ok",
        "http_status": status,
        "content_type": content_type.split(";")[0].strip(),
        "authentication_challenge": authenticate is not None,
        "cleartext": parts.scheme == "http",
    }


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()


def _capture_proxy(spec: dict[str, Any], sandbox: str) -> dict[str, Any]:
    argv = _launch_argv(spec, sandbox)
    command = _recorded_argv(argv, sandbox)

    probe: dict[str, Any] = {
        "cli": _cli_probe(argv),
    }
    if spec.get("probe_url"):
        process = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "NPM_CONFIG_YES": "true"},
            start_new_session=True,
        )
        try:
            probe["transport"] = _sse_probe(spec["probe_url"])
        finally:
            _terminate(process)

    capture = {
        "capture_source": "live_proxy_metadata",
        "ecosystem": spec["ecosystem"],
        "exposed_headers": dict(spec.get("exposed_headers") or {}),
        "exposed_url": spec["exposed_url"],
        "launch_command": command,
        "manifest_sha256": manifest_digest([]),
        "package_name": spec["package_name"],
        "package_version": package_version(
            spec["ecosystem"], spec["package_name"], spec.get("version_pin")
        ),
        "protocol_version": "n/a",
        "probe": probe,
        "server_info": {
            "name": spec["package_name"],
            "version": spec.get("version_pin") or "unknown",
        },
        "slug": spec["slug"],
        "tool_count": 0,
        "tools": [],
        **_spec_metadata(spec),
    }

    _write_capture(spec["slug"], capture)
    return {
        "slug": spec["slug"],
        "package_name": spec["package_name"],
        "ecosystem": spec["ecosystem"],
        "kind": spec["kind"],
        "status": "captured",
        "capture_source": "live_proxy_metadata",
        "tool_count": 0,
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
            print(f"{spec['slug']:32} {state:9} {detail}")
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
