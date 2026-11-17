"""Command line interface: ``pin`` / ``verify`` / ``audit`` / ``watch``.

Invoked as either ``mcpprobe`` or ``latch`` (same entrypoint).

Exit codes:
    0 -- verification (and audit, when requested) passed
    1 -- drift detected, audit findings at/above ``--fail-on``, or a rug pull
    2 -- invalid input: bad JSON, missing files, malformed schemas, transport errors
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click

from .auditor import AuditReport, audit_manifest
from .chain_prober import ChainVerificationReport, verify_trifecta_chains
from .config_loader import (
    ServerSpec,
    load_mcp_config,
    parse_server_manifest_arg,
    resolve_server_manifests,
)
from .graph import GraphReport, analyze_capability_graph, render_mermaid
from .lockfile import (
    DriftKind,
    VerificationReport,
    create_lockfile,
    load_lockfile,
    save_lockfile,
    verify_manifest,
)
from .models import SEVERITY_LEVELS, ProbeError
from .oauth_audit import AuthAuditReport, run_auth_audit
from .sarif import LIVE_TARGET_URI, to_sarif
from .shadow import ShadowReport, analyze_shadowing
from .transport import (
    DEFAULT_TIMEOUT,
    HarvestResult,
    harvest_http,
    harvest_stdio,
)
from .watcher import WatchReport, watch_http, watch_stdio

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_INVALID_INPUT = 2

AUDIT_FAIL_ON_DEFAULT = "MEDIUM"


def _fail(message: str) -> None:
    click.echo(f"error: {message}", err=True)
    raise SystemExit(EXIT_INVALID_INPUT)


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProbeError(f"cannot read {label} {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProbeError(f"invalid JSON in {label} {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProbeError(f"invalid {label} {path}: top-level JSON value must be an object")
    return data


def _render(value: Any, limit: int = 160) -> str:
    """Render a JSON value for terminals, with invisible chars escaped."""

    try:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True)
    except TypeError:  # pragma: no cover - defensive
        text = repr(value)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _parse_headers(raw_headers: tuple[str, ...]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in raw_headers:
        name, separator, value = raw.partition(":")
        name = name.strip()
        if not separator or not name:
            raise ProbeError(f'invalid --header {raw!r}: expected "Name: Value"')
        headers[name] = value.strip()
    return headers


def _require_single_target(
    input_path: Path | None, stdio_command: str | None, url: str | None
) -> str:
    provided = [
        flag
        for flag, value in (
            ("--input", input_path),
            ("--stdio", stdio_command),
            ("--url", url),
        )
        if value is not None
    ]
    if len(provided) != 1:
        got = f" (got {', '.join(provided)})" if provided else ""
        raise ProbeError(
            f"provide exactly one of --input, --stdio, or --url{got}"
        )
    return provided[0]


def _require_http_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        raise ProbeError(f"invalid --url {url!r}: expected an http(s) URL")
    return url


def _harvest(
    input_path: Path | None,
    stdio_command: str | None,
    url: str | None,
    headers: tuple[str, ...],
    timeout: float,
) -> HarvestResult | None:
    target = _require_single_target(input_path, stdio_command, url)
    custom_headers = _parse_headers(headers)
    if target == "--input":
        return None
    if target == "--stdio":
        assert stdio_command is not None
        return asyncio.run(harvest_stdio(stdio_command, timeout=timeout))
    assert url is not None
    return asyncio.run(
        harvest_http(
            _require_http_url(url),
            headers=custom_headers or None,
            timeout=timeout,
        )
    )


def _load_manifest(
    input_path: Path | None,
    stdio_command: str | None,
    url: str | None,
    headers: tuple[str, ...],
    timeout: float,
) -> tuple[dict[str, Any], HarvestResult | None]:
    harvest = _harvest(input_path, stdio_command, url, headers, timeout)
    if harvest is not None:
        return harvest.tools_payload, harvest
    assert input_path is not None
    return _load_object(input_path, "manifest"), None


def _echo_harvest(harvest: HarvestResult | None) -> None:
    if harvest is None:
        return
    click.echo(
        f"harvested:       {harvest.transport} (protocol {harvest.protocol_version})"
    )


def _artifact_uri(input_path: Path | None) -> str:
    return str(input_path) if input_path is not None else LIVE_TARGET_URI


def _graph_artifact_uri(
    config_paths: tuple[Path, ...], server_manifests: tuple[str, ...], live: bool
) -> str:
    if live:
        return LIVE_TARGET_URI
    if config_paths:
        return str(config_paths[0])
    for raw in server_manifests:
        _server_id, separator, raw_path = raw.partition("=")
        if separator and raw_path.strip():
            return raw_path.strip()
    return LIVE_TARGET_URI


def _emit_sarif(
    path: Path,
    *,
    verifications: Any = (),
    audits: Any = (),
    graphs: Any = (),
    shadow: Any = None,
    auth: Any = None,
    chain: Any = None,
    artifact_uri: str = LIVE_TARGET_URI,
) -> None:
    payload = to_sarif(
        verifications=verifications,
        audits=audits,
        graphs=graphs,
        shadow=shadow,
        auth=auth,
        chain=chain,
        artifact_uri=artifact_uri,
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        _fail(f"cannot write SARIF report to {path}: {exc}")


def target_options(*, input_help: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Attach the mutually-exclusive live/local target options."""

    def decorator(command: Callable[..., Any]) -> Callable[..., Any]:
        options = [
            click.option(
                "--url",
                "url",
                default=None,
                help="Streamable HTTP MCP endpoint URL.",
            ),
            click.option(
                "--stdio",
                "stdio_command",
                default=None,
                help="Command that starts a local MCP server over stdio.",
            ),
            click.option(
                "--input",
                "input_path",
                type=click.Path(exists=True, dir_okay=False, path_type=Path),
                default=None,
                help=input_help,
            ),
            click.option(
                "--header",
                "headers",
                multiple=True,
                help='HTTP header as "Name: Value". Repeatable.',
            ),
            click.option(
                "--timeout",
                "timeout",
                type=float,
                default=DEFAULT_TIMEOUT,
                show_default=True,
                help="Transport timeout in seconds.",
            ),
        ]
        for option in options:
            command = option(command)
        return command

    return decorator


@click.group()
@click.version_option(package_name="mcpprobe", prog_name="mcpprobe")
def cli() -> None:
    """mcpprobe (Latch) — Deterministic security verifier for Model Context Protocol (MCP) servers."""


@cli.command()
@target_options(input_help="Path to a captured tools/list manifest JSON file.")
@click.option("--server-id", required=True, help="Stable identifier for the MCP server.")
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Path of the lockfile to write.",
)
def pin(
    input_path: Path | None,
    stdio_command: str | None,
    url: str | None,
    headers: tuple[str, ...],
    timeout: float,
    server_id: str,
    output_path: Path,
) -> None:
    """Pin a tools/list manifest (or a live server) into a lockfile."""
    try:
        manifest, harvest = _load_manifest(input_path, stdio_command, url, headers, timeout)
        lockfile = create_lockfile(manifest, server_id)
        save_lockfile(lockfile, output_path)
    except (ProbeError, OSError) as exc:
        _fail(str(exc))

    _echo_harvest(harvest)
    click.echo(f"server id:       {lockfile.server_id}")
    click.echo(f"tools pinned:    {len(lockfile.tools)}")
    click.echo(f"manifest sha256: {lockfile.manifest_sha256}")
    click.echo(f"lockfile:        {output_path}")


@cli.command()
@target_options(input_help="Path to the tools/list manifest JSON to verify.")
@click.option(
    "--lockfile",
    "lockfile_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the pinned lockfile.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON report.")
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a SARIF 2.1.0 report to this path.",
)
@click.option(
    "--audit",
    "run_audit",
    is_flag=True,
    help="Also run the static protocol/Unicode audit in the same check.",
)
def verify(
    input_path: Path | None,
    stdio_command: str | None,
    url: str | None,
    headers: tuple[str, ...],
    timeout: float,
    lockfile_path: Path,
    as_json: bool,
    run_audit: bool,
    sarif_path: Path | None,
) -> None:
    """Verify a manifest or live server against a pinned lockfile."""
    try:
        manifest, harvest = _load_manifest(input_path, stdio_command, url, headers, timeout)
        lockfile = load_lockfile(lockfile_path)
        report = verify_manifest(manifest, lockfile)
        audit_report = audit_manifest(manifest, fail_on=AUDIT_FAIL_ON_DEFAULT) if run_audit else None
    except ProbeError as exc:
        _fail(str(exc))

    passed = report.passed and (audit_report.passed if audit_report is not None else True)

    if sarif_path is not None:
        _emit_sarif(
            sarif_path,
            verifications=[report],
            audits=[audit_report] if audit_report is not None else [],
            artifact_uri=_artifact_uri(input_path),
        )

    if as_json:
        payload = report.model_dump(mode="json")
        if audit_report is not None:
            payload["audit"] = audit_report.model_dump(mode="json")
        click.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _echo_harvest(harvest)
        if report.passed:
            click.echo(
                f"OK: {len(lockfile.tools)} tool(s) match lockfile for server '{report.server_id}'"
            )
            click.echo(f"manifest sha256: {report.actual_manifest_sha256}")
        else:
            _print_human_report(report)
        if audit_report is not None:
            click.echo("")
            _print_audit_report(audit_report, AUDIT_FAIL_ON_DEFAULT)

    raise SystemExit(EXIT_OK if passed else EXIT_DRIFT)


@cli.command()
@target_options(input_help="Path to the tools/list manifest JSON to audit.")
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(list(SEVERITY_LEVELS)),
    default=AUDIT_FAIL_ON_DEFAULT,
    show_default=True,
    help="Minimum severity that fails the audit. Use CRITICAL to ignore HIGH and below.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON report.")
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a SARIF 2.1.0 report to this path.",
)
def audit(
    input_path: Path | None,
    stdio_command: str | None,
    url: str | None,
    headers: tuple[str, ...],
    timeout: float,
    fail_on: str,
    as_json: bool,
    sarif_path: Path | None,
) -> None:
    """Audit MCP metadata and protocol hygiene, statically or from a live server."""
    try:
        manifest, harvest = _load_manifest(input_path, stdio_command, url, headers, timeout)
        report = audit_manifest(manifest, fail_on=fail_on)
    except ProbeError as exc:
        _fail(str(exc))

    if sarif_path is not None:
        _emit_sarif(sarif_path, audits=[report], artifact_uri=_artifact_uri(input_path))

    if as_json:
        click.echo(
            json.dumps(
                report.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    else:
        _echo_harvest(harvest)
        _print_audit_report(report, fail_on)

    raise SystemExit(EXIT_OK if report.passed else EXIT_DRIFT)


@cli.command()
@click.option(
    "--config",
    "config_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="MCP agent config (claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json). Repeatable.",
)
@click.option(
    "--server-manifest",
    "server_manifests",
    multiple=True,
    help="Static snapshot as <server_id>=path.json. Repeatable.",
)
@click.option(
    "--live",
    "live",
    is_flag=True,
    help="Harvest stdio/url servers declared in the config instead of failing.",
)
@click.option(
    "--trust-server",
    "trusted_servers",
    multiple=True,
    help="Server id barred from acting as an untrusted source or egress sink. Repeatable.",
)
@click.option(
    "--check-shadow",
    "check_shadow",
    is_flag=True,
    help="Also detect cross-server tool shadowing and cross-tool hijacking.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "mermaid"]),
    default="text",
    show_default=True,
    help="Report rendering.",
)
@click.option(
    "--warn-only",
    is_flag=True,
    help="Exit 0 even when lethal-trifecta paths or shadow findings are found.",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    show_default=True,
    help="Transport timeout in seconds when harvesting live servers.",
)
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a SARIF 2.1.0 report to this path.",
)
def graph(
    config_paths: tuple[Path, ...],
    server_manifests: tuple[str, ...],
    live: bool,
    trusted_servers: tuple[str, ...],
    check_shadow: bool,
    output_format: str,
    warn_only: bool,
    timeout: float,
    sarif_path: Path | None,
) -> None:
    """Analyze multi-server configs for lethal-trifecta exfiltration chains."""
    if not config_paths and not server_manifests:
        _fail("provide at least one --config or --server-manifest")

    try:
        specs: list[ServerSpec] = []
        for path in config_paths:
            specs.extend(load_mcp_config(path))
        for raw in server_manifests:
            specs.append(parse_server_manifest_arg(raw))
        servers = resolve_server_manifests(specs, live=live, timeout=timeout)
        report = analyze_capability_graph(
            servers, trusted_servers=set(trusted_servers) or None
        )
        shadow_report = (
            analyze_shadowing(servers, trusted_servers=set(trusted_servers) or None)
            if check_shadow
            else None
        )
    except ProbeError as exc:
        _fail(str(exc))

    if sarif_path is not None:
        _emit_sarif(
            sarif_path,
            graphs=[report],
            shadow=shadow_report,
            artifact_uri=_graph_artifact_uri(config_paths, server_manifests, live),
        )

    if output_format == "json":
        payload = report.model_dump(mode="json")
        if shadow_report is not None:
            payload["shadow"] = shadow_report.model_dump(mode="json")
        click.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    elif output_format == "mermaid":
        click.echo(render_mermaid(report), nl=False)
    else:
        _print_graph_report(report)
        if shadow_report is not None:
            click.echo("")
            _print_shadow_report(shadow_report)

    passed = report.passed and (
        shadow_report.passed if shadow_report is not None else True
    )
    raise SystemExit(EXIT_OK if (passed or warn_only) else EXIT_DRIFT)


@cli.command()
@click.option(
    "--config",
    "config_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="MCP agent config (claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json). Repeatable.",
)
@click.option(
    "--server-manifest",
    "server_manifests",
    multiple=True,
    help="Static snapshot as <server_id>=path.json. Repeatable.",
)
@click.option(
    "--live",
    "live",
    is_flag=True,
    help="Harvest stdio/url servers declared in the config instead of failing.",
)
@click.option(
    "--trust-server",
    "trusted_servers",
    multiple=True,
    help="Server id treated as trusted: never a hijack source, and shadowing its tools is CRITICAL. Repeatable.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Report rendering.",
)
@click.option(
    "--warn-only",
    is_flag=True,
    help="Exit 0 even when shadow findings are present.",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    show_default=True,
    help="Transport timeout in seconds when harvesting live servers.",
)
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a SARIF 2.1.0 report to this path.",
)
def shadow(
    config_paths: tuple[Path, ...],
    server_manifests: tuple[str, ...],
    live: bool,
    trusted_servers: tuple[str, ...],
    output_format: str,
    warn_only: bool,
    timeout: float,
    sarif_path: Path | None,
) -> None:
    """Detect cross-server tool shadowing, homoglyph collisions and cross-tool hijacking."""
    if not config_paths and not server_manifests:
        _fail("provide at least one --config or --server-manifest")

    try:
        specs: list[ServerSpec] = []
        for path in config_paths:
            specs.extend(load_mcp_config(path))
        for raw in server_manifests:
            specs.append(parse_server_manifest_arg(raw))
        servers = resolve_server_manifests(specs, live=live, timeout=timeout)
        report = analyze_shadowing(
            servers, trusted_servers=set(trusted_servers) or None
        )
    except ProbeError as exc:
        _fail(str(exc))

    if sarif_path is not None:
        _emit_sarif(
            sarif_path,
            shadow=report,
            artifact_uri=_graph_artifact_uri(config_paths, server_manifests, live),
        )

    if output_format == "json":
        click.echo(
            json.dumps(
                report.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    else:
        _print_shadow_report(report)

    raise SystemExit(EXIT_OK if (report.passed or warn_only) else EXIT_DRIFT)


@cli.command("auth-audit")
@click.option(
    "--config",
    "config_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="MCP agent config (claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json). Repeatable.",
)
@click.option(
    "--server-manifest",
    "server_manifests",
    multiple=True,
    help="Static snapshot as <server_id>=path.json. Repeatable.",
)
@click.option(
    "--live",
    "live",
    is_flag=True,
    help="Probe HTTP servers for RFC 9728 metadata and challenge compliance.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(list(SEVERITY_LEVELS)),
    default=AUDIT_FAIL_ON_DEFAULT,
    show_default=True,
    help="Minimum severity that fails the audit.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Report rendering.",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    show_default=True,
    help="Transport timeout in seconds.",
)
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a SARIF 2.1.0 report to this path.",
)
def auth_audit(
    config_paths: tuple[Path, ...],
    server_manifests: tuple[str, ...],
    live: bool,
    fail_on: str,
    output_format: str,
    timeout: float,
    sarif_path: Path | None,
) -> None:
    """Audit OAuth 2.1 / RFC 9728 authorization hygiene across MCP servers."""
    if not config_paths and not server_manifests:
        _fail("provide at least one --config or --server-manifest")

    try:
        specs: list[ServerSpec] = []
        for path in config_paths:
            specs.extend(load_mcp_config(path))
        for raw in server_manifests:
            specs.append(parse_server_manifest_arg(raw))

        # Static snapshots are always auditable; live transports only when asked,
        # so a config that merely declares `url`/`command` does not fail here.
        resolvable = specs if live else [s for s in specs if s.transport == "static"]
        manifests = resolve_server_manifests(resolvable, live=live, timeout=timeout)
        report = run_auth_audit(
            specs, manifests, live=live, timeout=timeout, fail_on=fail_on
        )
    except ProbeError as exc:
        _fail(str(exc))

    if sarif_path is not None:
        _emit_sarif(
            sarif_path,
            auth=report,
            artifact_uri=_graph_artifact_uri(config_paths, server_manifests, live),
        )

    if output_format == "json":
        click.echo(
            json.dumps(
                report.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    else:
        _print_auth_report(report, fail_on)

    raise SystemExit(EXIT_OK if report.passed else EXIT_DRIFT)


@cli.command("probe-chain")
@click.option(
    "--config",
    "config_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="MCP agent config with live stdio/url servers. Repeatable.",
)
@click.option(
    "--server-manifest",
    "server_manifests",
    multiple=True,
    help="Static snapshot as <server_id>=path.json (not executable on its own). Repeatable.",
)
@click.option(
    "--trust-server",
    "trusted_servers",
    multiple=True,
    help="Server id barred from acting as an untrusted source or egress sink. Repeatable.",
)
@click.option(
    "--no-seed-canary",
    "no_seed_canary",
    is_flag=True,
    help="Do not append the canary to read output before invoking egress.",
)
@click.option(
    "--i-understand-this-executes-tools",
    "acknowledge_execution",
    is_flag=True,
    help=(
        "Required for a live run: confirms you consent to live tools/call"
        " invocations."
    ),
)
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    help="Synthesize the read/egress arguments without calling any tool.",
)
@click.option(
    "--allow-tool",
    "allow_tools",
    multiple=True,
    help="Scope execution to <server:tool> or <server>:*. Repeatable.",
)
@click.option(
    "--allow-all-tools",
    "allow_all_tools",
    is_flag=True,
    help="Explicitly allow every tool named by a static chain.",
)
@click.option(
    "--sink-url",
    "sink_url",
    default=None,
    help=(
        "Send egress to this operator-controlled base URL instead of the"
        " loopback canary sink."
    ),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Report rendering.",
)
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a SARIF 2.1.0 report to this path.",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    show_default=True,
    help="Transport timeout in seconds.",
)
def probe_chain(
    config_paths: tuple[Path, ...],
    server_manifests: tuple[str, ...],
    trusted_servers: tuple[str, ...],
    no_seed_canary: bool,
    acknowledge_execution: bool,
    dry_run: bool,
    allow_tools: tuple[str, ...],
    allow_all_tools: bool,
    sink_url: str | None,
    output_format: str,
    sarif_path: Path | None,
    timeout: float,
) -> None:
    """Execute static lethal-trifecta paths against live servers with a canary."""
    if not config_paths and not server_manifests:
        _fail("provide at least one --config or --server-manifest")

    try:
        specs: list[ServerSpec] = []
        for path in config_paths:
            specs.extend(load_mcp_config(path))
        for raw in server_manifests:
            specs.append(parse_server_manifest_arg(raw))

        live_specs = [spec for spec in specs if spec.transport in ("stdio", "http")]
        if not live_specs:
            _fail(
                "probe-chain requires live stdio or http servers, but every supplied"
                " server is a static snapshot and cannot be executed. Point --config at"
                " entries with 'command' or 'url', or capture a live server with"
                " 'latch pin --stdio/--url' first."
            )

        if sink_url is not None and not sink_url.startswith(("http://", "https://")):
            _fail("--sink-url must be an http:// or https:// base URL")

        # Two independent safety gates: consent to execution, and a scope for
        # which tools may be called. Neither applies to --dry-run.
        if not dry_run:
            if not acknowledge_execution:
                _fail(
                    "probe-chain invokes live tools/call endpoints on the servers you"
                    " named, which can change state or send data. Re-run with"
                    " --i-understand-this-executes-tools once you consent, or use"
                    " --dry-run to inspect the exact read/egress arguments without"
                    " executing anything."
                )
            if not allow_tools and not allow_all_tools:
                _fail(
                    "probe-chain will invoke tools; scope it with --allow-tool"
                    " <server:tool> (or <server>:*) or pass --allow-all-tools."
                )

        report = asyncio.run(
            verify_trifecta_chains(
                live_specs,
                trusted_servers=set(trusted_servers) or None,
                seed_canary=not no_seed_canary,
                timeout=timeout,
                sink_url=sink_url,
                allowed_tools=(
                    None if allow_all_tools or not allow_tools else set(allow_tools)
                ),
                dry_run=dry_run,
            )
        )
    except ProbeError as exc:
        _fail(str(exc))

    if sarif_path is not None:
        _emit_sarif(
            sarif_path,
            chain=report,
            artifact_uri=_graph_artifact_uri(config_paths, server_manifests, False),
        )

    if output_format == "json":
        click.echo(
            json.dumps(
                report.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    else:
        _print_chain_report(report)

    raise SystemExit(EXIT_DRIFT if not report.passed else EXIT_OK)


@cli.command()
@click.option(
    "--stdio", "stdio_command", default=None, help="Command that starts a local MCP server."
)
@click.option("--url", "url", default=None, help="Streamable HTTP MCP endpoint URL.")
@click.option(
    "--lockfile",
    "lockfile_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Pin to compare every snapshot against. An in-memory baseline is used otherwise.",
)
@click.option(
    "--duration",
    type=float,
    default=15.0,
    show_default=True,
    help="Seconds to listen for notifications/tools/list_changed.",
)
@click.option(
    "--max-events",
    type=int,
    default=1,
    show_default=True,
    help="Stop after this many change notifications.",
)
@click.option(
    "--audit",
    "run_audit",
    is_flag=True,
    help="Also run the static protocol/Unicode audit on every snapshot.",
)
@click.option(
    "--header", "headers", multiple=True, help='HTTP header as "Name: Value". Repeatable.'
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    show_default=True,
    help="Transport timeout in seconds.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON report.")
@click.option(
    "--sarif",
    "sarif_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a SARIF 2.1.0 report to this path.",
)
def watch(
    stdio_command: str | None,
    url: str | None,
    lockfile_path: Path | None,
    duration: float,
    max_events: int,
    run_audit: bool,
    headers: tuple[str, ...],
    timeout: float,
    as_json: bool,
    sarif_path: Path | None,
) -> None:
    """Watch a live MCP server for mid-session tool mutations."""
    try:
        _require_single_target(None, stdio_command, url)
        custom_headers = _parse_headers(headers)
        lockfile = load_lockfile(lockfile_path) if lockfile_path is not None else None
        server_id = lockfile.server_id if lockfile is not None else None

        if stdio_command is not None:
            report = asyncio.run(
                watch_stdio(
                    stdio_command,
                    server_id=server_id,
                    lockfile=lockfile,
                    duration=duration,
                    max_events=max_events,
                    run_audit=run_audit,
                    timeout=timeout,
                )
            )
        else:
            assert url is not None
            report = asyncio.run(
                watch_http(
                    _require_http_url(url),
                    server_id=server_id,
                    headers=custom_headers or None,
                    lockfile=lockfile,
                    duration=duration,
                    max_events=max_events,
                    run_audit=run_audit,
                    timeout=timeout,
                )
            )
    except ProbeError as exc:
        _fail(str(exc))

    if sarif_path is not None:
        _emit_sarif(
            sarif_path,
            verifications=[event.verification for event in report.events],
            audits=[event.audit for event in report.events if event.audit is not None],
        )

    if as_json:
        click.echo(
            json.dumps(
                report.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    else:
        _print_watch_report(report)

    audit_failed = any(
        event.audit is not None and not event.audit.passed for event in report.events
    )
    raise SystemExit(EXIT_DRIFT if (report.rug_pull_detected or audit_failed) else EXIT_OK)


def _print_drift_items(report: VerificationReport) -> None:
    for item in report.drift:
        if item.kind is DriftKind.ADDED_TOOL:
            click.echo(
                f"  + ADDED_TOOL    {item.tool_name} [{item.severity}]"
                f" (sha256 {item.actual_sha256})"
            )
        elif item.kind is DriftKind.REMOVED_TOOL:
            click.echo(
                f"  - REMOVED_TOOL  {item.tool_name} [{item.severity}]"
                f" (sha256 {item.expected_sha256})"
            )
        else:
            click.echo(f"  ~ MODIFIED_TOOL {item.tool_name} [{item.severity}]")
            click.echo(f"      expected sha256 {item.expected_sha256}")
            click.echo(f"      actual   sha256 {item.actual_sha256}")
            for change in item.changes:
                click.echo(f"      {change.change_type} {change.path} [{change.severity}]")
                click.echo(
                    f"          {_render(change.old_value)} -> {_render(change.new_value)}"
                )
                click.echo(f"          reason: {change.risk_reason}")


def _print_human_report(report: VerificationReport) -> None:
    click.echo(f"FAILED: {len(report.drift)} drift item(s) for server '{report.server_id}'")
    click.echo(f"  expected manifest sha256: {report.expected_manifest_sha256}")
    click.echo(f"  actual   manifest sha256: {report.actual_manifest_sha256}")
    _print_drift_items(report)


def _print_audit_report(report: AuditReport, fail_on: str) -> None:
    if report.passed:
        click.echo(
            f"AUDIT PASSED: {len(report.findings)} finding(s) below {fail_on}"
            f" across {report.tool_count} tool(s)"
        )
    else:
        click.echo(
            f"AUDIT FAILED: {len(report.findings)} finding(s) across"
            f" {report.tool_count} tool(s) (fail-on: {fail_on})"
        )
    for finding in report.findings:
        click.echo(
            f"  [{finding.severity}] {finding.rule_id}"
            f" {finding.tool_name}.{finding.field_path}"
        )
        click.echo(f"      {finding.message}")
        if finding.evidence is not None:
            click.echo(f"      evidence: {finding.evidence}")


def _print_graph_report(report: GraphReport) -> None:
    click.echo("Latch capability graph")
    click.echo(
        f"  servers: {report.server_count}   tools: {report.tool_count}"
        f"   lethal trifecta paths: {len(report.trifecta_paths)}"
    )
    if report.trusted_servers_excluded:
        click.echo(
            "  trusted servers barred as sources/sinks:"
            f" {', '.join(report.trusted_servers_excluded)}"
        )
    if report.local_write_tools:
        click.echo(
            "  local-write tools (never an exfil sink):"
            f" {', '.join(report.local_write_tools)}"
        )

    click.echo("")
    for node in report.nodes:
        label = ", ".join(node.capabilities) if node.capabilities else "no capability"
        click.echo(f"  {node.qualified_name}  [{label}]")
        for evidence in node.evidence:
            click.echo(
                f"      - {evidence.tag}: {evidence.detail}"
                f" (signal {evidence.signal}, weight {evidence.weight:g})"
            )

    click.echo("")
    if report.trifecta_paths:
        click.echo(f"Lethal Trifecta paths ({len(report.trifecta_paths)}):")
        for index, path in enumerate(report.trifecta_paths, start=1):
            scope = "cross-server" if path.cross_server else "single-server"
            click.echo(
                f"  {index}. [{path.severity}] {scope} ({', '.join(path.servers)})"
                f"  {path.path_id}"
            )
            collapsed = (
                f" (+{path.collapsed_read_count - 1} more read tools)"
                if path.collapsed_read_count > 1
                else ""
            )
            click.echo(
                f"     {path.ingest_tool} -> {path.read_tool} -> {path.egress_tool}"
                f"{collapsed}"
            )
            click.echo(f"     {path.attack_narrative}")
        click.echo("")
        click.echo(
            f"RESULT: {len(report.trifecta_paths)} Lethal Trifecta path(s) detected"
        )
    else:
        click.echo("RESULT: no Lethal Trifecta path detected")


def _print_shadow_report(report: ShadowReport) -> None:
    click.echo("Latch cross-server shadow analysis")
    click.echo(
        f"  servers: {report.server_count}   tools: {report.tool_count}"
        f"   findings: {len(report.findings)}"
    )
    if report.trusted_servers_excluded:
        click.echo(
            "  trusted servers:"
            f" {', '.join(report.trusted_servers_excluded)}"
        )

    for finding in report.findings:
        click.echo("")
        click.echo(
            f"  [{finding.severity}] {finding.rule_id}  {finding.canonical_key}"
        )
        click.echo(f"      {finding.message}")
        click.echo(
            f"      servers: {', '.join(finding.servers)}"
            f"   tools: {', '.join(finding.involved_tools)}"
        )
        if finding.evidence is not None:
            click.echo(f"      evidence: {finding.evidence}")

    click.echo("")
    if report.passed:
        click.echo("RESULT: no tool shadowing or cross-tool hijack detected")
    else:
        click.echo(f"RESULT: {len(report.findings)} shadowing finding(s) detected")


def _print_auth_report(report: AuthAuditReport, fail_on: str) -> None:
    click.echo("Latch authorization audit")
    click.echo(
        f"  servers: {report.server_count}"
        f"   live probed: {len(report.live_probed_servers)}"
        f"   findings: {len(report.findings)}"
    )
    if report.live_probed_servers:
        click.echo(f"  live servers: {', '.join(report.live_probed_servers)}")

    for finding in report.findings:
        click.echo("")
        click.echo(f"  [{finding.severity}] {finding.rule_id}  {finding.field_path}")
        click.echo(f"      servers: {', '.join(finding.servers)}")
        click.echo(f"      {finding.message}")
        if finding.evidence is not None:
            click.echo(f"      evidence: {finding.evidence}")

    click.echo("")
    if report.passed:
        click.echo(f"AUTH AUDIT PASSED: no findings at or above {fail_on}")
    else:
        click.echo(
            f"AUTH AUDIT FAILED: {len(report.findings)} finding(s)"
            f" (fail-on: {fail_on})"
        )


def _print_chain_report(report: ChainVerificationReport) -> None:
    click.echo("Latch execution-aware chain verification")
    click.echo(
        f"  servers: {report.server_count}"
        f"   static paths: {report.static_paths_found}"
        f"   tested: {report.paths_tested}"
    )
    click.echo(
        f"  confirmed: {report.confirmed_exploitable}"
        f"   blocked: {report.blocked_count}"
        f"   unconfirmed-ssrf: {report.unconfirmed_ssrf_count}"
        f"   inconclusive: {report.inconclusive_count}"
    )
    if report.skipped_not_allowlisted_count or report.dry_run_count:
        click.echo(
            f"  skipped-not-allowlisted: {report.skipped_not_allowlisted_count}"
            f"   dry-run: {report.dry_run_count}"
        )

    for result in report.results:
        click.echo("")
        click.echo(f"  [{result.status}] {result.path_id}")
        click.echo(
            f"      static severity: {result.static_severity}"
            f"   verified severity: {result.verified_severity}"
        )
        click.echo(
            f"      {result.ingest_tool} -> {result.read_tool} -> {result.egress_tool}"
        )
        if result.canary_token:
            click.echo(f"      canary: {result.canary_token}")
        click.echo(
            f"      read observed: {result.read_observed}"
            f"   egress invoked: {result.egress_invoked}"
        )
        if result.status in ("DRY_RUN_SKIPPED", "SKIPPED_NOT_ALLOWLISTED"):
            click.echo(
                "      read args: "
                + json.dumps(result.read_args or {}, sort_keys=True)
            )
            click.echo(
                "      egress args: "
                + json.dumps(result.egress_args or {}, sort_keys=True)
            )
        if result.sink_request_summary is not None:
            click.echo(f"      sink: {result.sink_request_summary}")
        if result.block_reason is not None:
            click.echo(f"      block: {result.block_reason}")

    click.echo("")
    if report.passed:
        click.echo("RESULT: no static chain could be reproduced at runtime")
    elif report.confirmed_exploitable:
        click.echo(
            f"RESULT: {report.confirmed_exploitable} confirmed exploitable chain(s)"
        )
    else:
        click.echo(
            f"RESULT: {report.unconfirmed_ssrf_count} chain(s) could not be verified"
            " (SSRF guard or unreadable operator sink); they are not proven safe"
        )


def _print_watch_report(report: WatchReport) -> None:
    click.echo(
        f"watching '{report.server_id}' over {report.transport}"
        f" (protocol {report.protocol_version})"
    )
    for event in report.events:
        if event.verification.passed:
            click.echo(
                f"[event {event.sequence}] {event.trigger} at {event.timestamp}: no drift"
            )
        else:
            click.echo(
                f"[event {event.sequence}] {event.trigger} at {event.timestamp}:"
                f" {len(event.verification.drift)} drift item(s)"
            )
            _print_drift_items(event.verification)
        if event.audit is not None:
            _print_audit_report(event.audit, AUDIT_FAIL_ON_DEFAULT)

    if report.rug_pull_detected:
        click.echo("RESULT: RUG PULL DETECTED - the live tool surface diverged from the pin")
    else:
        click.echo("RESULT: no mid-session tool mutation detected")


def main() -> None:
    """Console entrypoint (``mcpprobe`` / ``latch``).

    ``prog_name`` is left to click so the usage line reflects whichever
    console script was invoked.
    """
    cli()


if __name__ == "__main__":  # pragma: no cover
    main()
