"""Command line interface: ``mcpprobe pin|verify|audit`` (alias: ``latch``).

Exit codes:
    0 -- verification (and audit, when requested) passed
    1 -- drift detected, or audit findings at/above ``--fail-on``
    2 -- invalid input: bad JSON, missing files, malformed tool schemas
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from .auditor import AuditReport, audit_manifest
from .lockfile import (
    DriftKind,
    VerificationReport,
    create_lockfile,
    load_lockfile,
    save_lockfile,
    verify_manifest,
)
from .models import SEVERITY_LEVELS, ProbeError

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


@click.group()
@click.version_option(package_name="mcpprobe", prog_name="mcpprobe")
def cli() -> None:
    """Deterministic security verification and schema pinning for MCP servers."""


@cli.command()
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a captured tools/list manifest JSON file.",
)
@click.option("--server-id", required=True, help="Stable identifier for the MCP server.")
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Path of the lockfile to write.",
)
def pin(input_path: Path, server_id: str, output_path: Path) -> None:
    """Pin a tools/list manifest into a cryptographic lockfile."""
    try:
        manifest = _load_object(input_path, "manifest")
        lockfile = create_lockfile(manifest, server_id)
        save_lockfile(lockfile, output_path)
    except (ProbeError, OSError) as exc:
        _fail(str(exc))

    click.echo(f"server id:       {lockfile.server_id}")
    click.echo(f"tools pinned:    {len(lockfile.tools)}")
    click.echo(f"manifest sha256: {lockfile.manifest_sha256}")
    click.echo(f"lockfile:        {output_path}")


@cli.command()
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the tools/list manifest JSON to verify.",
)
@click.option(
    "--lockfile",
    "lockfile_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the pinned lockfile.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON report.")
@click.option(
    "--audit",
    "run_audit",
    is_flag=True,
    help="Also run the static protocol/Unicode audit in the same check.",
)
def verify(input_path: Path, lockfile_path: Path, as_json: bool, run_audit: bool) -> None:
    """Verify a live manifest against a pinned lockfile."""
    try:
        manifest = _load_object(input_path, "manifest")
        lockfile = load_lockfile(lockfile_path)
        report = verify_manifest(manifest, lockfile)
        audit_report = audit_manifest(manifest, fail_on=AUDIT_FAIL_ON_DEFAULT) if run_audit else None
    except ProbeError as exc:
        _fail(str(exc))

    passed = report.passed and (audit_report.passed if audit_report is not None else True)

    if as_json:
        payload = report.model_dump(mode="json")
        if audit_report is not None:
            payload["audit"] = audit_report.model_dump(mode="json")
        click.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
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
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the tools/list manifest JSON to audit.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(list(SEVERITY_LEVELS)),
    default=AUDIT_FAIL_ON_DEFAULT,
    show_default=True,
    help="Minimum severity that fails the audit. Use CRITICAL to ignore HIGH and below.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit a machine-readable JSON report.")
def audit(input_path: Path, fail_on: str, as_json: bool) -> None:
    """Statically audit MCP metadata and protocol hygiene (no server call)."""
    try:
        manifest = _load_object(input_path, "manifest")
        report = audit_manifest(manifest, fail_on=fail_on)
    except ProbeError as exc:
        _fail(str(exc))

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
        _print_audit_report(report, fail_on)

    raise SystemExit(EXIT_OK if report.passed else EXIT_DRIFT)


def _print_human_report(report: VerificationReport) -> None:
    click.echo(f"FAILED: {len(report.drift)} drift item(s) for server '{report.server_id}'")
    click.echo(f"  expected manifest sha256: {report.expected_manifest_sha256}")
    click.echo(f"  actual   manifest sha256: {report.actual_manifest_sha256}")
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
                click.echo(
                    f"      {change.change_type} {change.path} [{change.severity}]"
                )
                click.echo(
                    f"          {_render(change.old_value)} -> {_render(change.new_value)}"
                )
                click.echo(f"          reason: {change.risk_reason}")


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


def main() -> None:
    """Console entrypoint (``mcpprobe`` / ``latch``).

    ``prog_name`` is left to click so the usage line reflects whichever
    console script was invoked.
    """
    cli()


if __name__ == "__main__":  # pragma: no cover
    main()
