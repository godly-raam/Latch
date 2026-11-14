"""Command line interface: ``mcpprobe pin`` and ``mcpprobe verify``.

Exit codes:
    0 -- verification passed
    1 -- drift detected (ADDED_TOOL / REMOVED_TOOL / MODIFIED_TOOL)
    2 -- invalid input: bad JSON, missing files, malformed tool schemas
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from .lockfile import (
    DriftKind,
    create_lockfile,
    load_lockfile,
    save_lockfile,
    verify_manifest,
)
from .models import ProbeError

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_INVALID_INPUT = 2


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
def verify(input_path: Path, lockfile_path: Path, as_json: bool) -> None:
    """Verify a live manifest against a pinned lockfile."""
    try:
        manifest = _load_object(input_path, "manifest")
        lockfile = load_lockfile(lockfile_path)
        report = verify_manifest(manifest, lockfile)
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
    elif report.passed:
        click.echo(f"OK: {len(lockfile.tools)} tool(s) match lockfile for server '{report.server_id}'")
        click.echo(f"manifest sha256: {report.actual_manifest_sha256}")
    else:
        _print_human_report(report)

    raise SystemExit(EXIT_OK if report.passed else EXIT_DRIFT)


def _print_human_report(report: Any) -> None:
    click.echo(f"FAILED: {len(report.drift)} drift item(s) for server '{report.server_id}'")
    click.echo(f"  expected manifest sha256: {report.expected_manifest_sha256}")
    click.echo(f"  actual   manifest sha256: {report.actual_manifest_sha256}")
    for item in report.drift:
        if item.kind is DriftKind.ADDED_TOOL:
            click.echo(f"  + ADDED_TOOL    {item.tool_name} (sha256 {item.actual_sha256})")
        elif item.kind is DriftKind.REMOVED_TOOL:
            click.echo(f"  - REMOVED_TOOL  {item.tool_name} (sha256 {item.expected_sha256})")
        else:
            click.echo(f"  ~ MODIFIED_TOOL {item.tool_name}")
            click.echo(f"      expected sha256 {item.expected_sha256}")
            click.echo(f"      actual   sha256 {item.actual_sha256}")


def main() -> None:
    """Console entrypoint (``mcpprobe``)."""
    cli(prog_name="mcpprobe")


if __name__ == "__main__":  # pragma: no cover
    main()
