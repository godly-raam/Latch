"""Tests for the mcpprobe CLI: exit codes and output modes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mcpprobe.cli import cli


def tool_payload(name: str = "echo", description: str = "Echo text back.") -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    }


def write_manifest(path: Path, *tools: dict[str, Any]) -> Path:
    path.write_text(json.dumps({"tools": list(tools)}), encoding="utf-8")
    return path


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def locked(tmp_path: Path, runner: CliRunner) -> tuple[Path, Path]:
    """Pin a two-tool manifest and return (manifest path, lockfile path)."""
    manifest_path = write_manifest(
        tmp_path / "manifest.json", tool_payload("alpha"), tool_payload("beta")
    )
    lockfile_path = tmp_path / "mcpprobe.lock.json"
    result = runner.invoke(
        cli,
        [
            "pin",
            "--input",
            str(manifest_path),
            "--server-id",
            "demo-server",
            "--output",
            str(lockfile_path),
        ],
    )
    assert result.exit_code == 0, result.output
    return manifest_path, lockfile_path


def test_pin_writes_lockfile_and_prints_summary(runner: CliRunner, tmp_path: Path) -> None:
    manifest_path = write_manifest(tmp_path / "manifest.json", tool_payload("alpha"))
    lockfile_path = tmp_path / "mcpprobe.lock.json"

    result = runner.invoke(
        cli,
        [
            "pin",
            "--input",
            str(manifest_path),
            "--server-id",
            "demo-server",
            "--output",
            str(lockfile_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "demo-server" in result.output
    assert "1" in result.output
    data = json.loads(lockfile_path.read_text(encoding="utf-8"))
    assert data["manifest_sha256"] in result.output
    assert data["server_id"] == "demo-server"


def test_pin_accepts_jsonrpc_envelope(runner: CliRunner, tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": {"tools": [tool_payload("alpha")], "ttlMs": 5000}}
        ),
        encoding="utf-8",
    )
    lockfile_path = tmp_path / "mcpprobe.lock.json"

    result = runner.invoke(
        cli,
        [
            "pin",
            "--input",
            str(manifest_path),
            "--server-id",
            "enveloped",
            "--output",
            str(lockfile_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(lockfile_path.read_text(encoding="utf-8"))["tools"].keys() == {"alpha"}


def test_verify_identical_manifest_exits_zero(runner: CliRunner, locked: tuple[Path, Path]) -> None:
    manifest_path, lockfile_path = locked

    result = runner.invoke(
        cli, ["verify", "--input", str(manifest_path), "--lockfile", str(lockfile_path)]
    )

    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_verify_reordered_tools_exits_zero(runner: CliRunner, tmp_path: Path, locked: tuple[Path, Path]) -> None:
    _, lockfile_path = locked
    reordered = write_manifest(tmp_path / "reordered.json", tool_payload("beta"), tool_payload("alpha"))

    result = runner.invoke(
        cli, ["verify", "--input", str(reordered), "--lockfile", str(lockfile_path)]
    )

    assert result.exit_code == 0, result.output


def test_verify_drift_exits_one_with_diagnostics(
    runner: CliRunner, tmp_path: Path, locked: tuple[Path, Path]
) -> None:
    _, lockfile_path = locked
    drifted = write_manifest(
        tmp_path / "drifted.json",
        tool_payload("alpha", description="Echo text back!\u200b"),
        tool_payload("gamma"),
    )

    result = runner.invoke(
        cli, ["verify", "--input", str(drifted), "--lockfile", str(lockfile_path)]
    )

    assert result.exit_code == 1, result.output
    assert "MODIFIED_TOOL" in result.output
    assert "ADDED_TOOL" in result.output
    assert "REMOVED_TOOL" in result.output
    assert "alpha" in result.output
    assert "beta" in result.output
    assert "gamma" in result.output


def test_verify_json_mode_reports_drift(
    runner: CliRunner, tmp_path: Path, locked: tuple[Path, Path]
) -> None:
    _, lockfile_path = locked
    drifted = write_manifest(
        tmp_path / "drifted.json", tool_payload("alpha"), tool_payload("gamma")
    )

    result = runner.invoke(
        cli, ["verify", "--input", str(drifted), "--lockfile", str(lockfile_path), "--json"]
    )

    assert result.exit_code == 1, result.output
    report = json.loads(result.output)
    assert report["passed"] is False
    assert report["server_id"] == "demo-server"
    kinds = {(item["kind"], item["tool_name"]) for item in report["drift"]}
    assert kinds == {("ADDED_TOOL", "gamma"), ("REMOVED_TOOL", "beta")}


def test_verify_json_mode_passes(runner: CliRunner, locked: tuple[Path, Path]) -> None:
    manifest_path, lockfile_path = locked

    result = runner.invoke(
        cli, ["verify", "--input", str(manifest_path), "--lockfile", str(lockfile_path), "--json"]
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["passed"] is True
    assert report["drift"] == []
    assert report["expected_manifest_sha256"] == report["actual_manifest_sha256"]


def test_verify_invalid_json_manifest_exits_two(
    runner: CliRunner, tmp_path: Path, locked: tuple[Path, Path]
) -> None:
    _, lockfile_path = locked
    broken = tmp_path / "broken.json"
    broken.write_text('{"tools": [', encoding="utf-8")

    result = runner.invoke(cli, ["verify", "--input", str(broken), "--lockfile", str(lockfile_path)])

    assert result.exit_code == 2, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_verify_malformed_tool_schema_exits_two(
    runner: CliRunner, tmp_path: Path, locked: tuple[Path, Path]
) -> None:
    _, lockfile_path = locked
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"tools": [{"description": "missing name"}]}), encoding="utf-8")

    result = runner.invoke(cli, ["verify", "--input", str(bad), "--lockfile", str(lockfile_path)])

    assert result.exit_code == 2, result.output


def test_verify_non_object_payload_exits_two(
    runner: CliRunner, tmp_path: Path, locked: tuple[Path, Path]
) -> None:
    _, lockfile_path = locked
    bad = tmp_path / "list.json"
    bad.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    result = runner.invoke(cli, ["verify", "--input", str(bad), "--lockfile", str(lockfile_path)])

    assert result.exit_code == 2, result.output


def test_verify_missing_lockfile_exits_two(runner: CliRunner, locked: tuple[Path, Path], tmp_path: Path) -> None:
    manifest_path, _ = locked

    result = runner.invoke(
        cli,
        ["verify", "--input", str(manifest_path), "--lockfile", str(tmp_path / "absent.lock.json")],
    )

    assert result.exit_code == 2, result.output


def test_pin_missing_input_exits_two(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(
        cli,
        [
            "pin",
            "--input",
            str(tmp_path / "absent.json"),
            "--server-id",
            "demo",
            "--output",
            str(tmp_path / "out.json"),
        ],
    )

    assert result.exit_code == 2, result.output


def test_pin_invalid_json_exits_two(runner: CliRunner, tmp_path: Path) -> None:
    manifest_path = tmp_path / "broken.json"
    manifest_path.write_text("nope", encoding="utf-8")

    result = runner.invoke(
        cli,
        [
            "pin",
            "--input",
            str(manifest_path),
            "--server-id",
            "demo",
            "--output",
            str(tmp_path / "out.json"),
        ],
    )

    assert result.exit_code == 2, result.output
    assert not (tmp_path / "out.json").exists()
