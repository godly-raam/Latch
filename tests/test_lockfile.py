"""Tests for the lockfile engine and drift verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcpprobe.lockfile import (
    DriftKind,
    LockfileError,
    create_lockfile,
    load_lockfile,
    save_lockfile,
    verify_manifest,
)
from mcpprobe.models import Lockfile, ManifestError, ToolDefinition
from mcpprobe.normalizer import hash_manifest, hash_tool


def tool_payload(name: str = "echo", description: str = "Echo text back.") -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "punctuation": {"type": "boolean"},
            },
            "required": ["text"],
        },
    }


def manifest(*tools: dict[str, Any]) -> dict[str, Any]:
    return {"tools": list(tools)}


def envelope(*tools: dict[str, Any], ttl_ms: int = 60_000) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"tools": list(tools), "ttlMs": ttl_ms, "cacheScope": "session"},
    }


def test_create_lockfile_from_raw_manifest() -> None:
    lockfile = create_lockfile(manifest(tool_payload()), "demo-server")

    assert isinstance(lockfile, Lockfile)
    assert lockfile.schema_version == "1.0"
    assert lockfile.server_id == "demo-server"
    assert list(lockfile.tools) == ["echo"]

    entry = lockfile.tools["echo"]
    expected_tool = ToolDefinition.model_validate(tool_payload())
    assert entry.name == "echo"
    assert entry.sha256 == hash_tool(expected_tool)
    assert entry.parameter_names == ["punctuation", "text"]
    assert entry.has_output_schema is False


def test_raw_manifest_and_envelope_produce_identical_pins() -> None:
    raw = create_lockfile(manifest(tool_payload()), "demo")
    enveloped = create_lockfile(envelope(tool_payload()), "demo")

    assert raw.manifest_sha256 == enveloped.manifest_sha256
    assert raw.tools == enveloped.tools


def test_envelope_cache_metadata_does_not_affect_pin() -> None:
    short_ttl = create_lockfile(envelope(tool_payload(), ttl_ms=1_000), "demo")
    long_ttl = create_lockfile(envelope(tool_payload(), ttl_ms=600_000), "demo")

    assert short_ttl.manifest_sha256 == long_ttl.manifest_sha256


def test_has_output_schema_reflects_manifest() -> None:
    payload = tool_payload("structured")
    payload["outputSchema"] = {"type": "object"}

    lockfile = create_lockfile(manifest(payload), "demo")

    assert lockfile.tools["structured"].has_output_schema is True


def test_manifest_sha256_matches_normalizer() -> None:
    payloads = [tool_payload("alpha"), tool_payload("beta")]
    lockfile = create_lockfile(manifest(*payloads), "demo")
    tools = [ToolDefinition.model_validate(payload) for payload in payloads]

    assert lockfile.manifest_sha256 == hash_manifest(tools)


def test_tool_order_in_manifest_does_not_change_pin() -> None:
    forward = create_lockfile(manifest(tool_payload("alpha"), tool_payload("beta")), "demo")
    reverse = create_lockfile(manifest(tool_payload("beta"), tool_payload("alpha")), "demo")

    assert forward.manifest_sha256 == reverse.manifest_sha256


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    lockfile = create_lockfile(manifest(tool_payload()), "demo")
    path = tmp_path / "mcpprobe.lock.json"

    save_lockfile(lockfile, path)

    assert path.exists()
    assert path.read_text(encoding="utf-8").endswith("\n")
    assert load_lockfile(path) == lockfile


def test_saved_lockfile_is_sorted_json(tmp_path: Path) -> None:
    path = tmp_path / "mcpprobe.lock.json"
    save_lockfile(create_lockfile(manifest(tool_payload("beta"), tool_payload("alpha")), "demo"), path)

    data = json.loads(path.read_text(encoding="utf-8"))

    assert list(data) == sorted(data)
    assert list(data["tools"]) == ["alpha", "beta"]


def test_load_lockfile_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(LockfileError):
        load_lockfile(path)


def test_load_lockfile_rejects_malformed_shape(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"server_id": "demo"}), encoding="utf-8")

    with pytest.raises(LockfileError):
        load_lockfile(path)


def test_load_lockfile_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(LockfileError):
        load_lockfile(tmp_path / "nope.json")


def test_create_lockfile_rejects_malformed_manifest() -> None:
    with pytest.raises(ManifestError):
        create_lockfile({"tools": "not-a-list"}, "demo")


def test_verify_passes_for_identical_manifest_in_any_order() -> None:
    lockfile = create_lockfile(manifest(tool_payload("alpha"), tool_payload("beta")), "demo")

    report = verify_manifest(manifest(tool_payload("beta"), tool_payload("alpha")), lockfile)

    assert report.passed is True
    assert report.drift == []
    assert report.expected_manifest_sha256 == report.actual_manifest_sha256
    assert report.server_id == "demo"


def test_verify_detects_added_tool() -> None:
    lockfile = create_lockfile(manifest(tool_payload("alpha")), "demo")
    new_tool = tool_payload("gamma")
    report = verify_manifest(manifest(tool_payload("alpha"), new_tool), lockfile)

    assert report.passed is False
    assert len(report.drift) == 1
    item = report.drift[0]
    assert item.kind is DriftKind.ADDED_TOOL
    assert item.tool_name == "gamma"
    assert item.actual_sha256 == hash_tool(ToolDefinition.model_validate(new_tool))
    assert item.expected_sha256 is None


def test_verify_detects_removed_tool() -> None:
    lockfile = create_lockfile(manifest(tool_payload("alpha"), tool_payload("beta")), "demo")
    report = verify_manifest(manifest(tool_payload("alpha")), lockfile)

    assert report.passed is False
    assert len(report.drift) == 1
    item = report.drift[0]
    assert item.kind is DriftKind.REMOVED_TOOL
    assert item.tool_name == "beta"
    assert item.expected_sha256 == lockfile.tools["beta"].sha256
    assert item.actual_sha256 is None


def test_verify_detects_modified_tool_with_both_digests() -> None:
    lockfile = create_lockfile(manifest(tool_payload("alpha")), "demo")
    edited = tool_payload("alpha", description="Echo text back!\u200b")
    report = verify_manifest(manifest(edited), lockfile)

    assert report.passed is False
    assert len(report.drift) == 1
    item = report.drift[0]
    assert item.kind is DriftKind.MODIFIED_TOOL
    assert item.tool_name == "alpha"
    assert item.expected_sha256 == lockfile.tools["alpha"].sha256
    assert item.actual_sha256 == hash_tool(ToolDefinition.model_validate(edited))
    assert item.expected_sha256 != item.actual_sha256


def test_verify_detects_mixed_drift_and_sorts_items() -> None:
    lockfile = create_lockfile(
        manifest(tool_payload("alpha"), tool_payload("beta"), tool_payload("delta")), "demo"
    )
    current = manifest(
        tool_payload("alpha", description="Echo text back."),
        tool_payload("beta", description="Changed!"),
        tool_payload("gamma"),
    )

    report = verify_manifest(current, lockfile)

    assert report.passed is False
    assert [(item.tool_name, item.kind) for item in report.drift] == [
        ("beta", DriftKind.MODIFIED_TOOL),
        ("delta", DriftKind.REMOVED_TOOL),
        ("gamma", DriftKind.ADDED_TOOL),
    ]
    assert report.expected_manifest_sha256 == lockfile.manifest_sha256
    assert report.actual_manifest_sha256 == hash_manifest(
        [ToolDefinition.model_validate(payload) for payload in current["tools"]]
    )


def test_verify_detects_schema_key_reordering_as_no_drift() -> None:
    lockfile = create_lockfile(manifest(tool_payload("alpha")), "demo")
    reordered = {
        "tools": [
            {
                "inputSchema": {
                    "required": ["text"],
                    "properties": {
                        "punctuation": {"type": "boolean"},
                        "text": {"type": "string"},
                    },
                    "type": "object",
                },
                "description": "Echo text back.",
                "name": "alpha",
            }
        ]
    }

    report = verify_manifest(reordered, lockfile)

    assert report.passed is True
    assert report.drift == []


def test_verify_rejects_malformed_manifest() -> None:
    lockfile = create_lockfile(manifest(tool_payload()), "demo")

    with pytest.raises(ManifestError):
        verify_manifest({"result": {"tools": [{"description": "no name"}]}}, lockfile)
