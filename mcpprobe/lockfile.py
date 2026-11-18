"""Lockfile creation, persistence and drift verification."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from .auditor import audit_tool
from .diff import FieldChange, diff_tool_definitions
from .models import (
    Lockfile,
    PinnedToolEntry,
    ProbeError,
    Severity,
    ToolDefinition,
    parse_tools_payload,
)
from .normalizer import (
    canonicalize_tool,
    hash_manifest,
    hash_manifest_entries,
    hash_tool,
)

LOCKFILE_SCHEMA_VERSION = "1.0"


class LockfileError(ProbeError):
    """Raised when a lockfile cannot be read, parsed or validated."""


class DriftKind(str, Enum):
    """Categories of structural drift between a manifest and a lockfile."""

    ADDED_TOOL = "ADDED_TOOL"
    REMOVED_TOOL = "REMOVED_TOOL"
    MODIFIED_TOOL = "MODIFIED_TOOL"


class DriftItem(BaseModel):
    """One categorized difference between manifest and lockfile."""

    kind: DriftKind
    tool_name: str
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    severity: Severity = "MEDIUM"
    changes: list[FieldChange] = Field(default_factory=list)


class VerificationReport(BaseModel):
    """Outcome of comparing a live manifest against a lockfile."""

    passed: bool
    server_id: str
    schema_version: str
    expected_manifest_sha256: str
    actual_manifest_sha256: str
    drift: list[DriftItem] = Field(default_factory=list)


def parameter_names(tool: ToolDefinition) -> list[str]:
    """Return the sorted top-level parameter names declared by a tool."""

    properties = tool.inputSchema.get("properties")
    if not isinstance(properties, dict):
        return []
    return sorted(str(name) for name in properties)


def _pinned_entry(tool: ToolDefinition) -> PinnedToolEntry:
    return PinnedToolEntry(
        name=tool.name,
        sha256=hash_tool(tool),
        canonical_json=canonicalize_tool(tool),
        parameter_names=parameter_names(tool),
        has_output_schema=tool.outputSchema is not None,
    )


def create_lockfile(manifest_data: dict[str, Any], server_id: str) -> Lockfile:
    """Pin every tool in ``manifest_data`` into a new ``Lockfile``."""

    tools = parse_tools_payload(manifest_data)
    return Lockfile(
        schema_version=LOCKFILE_SCHEMA_VERSION,
        server_id=server_id,
        manifest_sha256=hash_manifest(tools),
        tools={tool.name: _pinned_entry(tool) for tool in tools},
    )


def save_lockfile(lockfile: Lockfile, path: Path) -> None:
    """Write ``lockfile`` as stable, diff-friendly JSON."""

    path = Path(path)
    payload = lockfile.model_dump(mode="json", by_alias=True)
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:  # pragma: no cover - defensive
        raise LockfileError(f"cannot write lockfile {path}: {exc}") from exc


def load_lockfile(path: Path) -> Lockfile:
    """Read and validate a lockfile from disk."""

    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LockfileError(f"cannot read lockfile {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LockfileError(f"invalid JSON in lockfile {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LockfileError(f"invalid lockfile {path}: top-level JSON value must be an object")
    try:
        return Lockfile.model_validate(data)
    except ValidationError as exc:
        raise LockfileError(f"invalid lockfile {path}: {exc}") from exc


def _added_tool_severity(tool: ToolDefinition) -> Severity:
    """A newly exposed tool is HIGH, or CRITICAL if it already audits critical."""

    if any(finding.severity == "CRITICAL" for finding in audit_tool(tool)):
        return "CRITICAL"
    return "HIGH"


def verify_manifest(manifest_data: dict[str, Any], lockfile: Lockfile) -> VerificationReport:
    """Compare a live manifest against a lockfile and categorize drift."""

    tools = parse_tools_payload(manifest_data)
    by_name = {tool.name: tool for tool in tools}
    actual = {tool.name: hash_tool(tool) for tool in tools}
    expected = lockfile.tools

    drift: list[DriftItem] = []
    for name, actual_sha in actual.items():
        pinned = expected.get(name)
        if pinned is None:
            drift.append(
                DriftItem(
                    kind=DriftKind.ADDED_TOOL,
                    tool_name=name,
                    actual_sha256=actual_sha,
                    severity=_added_tool_severity(by_name[name]),
                )
            )
        elif pinned.sha256 != actual_sha:
            changes, severity = diff_tool_definitions(pinned.canonical_json, by_name[name])
            drift.append(
                DriftItem(
                    kind=DriftKind.MODIFIED_TOOL,
                    tool_name=name,
                    expected_sha256=pinned.sha256,
                    actual_sha256=actual_sha,
                    severity=severity,
                    changes=changes,
                )
            )

    for name, pinned in expected.items():
        if name not in actual:
            drift.append(
                DriftItem(
                    kind=DriftKind.REMOVED_TOOL,
                    tool_name=name,
                    expected_sha256=pinned.sha256,
                    severity="LOW",
                )
            )

    drift.sort(key=lambda item: (item.tool_name, item.kind.value))

    return VerificationReport(
        passed=not drift,
        server_id=lockfile.server_id,
        schema_version=lockfile.schema_version,
        expected_manifest_sha256=lockfile.manifest_sha256,
        # Reuse the per-tool digests instead of canonicalizing and hashing every
        # tool a second time.
        actual_manifest_sha256=hash_manifest_entries(
            f"{name}:{sha}" for name, sha in actual.items()
        ),
        drift=drift,
    )
