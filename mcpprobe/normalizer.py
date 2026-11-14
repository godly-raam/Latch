"""Canonical serialization and hashing of MCP tool definitions.

Canonical form is deterministic JSON: keys sorted, no insignificant
whitespace, non-ASCII text kept literal (UTF-8 encoded). Text is *never*
stripped or Unicode-normalized, so a single-character or invisible-character
edit inside a description changes the digest.

Two independent digests are produced:

* ``hash_tool`` -- per-tool digest, so drift can be attributed to a tool.
* ``hash_manifest`` -- whole-surface digest, order-insensitive across the
  ``tools`` array but sensitive to any added, removed or modified tool.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import ToolDefinition


def canonical_payload(tool: ToolDefinition) -> dict[str, Any]:
    """Return the complete JSON-ready mapping that gets hashed for ``tool``.

    Includes declared fields, explicit ``null``s for absent optional fields, and
    every extra/extension field the server sent.
    """

    return tool.model_dump(mode="json", by_alias=True)


def canonicalize_tool(tool: ToolDefinition) -> str:
    """Serialize ``tool`` to deterministic, dependency-free canonical JSON."""

    return json.dumps(
        canonical_payload(tool),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def hash_tool(tool: ToolDefinition) -> str:
    """Return the lowercase hex SHA-256 of the tool's canonical JSON."""

    return hashlib.sha256(canonicalize_tool(tool).encode("utf-8")).hexdigest()


def manifest_entries(tools: list[ToolDefinition]) -> list[str]:
    """Return sorted ``"<name>:<sha256>"`` entries for the tool surface."""

    return sorted(f"{tool.name}:{hash_tool(tool)}" for tool in tools)


def hash_manifest(tools: list[ToolDefinition]) -> str:
    """Hash the whole tool surface, independent of ``tools`` array order."""

    joined = "\n".join(manifest_entries(tools))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
