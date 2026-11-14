"""Data models for MCP ``tools/list`` payloads and MCPProbe lockfiles.

The models mirror the MCP wire format exactly. Field names are kept in their
camelCase MCP spelling (``inputSchema``, ``outputSchema``) so that a model dump
is byte-for-byte comparable with the manifest a server actually returned.

Unknown / extension fields are retained (``extra="allow"``). A security tool
must hash everything it was given: silently dropping a vendor extension field
would let a server change semantics without breaking a pin.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

DEFAULT_INPUT_SCHEMA: dict[str, Any] = {"type": "object"}


class ProbeError(ValueError):
    """Base class for every error surfaced as a CLI exit code 2."""


class ManifestError(ProbeError):
    """Raised when a payload is not a usable MCP ``tools/list`` response."""


class ToolDefinition(BaseModel):
    """A single entry of the MCP ``tools/list`` ``tools`` array."""

    model_config = ConfigDict(extra="allow")

    name: str
    title: str | None = None
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=lambda: dict(DEFAULT_INPUT_SCHEMA))
    outputSchema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None


class ToolListResult(BaseModel):
    """The JSON-RPC ``result`` object of a ``tools/list`` response."""

    model_config = ConfigDict(extra="allow")

    tools: list[ToolDefinition]
    ttlMs: int | None = None
    cacheScope: str | None = None


class PinnedToolEntry(BaseModel):
    """The pinned digest of one tool, as stored in a lockfile."""

    name: str
    sha256: str
    canonical_json: str
    parameter_names: list[str]
    has_output_schema: bool


class Lockfile(BaseModel):
    """A committed, reviewable pin of an MCP server's tool surface."""

    schema_version: str = "1.0"
    server_id: str
    manifest_sha256: str
    tools: dict[str, PinnedToolEntry]


def parse_tools_payload(data: Any) -> list[ToolDefinition]:
    """Extract tool definitions from a raw or JSON-RPC-enveloped payload.

    Accepts both shapes:

    * ``{"tools": [...]}``
    * ``{"jsonrpc": "2.0", "id": 1, "result": {"tools": [...], "ttlMs": ...}}``

    Raises:
        ManifestError: if the payload is not a usable ``tools/list`` response.
    """

    if not isinstance(data, dict):
        raise ManifestError("MCP manifest must be a JSON object")

    if "tools" in data:
        raw_tools = data["tools"]
    elif "result" in data:
        result = data["result"]
        if not isinstance(result, dict):
            raise ManifestError("JSON-RPC 'result' must be an object")
        if "tools" not in result:
            raise ManifestError("JSON-RPC 'result' has no 'tools' array")
        raw_tools = result["tools"]
    elif "error" in data:
        raise ManifestError("payload is a JSON-RPC error response, not a tools/list result")
    else:
        raise ManifestError("payload has neither a 'tools' array nor a JSON-RPC 'result'")

    if not isinstance(raw_tools, list):
        raise ManifestError("'tools' must be an array")

    tools: list[ToolDefinition] = []
    for index, raw_tool in enumerate(raw_tools):
        if not isinstance(raw_tool, dict):
            raise ManifestError(f"tools[{index}] must be an object")
        try:
            tools.append(ToolDefinition.model_validate(raw_tool))
        except ValidationError as exc:
            raise ManifestError(f"tools[{index}] is not a valid MCP tool definition: {exc}") from exc

    seen: set[str] = set()
    for tool in tools:
        if tool.name in seen:
            raise ManifestError(f"duplicate tool name in manifest: {tool.name!r}")
        seen.add(tool.name)

    return tools
