"""Ingest multi-server MCP agent configurations.

Supported shapes:

* Claude Desktop / Cursor / Windsurf -- ``{"mcpServers": {"<id>": {...}}}``
* VS Code -- ``{"servers": {"<id>": {...}}}``
* Latch bundles -- either key, with an entry carrying ``{"tools": [...]}``
* CLI -- ``--server-manifest <server_id>=path.json``

Entries are classified by content: ``tools`` means a static snapshot, ``url``
means Streamable HTTP, ``command`` means a stdio child process. Live transports
are only harvested when ``live=True``; otherwise ``resolve_server_manifests``
fails with an instruction instead of silently producing an empty graph.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from .models import ManifestError, ToolDefinition, parse_tools_payload
from .transport import DEFAULT_TIMEOUT, harvest_http, harvest_stdio

CONFIG_CONTAINER_KEYS = ("mcpServers", "servers")


class ServerSpec(BaseModel):
    """One MCP server declared by a config file or a CLI flag."""

    server_id: str
    transport: Literal["static", "stdio", "http"]
    manifest_payload: dict[str, Any] | None = None
    command: list[str] | None = None
    env: dict[str, str] | None = None
    url: str | None = None
    headers: dict[str, str] | None = None


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read {label} {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {label} {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"invalid {label} {path}: top-level JSON value must be an object")
    return data


def _string_map(value: Any, *, label: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ManifestError(f"{label} must be an object")
    return {str(key): str(item) for key, item in value.items()}


def _spec_from_entry(server_id: str, entry: Any, path: Path) -> ServerSpec:
    if not isinstance(entry, dict):
        raise ManifestError(f"invalid MCP config {path}: server {server_id!r} must be an object")

    if "tools" in entry:
        tools = entry["tools"]
        if not isinstance(tools, list):
            raise ManifestError(
                f"invalid MCP config {path}: server {server_id!r} 'tools' must be an array"
            )
        payload: dict[str, Any] = {"tools": tools}
        for key in ("ttlMs", "cacheScope"):
            if key in entry:
                payload[key] = entry[key]
        return ServerSpec(server_id=server_id, transport="static", manifest_payload=payload)

    if "url" in entry:
        url = entry["url"]
        if not isinstance(url, str) or not url.strip():
            raise ManifestError(
                f"invalid MCP config {path}: server {server_id!r} 'url' must be a non-empty string"
            )
        return ServerSpec(
            server_id=server_id,
            transport="http",
            url=url.strip(),
            headers=_string_map(
                entry.get("headers"),
                label=f"invalid MCP config {path}: server {server_id!r} 'headers'",
            ),
        )

    if "command" in entry:
        command = entry["command"]
        if isinstance(command, str) and command.strip():
            argv = [command.strip()]
        elif isinstance(command, list) and command and all(isinstance(item, str) for item in command):
            argv = [str(item) for item in command]
        else:
            raise ManifestError(
                f"invalid MCP config {path}: server {server_id!r} 'command' must be a"
                " non-empty string or array of strings"
            )

        args = entry.get("args", [])
        if args is None:
            args = []
        if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
            raise ManifestError(
                f"invalid MCP config {path}: server {server_id!r} 'args' must be an array of strings"
            )
        argv.extend(str(item) for item in args)

        return ServerSpec(
            server_id=server_id,
            transport="stdio",
            command=argv,
            env=_string_map(
                entry.get("env"),
                label=f"invalid MCP config {path}: server {server_id!r} 'env'",
            ),
        )

    raise ManifestError(
        f"invalid MCP config {path}: server {server_id!r} declares none of"
        " 'tools', 'url' or 'command'"
    )


def load_mcp_config(path: Path) -> list[ServerSpec]:
    """Load every server declared by an MCP agent configuration file."""

    path = Path(path)
    data = _read_json_object(path, "MCP config")

    mappings: list[tuple[str, dict[str, Any]]] = []
    for key in CONFIG_CONTAINER_KEYS:
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ManifestError(f"invalid MCP config {path}: {key!r} must be an object")
        mappings.append((key, value))

    if not mappings:
        raise ManifestError(
            f"invalid MCP config {path}: expected a 'mcpServers' or 'servers' object"
        )

    specs: list[ServerSpec] = []
    seen: set[str] = set()
    for _key, mapping in mappings:
        for raw_server_id, entry in mapping.items():
            server_id = str(raw_server_id)
            if server_id in seen:
                raise ManifestError(f"invalid MCP config {path}: duplicate server id {server_id!r}")
            seen.add(server_id)
            specs.append(_spec_from_entry(server_id, entry, path))

    return sorted(specs, key=lambda spec: spec.server_id)


def parse_server_manifest_arg(spec: str) -> ServerSpec:
    """Parse ``--server-manifest <server_id>=path.json`` into a static spec."""

    server_id, separator, raw_path = spec.partition("=")
    server_id = server_id.strip()
    raw_path = raw_path.strip()
    if not separator or not server_id or not raw_path:
        raise ManifestError(
            f"invalid --server-manifest {spec!r}: expected <server_id>=path.json"
        )

    payload = _read_json_object(Path(raw_path), "server manifest")
    return ServerSpec(server_id=server_id, transport="static", manifest_payload=payload)


def _live_hint(spec: ServerSpec) -> str:
    return (
        f"server {spec.server_id!r} is declared as {spec.transport} but has no captured"
        f" manifest: pass --live to harvest it, or supply a static snapshot with"
        f" --server-manifest {spec.server_id}=path.json"
    )


async def _live_tools(spec: ServerSpec, timeout: float) -> list[ToolDefinition]:
    """Harvest one live spec through the shared transport helpers."""

    if spec.transport == "stdio":
        harvest = await harvest_stdio(
            spec.command or [], timeout=timeout, env=spec.env or None
        )
    else:
        harvest = await harvest_http(
            spec.url or "",
            headers=spec.headers or None,
            timeout=timeout,
        )
    return parse_tools_payload(harvest.tools_payload)


def resolve_server_manifests(
    specs: list[ServerSpec], live: bool = False, timeout: float = DEFAULT_TIMEOUT
) -> dict[str, list[ToolDefinition]]:
    """Turn every spec into a concrete tool list, harvesting when asked."""

    resolved: dict[str, list[ToolDefinition]] = {}

    for spec in specs:
        if spec.server_id in resolved:
            raise ManifestError(f"duplicate server id {spec.server_id!r}")

        if spec.transport == "static":
            if spec.manifest_payload is None:
                raise ManifestError(
                    f"server {spec.server_id!r} is static but carries no manifest payload"
                )
            resolved[spec.server_id] = parse_tools_payload(spec.manifest_payload)
            continue

        if not live:
            raise ManifestError(_live_hint(spec))

        resolved[spec.server_id] = asyncio.run(_live_tools(spec, timeout))

    return resolved
