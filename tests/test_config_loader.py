"""Tests for multi-server MCP config ingestion."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from mcpprobe.config_loader import (
    ServerSpec,
    load_mcp_config,
    parse_server_manifest_arg,
    resolve_server_manifests,
)
from mcpprobe.models import ManifestError, ProbeError

FIXTURE = Path(__file__).parent / "fixtures" / "mock_mcp_stdio.py"

ECHO_TOOL: dict[str, Any] = {
    "name": "echo",
    "description": "Echo text back.",
    "inputSchema": {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
}


def write_json(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def claude_config() -> dict[str, Any]:
    return {
        "mcpServers": {
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "secret"},
            },
            "remote-tools": {
                "url": "https://mcp.example.com/mcp",
                "headers": {"Authorization": "Bearer token"},
            },
            "bundle": {"tools": [ECHO_TOOL]},
        }
    }


def test_load_claude_desktop_config(tmp_path: Path) -> None:
    path = write_json(tmp_path / "claude_desktop_config.json", claude_config())

    specs = load_mcp_config(path)

    assert [spec.server_id for spec in specs] == ["bundle", "github", "remote-tools"]
    by_id = {spec.server_id: spec for spec in specs}

    assert by_id["github"].transport == "stdio"
    assert by_id["github"].command == ["npx", "-y", "@modelcontextprotocol/server-github"]
    assert by_id["github"].env == {"GITHUB_TOKEN": "secret"}

    assert by_id["remote-tools"].transport == "http"
    assert by_id["remote-tools"].url == "https://mcp.example.com/mcp"
    assert by_id["remote-tools"].headers == {"Authorization": "Bearer token"}

    assert by_id["bundle"].transport == "static"
    assert by_id["bundle"].manifest_payload == {"tools": [ECHO_TOOL]}


def test_load_cursor_config_with_list_command(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "mcp.json",
        {"mcpServers": {"local": {"command": ["python", "-m", "my_server"]}}},
    )

    specs = load_mcp_config(path)

    assert specs[0].transport == "stdio"
    assert specs[0].command == ["python", "-m", "my_server"]
    assert specs[0].env == {}


def test_load_vscode_servers_config(tmp_path: Path) -> None:
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir()
    path = write_json(
        vscode_dir / "mcp.json",
        {
            "servers": {
                "vscode-stdio": {"type": "stdio", "command": "python", "args": ["server.py"]},
                "vscode-http": {"type": "http", "url": "http://127.0.0.1:3000/mcp"},
            }
        },
    )

    specs = load_mcp_config(path)

    assert [spec.server_id for spec in specs] == ["vscode-http", "vscode-stdio"]
    assert specs[0].transport == "http"
    assert specs[1].command == ["python", "server.py"]


def test_load_multi_server_static_bundle_with_servers_key(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "bundle.json",
        {"servers": {"alpha": {"tools": [ECHO_TOOL]}, "beta": {"tools": []}}},
    )

    specs = load_mcp_config(path)

    assert [(spec.server_id, spec.transport) for spec in specs] == [
        ("alpha", "static"),
        ("beta", "static"),
    ]
    assert specs[1].manifest_payload == {"tools": []}


def test_static_entry_keeps_cache_metadata(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "bundle.json",
        {"servers": {"alpha": {"tools": [ECHO_TOOL], "ttlMs": 5000, "cacheScope": "session"}}},
    )

    spec = load_mcp_config(path)[0]

    assert spec.manifest_payload is not None
    assert spec.manifest_payload["ttlMs"] == 5000
    assert spec.manifest_payload["cacheScope"] == "session"


def test_missing_container_is_rejected(tmp_path: Path) -> None:
    path = write_json(tmp_path / "config.json", {"unrelated": {}})

    with pytest.raises(ManifestError, match="mcpServers"):
        load_mcp_config(path)


def test_non_object_container_is_rejected(tmp_path: Path) -> None:
    path = write_json(tmp_path / "config.json", {"mcpServers": []})

    with pytest.raises(ManifestError, match="object"):
        load_mcp_config(path)


def test_non_object_entry_is_rejected(tmp_path: Path) -> None:
    path = write_json(tmp_path / "config.json", {"mcpServers": {"bad": "nope"}})

    with pytest.raises(ManifestError, match="must be an object"):
        load_mcp_config(path)


def test_entry_without_transport_is_rejected(tmp_path: Path) -> None:
    path = write_json(tmp_path / "config.json", {"mcpServers": {"odd": {"foo": 1}}})

    with pytest.raises(ManifestError, match="none of"):
        load_mcp_config(path)


def test_invalid_args_are_rejected(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "config.json", {"mcpServers": {"x": {"command": "python", "args": "oops"}}}
    )

    with pytest.raises(ManifestError, match="args"):
        load_mcp_config(path)


def test_invalid_env_is_rejected(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "config.json", {"mcpServers": {"x": {"command": "python", "env": []}}}
    )

    with pytest.raises(ManifestError, match="env"):
        load_mcp_config(path)


def test_invalid_headers_are_rejected(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "config.json",
        {"mcpServers": {"x": {"url": "https://example.test/mcp", "headers": "nope"}}},
    )

    with pytest.raises(ManifestError, match="headers"):
        load_mcp_config(path)


def test_empty_url_is_rejected(tmp_path: Path) -> None:
    path = write_json(tmp_path / "config.json", {"mcpServers": {"x": {"url": ""}}})

    with pytest.raises(ManifestError, match="url"):
        load_mcp_config(path)


def test_duplicate_server_across_containers_is_rejected(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "config.json",
        {
            "mcpServers": {"same": {"tools": [ECHO_TOOL]}},
            "servers": {"same": {"tools": [ECHO_TOOL]}},
        },
    )

    with pytest.raises(ManifestError, match="duplicate server id"):
        load_mcp_config(path)


def test_invalid_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text("{oops", encoding="utf-8")

    with pytest.raises(ManifestError, match="invalid JSON"):
        load_mcp_config(path)


def test_missing_config_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="cannot read"):
        load_mcp_config(tmp_path / "absent.json")


# -- --server-manifest -----------------------------------------------------


def test_parse_server_manifest_arg(tmp_path: Path) -> None:
    path = write_json(tmp_path / "snapshot.json", {"tools": [ECHO_TOOL]})

    spec = parse_server_manifest_arg(f"github={path}")

    assert spec.server_id == "github"
    assert spec.transport == "static"
    assert spec.manifest_payload == {"tools": [ECHO_TOOL]}


@pytest.mark.parametrize("raw", ["github", "=path.json", "github=", "  =  "])
def test_parse_server_manifest_arg_rejects_malformed(raw: str) -> None:
    with pytest.raises(ManifestError, match="server_id"):
        parse_server_manifest_arg(raw)


def test_parse_server_manifest_arg_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="cannot read"):
        parse_server_manifest_arg(f"github={tmp_path / 'absent.json'}")


def test_parse_server_manifest_arg_non_object(tmp_path: Path) -> None:
    path = write_json(tmp_path / "list.json", [1, 2, 3])

    with pytest.raises(ManifestError, match="must be an object"):
        parse_server_manifest_arg(f"github={path}")


# -- resolve ---------------------------------------------------------------


def test_resolve_static_specs(tmp_path: Path) -> None:
    path = write_json(tmp_path / "bundle.json", {"servers": {"alpha": {"tools": [ECHO_TOOL]}}})

    resolved = resolve_server_manifests(load_mcp_config(path))

    assert list(resolved) == ["alpha"]
    assert [tool.name for tool in resolved["alpha"]] == ["echo"]


def test_resolve_rejects_duplicate_ids(tmp_path: Path) -> None:
    path = write_json(tmp_path / "snapshot.json", {"tools": [ECHO_TOOL]})
    spec = parse_server_manifest_arg(f"dup={path}")

    with pytest.raises(ManifestError, match="duplicate server id"):
        resolve_server_manifests([spec, spec])


def test_resolve_stdio_without_live_explains_flag() -> None:
    spec = ServerSpec(server_id="local", transport="stdio", command=["python", "server.py"])

    with pytest.raises(ManifestError, match="--live"):
        resolve_server_manifests([spec])


def test_resolve_http_without_live_explains_flag() -> None:
    spec = ServerSpec(server_id="remote", transport="http", url="https://example.test/mcp")

    with pytest.raises(ManifestError, match="--live"):
        resolve_server_manifests([spec])


def test_resolve_live_stdio_harvests_tools() -> None:
    spec = ServerSpec(
        server_id="mock",
        transport="stdio",
        command=[sys.executable, str(FIXTURE)],
    )

    resolved = resolve_server_manifests([spec], live=True, timeout=10.0)

    assert [tool.name for tool in resolved["mock"]] == ["echo", "add"]


def test_resolve_live_stdio_failure_is_probe_error() -> None:
    spec = ServerSpec(server_id="broken", transport="stdio", command=["/nonexistent/binary"])

    with pytest.raises(ProbeError, match="cannot start MCP server"):
        resolve_server_manifests([spec], live=True, timeout=1.0)
