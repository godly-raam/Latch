"""Tests for the MCP tool definition models."""

from __future__ import annotations

from mcpprobe.models import ToolDefinition, parse_tools_payload


def test_null_description_is_normalized_to_an_empty_string() -> None:
    tools = parse_tools_payload(
        {
            "tools": [
                {
                    "name": "echo",
                    "description": None,
                    "inputSchema": {"type": "object"},
                }
            ]
        }
    )

    assert tools[0].description == ""
    assert isinstance(tools[0].description, str)
    assert tools[0].model_dump(mode="json")["description"] == ""


def test_description_still_accepts_text() -> None:
    tool = ToolDefinition.model_validate({"name": "echo", "description": "Echo."})

    assert tool.description == "Echo."
