"""Tests for canonical serialization and hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from mcpprobe.models import ToolDefinition
from mcpprobe.normalizer import (
    canonicalize_tool,
    hash_manifest,
    hash_tool,
    manifest_entries,
)


def make_tool(**overrides: Any) -> ToolDefinition:
    payload: dict[str, Any] = {
        "name": "echo",
        "description": "Echo text back.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to echo."}},
            "required": ["text"],
        },
    }
    payload.update(overrides)
    return ToolDefinition.model_validate(payload)


def test_canonicalize_is_key_order_invariant_for_nested_schema() -> None:
    first = make_tool(
        inputSchema={
            "type": "object",
            "properties": {"text": {"type": "string", "minLength": 1}},
            "required": ["text"],
            "additionalProperties": False,
        }
    )
    second = make_tool(
        inputSchema={
            "additionalProperties": False,
            "required": ["text"],
            "properties": {"text": {"minLength": 1, "type": "string"}},
            "type": "object",
        }
    )

    assert canonicalize_tool(first) == canonicalize_tool(second)
    assert hash_tool(first) == hash_tool(second)


def test_canonical_json_is_sorted_and_compact() -> None:
    canonical = canonicalize_tool(make_tool())

    assert canonical == json.dumps(
        json.loads(canonical), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert ", " not in canonical
    assert '": ' not in canonical


def test_non_ascii_text_is_kept_literal() -> None:
    canonical = canonicalize_tool(make_tool(description="Renvoie le texte — café ✓"))

    assert "café ✓" in canonical
    assert "\\u" not in canonical


def test_description_single_character_change_alters_hash() -> None:
    assert hash_tool(make_tool(description="Echo text back.")) != hash_tool(
        make_tool(description="Echo text back!")
    )


def test_description_trailing_whitespace_alters_hash() -> None:
    assert hash_tool(make_tool(description="Echo text back.")) != hash_tool(
        make_tool(description="Echo text back. ")
    )


@pytest.mark.parametrize(
    "invisible",
    [
        "\u200b",  # zero width space
        "\u200e",  # left-to-right mark
        "\u00a0",  # no-break space
        "\ufeff",  # zero width no-break space / BOM
        "\u2028",  # line separator
    ],
)
def test_invisible_characters_inside_description_alter_hash(invisible: str) -> None:
    baseline = hash_tool(make_tool(description="Echo text back."))
    sneaky = hash_tool(make_tool(description=f"Echo{invisible} text back."))

    assert baseline != sneaky


def test_nested_schema_description_change_alters_hash() -> None:
    baseline = make_tool()
    edited = make_tool(
        inputSchema={
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to echo!\u200b"}},
            "required": ["text"],
        }
    )

    assert hash_tool(baseline) != hash_tool(edited)


def test_extension_fields_are_preserved_and_hashed() -> None:
    baseline = make_tool()
    with_extension = ToolDefinition.model_validate(
        {**baseline.model_dump(), "x-vendor": {"requiresConsent": True}}
    )

    canonical = canonicalize_tool(with_extension)
    assert "x-vendor" in canonical
    assert "x-vendor" not in canonicalize_tool(baseline)
    assert hash_tool(baseline) != hash_tool(with_extension)


def test_extension_field_key_order_is_invariant() -> None:
    base = make_tool().model_dump()
    first = ToolDefinition.model_validate(
        {**base, "x-vendor": {"a": 1, "b": {"x": True, "y": False}}}
    )
    second = ToolDefinition.model_validate(
        {**base, "x-vendor": {"b": {"y": False, "x": True}, "a": 1}}
    )

    assert hash_tool(first) == hash_tool(second)


def test_omitted_defaults_match_explicit_defaults() -> None:
    minimal = ToolDefinition.model_validate({"name": "noop"})
    explicit = ToolDefinition.model_validate(
        {
            "name": "noop",
            "title": None,
            "description": "",
            "inputSchema": {"type": "object"},
            "outputSchema": None,
            "annotations": None,
        }
    )

    assert canonicalize_tool(minimal) == canonicalize_tool(explicit)
    assert hash_tool(minimal) == hash_tool(explicit)


def test_output_schema_and_annotations_participate_in_digest() -> None:
    baseline = make_tool()
    with_output = make_tool(outputSchema={"type": "object", "properties": {"ok": {"type": "boolean"}}})
    with_annotations = make_tool(annotations={"readOnlyHint": True})

    assert hash_tool(baseline) != hash_tool(with_output)
    assert hash_tool(baseline) != hash_tool(with_annotations)


def test_hash_tool_is_lowercase_sha256_of_canonical_json() -> None:
    tool = make_tool()
    digest = hash_tool(tool)

    assert digest == hashlib.sha256(canonicalize_tool(tool).encode("utf-8")).hexdigest()
    assert len(digest) == 64
    assert digest == digest.lower()
    assert all(char in "0123456789abcdef" for char in digest)


def test_hash_manifest_is_order_invariant() -> None:
    first = make_tool(name="alpha", description="First.")
    second = make_tool(name="beta", description="Second.")

    assert hash_manifest([first, second]) == hash_manifest([second, first])
    assert manifest_entries([first, second]) == sorted(manifest_entries([second, first]))


def test_hash_manifest_detects_added_tool() -> None:
    alpha = make_tool(name="alpha", description="First.")
    beta = make_tool(name="beta", description="Second.")

    assert hash_manifest([alpha]) != hash_manifest([alpha, beta])


def test_hash_manifest_detects_removed_tool() -> None:
    alpha = make_tool(name="alpha", description="First.")
    beta = make_tool(name="beta", description="Second.")

    assert hash_manifest([alpha, beta]) != hash_manifest([alpha])


def test_hash_manifest_detects_modified_tool() -> None:
    alpha = make_tool(name="alpha", description="First.")
    alpha_edited = make_tool(name="alpha", description="First!")

    assert hash_manifest([alpha]) != hash_manifest([alpha_edited])


def test_manifest_entries_use_name_colon_sha256_format() -> None:
    tool = make_tool(name="alpha")

    entries = manifest_entries([tool])

    assert entries == [f"alpha:{hash_tool(tool)}"]
