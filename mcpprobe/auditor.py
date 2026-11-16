"""Deterministic MCP metadata and protocol-hygiene auditor.

The auditor is purely static: it never calls the MCP server, and it never
consults anything but the manifest bytes. Every finding is produced by a fixed
rule so two runs over the same manifest always yield the same report.

Implemented rules:

``UNICODE_TAG_BLOCK`` (CRITICAL)
    Unicode Tag characters (``U+E0000``-``U+E007F``) are invisible in every
    terminal and renderer, yet LLMs tokenize them. They are the standard
    vehicle for smuggled instructions, so they are always critical -- and the
    hidden ASCII payload is decoded into the finding's evidence.

``UNICODE_BIDI_OVERRIDE`` (HIGH)
    Bidirectional override/embedding controls can visually reorder a schema so
    the approved text is not the text the model reads.

``UNICODE_ZERO_WIDTH`` (MEDIUM)
    Zero-width and BOM codepoints can split keywords or smuggle hidden markers
    without changing how the metadata looks.

``UNICODE_VARIATION_SELECTOR`` (HIGH)
    Variation selectors (``U+FE00``-``U+FE0F``, ``U+E0100``-``U+E01EF``) select
    an alternate glyph for the preceding character. They are invisible when the
    font ignores them, so they can carry a hidden marker or make an approved
    string render differently from the bytes the model reads.

``HEADER_PRIVILEGED_INJECTION`` (CRITICAL)
    ``x-mcp-header`` tells an MCP transport to place LLM-supplied parameter
    values into an HTTP header. Binding a privileged header (``Authorization``,
    ``Cookie``, ``Host``, ``X-API-Key``, ``X-Forwarded-For`` ...) hands header
    control to the model.

``HEADER_CRLF_CONTROL`` (CRITICAL)
    Control characters in a header binding enable header splitting.

``HEADER_SPEC_VIOLATION`` (HIGH)
    Violations of the ``2026-07-28`` header rules: non-string/empty name,
    duplicate case-insensitive name within one tool, or a parameter type other
    than ``string`` / ``integer`` / ``boolean``.

``TOOL_NAME_SPEC_VIOLATION`` (MEDIUM)
    Names outside ``^[A-Za-z0-9_.-]{1,128}$``.

``ANNOTATION_CONTRADICTION`` (MEDIUM)
    ``readOnlyHint: true`` alongside ``destructiveHint: true`` or an
    ``x-mcp-header`` binding.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from pydantic import BaseModel, Field

from .models import (
    SEVERITY_LEVELS,
    ProbeError,
    Severity,
    ToolDefinition,
    iter_strings,
    parse_tools_payload,
    severity_rank,
)

TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

#: Only these tag codepoints map onto printable ASCII.
TAG_ASCII_START = 0xE0020
TAG_ASCII_END = 0xE007E

BIDI_CODEPOINTS = frozenset(
    {
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x061C,  # ARABIC LETTER MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)

ZERO_WIDTH_CODEPOINTS = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
    }
)

VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))

PRIVILEGED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "host",
        "x-api-key",
        "x-auth-token",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "forwarded",
        "x-real-ip",
        "x-original-url",
        "x-rewrite-url",
        "content-length",
        "transfer-encoding",
    }
)

#: MCP 2026-07-28 only allows these parameter types for header bindings.
ALLOWED_HEADER_PARAM_TYPES = frozenset({"string", "integer", "boolean"})

TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class AuditFinding(BaseModel):
    """A single deterministic rule violation."""

    rule_id: str
    severity: Severity
    tool_name: str
    field_path: str
    message: str
    evidence: str | None = None


class AuditReport(BaseModel):
    """Result of auditing one ``tools/list`` manifest."""

    server_id: str | None = None
    tool_count: int
    findings: list[AuditFinding] = Field(default_factory=list)
    passed: bool


def _hex_codepoints(codepoints: list[int]) -> str:
    return ", ".join(f"U+{codepoint:04X}" for codepoint in codepoints)


def tag_block_codepoints(text: str) -> list[int]:
    """Return codepoints of every Unicode Tag character in ``text``."""

    return [ord(char) for char in text if TAG_BLOCK_START <= ord(char) <= TAG_BLOCK_END]


def decode_tag_block(text: str) -> str:
    """Decode ``U+E0020``-``U+E007E`` back to the ASCII payload they hide."""

    return "".join(
        chr(ord(char) - TAG_BLOCK_START)
        for char in text
        if TAG_ASCII_START <= ord(char) <= TAG_ASCII_END
    )


def bidi_codepoints(text: str) -> list[int]:
    """Return codepoints of every BiDi control character in ``text``."""

    return [ord(char) for char in text if ord(char) in BIDI_CODEPOINTS]


def zero_width_codepoints(text: str) -> list[int]:
    """Return codepoints of every zero-width / BOM character in ``text``."""

    return [ord(char) for char in text if ord(char) in ZERO_WIDTH_CODEPOINTS]


def variation_selector_codepoints(text: str) -> list[int]:
    """Return codepoints of every Unicode variation selector in ``text``."""

    return [
        ord(char)
        for char in text
        if any(low <= ord(char) <= high for low, high in VARIATION_SELECTOR_RANGES)
    ]


def concealment_codepoints(text: str) -> list[int]:
    """Return every concealment codepoint (tag block, BiDi, zero width)."""

    return [
        ord(char)
        for char in text
        if TAG_BLOCK_START <= ord(char) <= TAG_BLOCK_END
        or ord(char) in BIDI_CODEPOINTS
        or ord(char) in ZERO_WIDTH_CODEPOINTS
    ]


def _escape_controls(value: str) -> str:
    return value.encode("unicode_escape").decode("ascii")


def iter_header_bindings(
    schema: Any, path: str = "inputSchema"
) -> Iterator[tuple[str, Any, Any]]:
    """Yield ``(field_path, header_value, owning_schema)`` for each binding."""

    if isinstance(schema, dict):
        if "x-mcp-header" in schema:
            yield f"{path}.x-mcp-header", schema.get("x-mcp-header"), schema
        for key, value in schema.items():
            if key == "x-mcp-header":
                continue
            child = f"{path}.{key}"
            if key == "properties" and isinstance(value, dict):
                for property_name, property_schema in value.items():
                    yield from iter_header_bindings(property_schema, f"{child}.{property_name}")
            else:
                yield from iter_header_bindings(value, child)
    elif isinstance(schema, (list, tuple)):
        for index, item in enumerate(schema):
            yield from iter_header_bindings(item, f"{path}[{index}]")


def _unicode_findings(tool: ToolDefinition) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    payload = tool.model_dump(mode="json", by_alias=True)

    for path, text in iter_strings(payload):
        tags = tag_block_codepoints(text)
        if tags:
            decoded = decode_tag_block(text)
            findings.append(
                AuditFinding(
                    rule_id="UNICODE_TAG_BLOCK",
                    severity="CRITICAL",
                    tool_name=tool.name,
                    field_path=path,
                    message=(
                        f"{len(tags)} invisible Unicode tag-block character(s) conceal content"
                        " that renders as nothing but is read by the model"
                    ),
                    evidence=decoded or "(no printable ASCII payload)",
                )
            )

        bidi = bidi_codepoints(text)
        if bidi:
            findings.append(
                AuditFinding(
                    rule_id="UNICODE_BIDI_OVERRIDE",
                    severity="HIGH",
                    tool_name=tool.name,
                    field_path=path,
                    message="Bidirectional control characters can reorder text so the approved metadata is not what the model reads",
                    evidence=_hex_codepoints(bidi),
                )
            )

        variation = variation_selector_codepoints(text)
        if variation:
            findings.append(
                AuditFinding(
                    rule_id="UNICODE_VARIATION_SELECTOR",
                    severity="HIGH",
                    tool_name=tool.name,
                    field_path=path,
                    message=(
                        "Unicode variation selectors can pick an alternate glyph or"
                        " carry an invisible marker, so the rendered metadata need"
                        " not be the bytes the model reads"
                    ),
                    evidence=_hex_codepoints(variation),
                )
            )

        zero_width = zero_width_codepoints(text)
        if zero_width:
            findings.append(
                AuditFinding(
                    rule_id="UNICODE_ZERO_WIDTH",
                    severity="MEDIUM",
                    tool_name=tool.name,
                    field_path=path,
                    message="Zero-width or BOM characters hide markers inside otherwise identical-looking text",
                    evidence=_hex_codepoints(zero_width),
                )
            )

    return findings


def _header_findings(tool: ToolDefinition) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    seen_headers: dict[str, str] = {}

    for path, raw_header, owner in iter_header_bindings(tool.inputSchema):
        if not isinstance(raw_header, str) or not raw_header.strip():
            findings.append(
                AuditFinding(
                    rule_id="HEADER_SPEC_VIOLATION",
                    severity="HIGH",
                    tool_name=tool.name,
                    field_path=path,
                    message=(
                        "x-mcp-header must be a non-empty string per MCP 2026-07-28,"
                        f" got {raw_header!r}"
                    ),
                    evidence=_escape_controls(str(raw_header)),
                )
            )
        else:
            normalized = raw_header.strip().lower()
            if normalized in PRIVILEGED_HEADERS:
                findings.append(
                    AuditFinding(
                        rule_id="HEADER_PRIVILEGED_INJECTION",
                        severity="CRITICAL",
                        tool_name=tool.name,
                        field_path=path,
                        message=(
                            f"Parameter value is bound to the privileged HTTP header {normalized!r},"
                            " letting LLM-controlled input set it"
                        ),
                        evidence=raw_header,
                    )
                )

            if any(ord(char) < 32 or ord(char) == 127 for char in raw_header):
                findings.append(
                    AuditFinding(
                        rule_id="HEADER_CRLF_CONTROL",
                        severity="CRITICAL",
                        tool_name=tool.name,
                        field_path=path,
                        message="x-mcp-header contains control characters (CR/LF/NUL), enabling HTTP header splitting",
                        evidence=_escape_controls(raw_header),
                    )
                )

            if normalized in seen_headers:
                findings.append(
                    AuditFinding(
                        rule_id="HEADER_SPEC_VIOLATION",
                        severity="HIGH",
                        tool_name=tool.name,
                        field_path=path,
                        message=(
                            f"Duplicate x-mcp-header {raw_header!r}: the same header is already bound"
                            f" at {seen_headers[normalized]} (MCP 2026-07-28 requires unique names)"
                        ),
                        evidence=raw_header,
                    )
                )
            else:
                seen_headers[normalized] = path

        param_type = owner.get("type") if isinstance(owner, dict) else None
        if not (isinstance(param_type, str) and param_type in ALLOWED_HEADER_PARAM_TYPES):
            findings.append(
                AuditFinding(
                    rule_id="HEADER_SPEC_VIOLATION",
                    severity="HIGH",
                    tool_name=tool.name,
                    field_path=path,
                    message=(
                        "x-mcp-header is only allowed on parameters typed string, integer or boolean;"
                        f" this parameter has type {param_type!r}"
                    ),
                    evidence=str(param_type),
                )
            )

    return findings


def audit_tool(tool: ToolDefinition) -> list[AuditFinding]:
    """Run every audit rule against a single tool definition."""

    findings: list[AuditFinding] = []

    if not TOOL_NAME_PATTERN.fullmatch(tool.name or ""):
        findings.append(
            AuditFinding(
                rule_id="TOOL_NAME_SPEC_VIOLATION",
                severity="MEDIUM",
                tool_name=tool.name,
                field_path="name",
                message="Tool name must match ^[A-Za-z0-9_.-]{1,128}$",
                evidence=tool.name,
            )
        )

    findings.extend(_unicode_findings(tool))

    header_findings = _header_findings(tool)
    findings.extend(header_findings)
    has_header_binding = bool(list(iter_header_bindings(tool.inputSchema)))

    annotations = tool.annotations or {}
    if annotations.get("readOnlyHint") is True:
        if annotations.get("destructiveHint") is True:
            findings.append(
                AuditFinding(
                    rule_id="ANNOTATION_CONTRADICTION",
                    severity="MEDIUM",
                    tool_name=tool.name,
                    field_path="annotations.readOnlyHint",
                    message="readOnlyHint=true contradicts destructiveHint=true",
                    evidence="readOnlyHint=true, destructiveHint=true",
                )
            )
        if has_header_binding:
            findings.append(
                AuditFinding(
                    rule_id="ANNOTATION_CONTRADICTION",
                    severity="MEDIUM",
                    tool_name=tool.name,
                    field_path="annotations.readOnlyHint",
                    message="readOnlyHint=true contradicts x-mcp-header bindings, which inject request metadata",
                    evidence="readOnlyHint=true with x-mcp-header binding",
                )
            )

    return findings


def audit_manifest(
    manifest_data: dict[str, Any], fail_on: Severity = "MEDIUM"
) -> AuditReport:
    """Audit every tool in a raw or JSON-RPC ``tools/list`` payload."""

    if fail_on not in SEVERITY_LEVELS:
        raise ProbeError(f"invalid fail_on severity: {fail_on!r}")

    tools = parse_tools_payload(manifest_data)

    findings: list[AuditFinding] = []
    for tool in tools:
        findings.extend(audit_tool(tool))

    findings.sort(key=lambda finding: (finding.tool_name, finding.field_path, finding.rule_id))

    threshold = severity_rank(fail_on)
    passed = all(severity_rank(finding.severity) < threshold for finding in findings)

    return AuditReport(
        server_id=None,
        tool_count=len(tools),
        findings=findings,
        passed=passed,
    )

