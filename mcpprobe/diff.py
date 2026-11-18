"""Field-level differential engine for MCP tool definitions.

``hash_tool`` answers *whether* a tool changed. This module answers *what*
changed, with enough context for an operator to judge a rug pull: a poisoned
``description``, a newly injected parameter, or a flipped safety annotation.

Severity ladder (also used by drift reports):

``CRITICAL``
    ``x-mcp-header`` added or modified on a parameter, or Unicode concealment
    characters introduced into a modified field.
``HIGH``
    Tool or parameter descriptions modified, a parameter added, ``required``
    relaxed, or a safety hint flipped towards danger.
``MEDIUM``
    ``outputSchema``, parameter constraints, or unknown extension fields.
``LOW``
    Display-only ``title`` / ``icons`` changes.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel

from .auditor import concealment_codepoints
from .models import (
    ProbeError,
    Severity,
    ToolDefinition,
    highest_severity,
    iter_strings,
)
from .normalizer import canonical_payload

ChangeType = Literal["ADDED", "REMOVED", "MODIFIED"]

KNOWN_TOOL_FIELDS = frozenset(
    {"name", "title", "description", "inputSchema", "outputSchema", "annotations"}
)

DISPLAY_ONLY_FIELDS = frozenset({"title", "icons"})

SECURITY_HINTS: tuple[tuple[str, Any, str], ...] = (
    (
        "annotations.readOnlyHint",
        True,
        "readOnlyHint no longer true: a tool advertised as read-only may now mutate state",
    ),
    (
        "annotations.destructiveHint",
        True,
        "destructiveHint became true: the tool now advertises destructive behaviour",
    ),
    (
        "annotations.openWorldHint",
        True,
        "openWorldHint became true: the tool now reaches outside its declared boundary",
    ),
)


class FieldChange(BaseModel):
    """One leaf-level difference between a pinned tool and the live one."""

    path: str
    change_type: ChangeType
    old_value: Any = None
    new_value: Any = None
    risk_reason: str
    severity: Severity


def _concealment_count(value: Any) -> int:
    return sum(len(concealment_codepoints(text)) for _, text in iter_strings(value))


def _introduces_concealment(old_value: Any, new_value: Any) -> bool:
    return _concealment_count(new_value) > _concealment_count(old_value)


def _is_relaxed_required(old_value: Any, new_value: Any) -> bool:
    """True when ``required`` lists lost entries without gaining any."""

    if new_value is None:
        return bool(old_value)
    if not isinstance(old_value, list) or not isinstance(new_value, list):
        return False
    old_set = {str(item) for item in old_value}
    new_set = {str(item) for item in new_value}
    return bool(old_set - new_set) and not (new_set - old_set)


def _hint_flip(path: str, old_value: Any, new_value: Any) -> str | None:
    for hint_path, dangerous, reason in SECURITY_HINTS:
        if path != hint_path:
            continue
        if hint_path == "annotations.readOnlyHint":
            if old_value is True and new_value is not True:
                return reason
        elif old_value is not True and new_value is True:
            return reason
    return None


def _classify(
    path: str, change_type: ChangeType, old_value: Any, new_value: Any
) -> tuple[Severity, str]:
    segments = path.split(".")
    last = segments[-1]
    is_input_schema = segments[0] == "inputSchema"
    is_parameter_root = (
        len(segments) == 3 and is_input_schema and segments[1] == "properties"
    )

    if change_type != "REMOVED" and _introduces_concealment(old_value, new_value):
        return (
            "CRITICAL",
            "Unicode concealment characters introduced: hidden content the operator never approved",
        )

    if last == "x-mcp-header":
        if change_type == "ADDED":
            return (
                "CRITICAL",
                "x-mcp-header binding added to a parameter: LLM-controlled input now reaches an HTTP header",
            )
        if change_type == "MODIFIED":
            return (
                "CRITICAL",
                "x-mcp-header binding modified: the header an LLM-controlled parameter feeds changed",
            )
        return ("LOW", "x-mcp-header binding removed")

    hint_reason = _hint_flip(path, old_value, new_value)
    if hint_reason is not None:
        return ("HIGH", hint_reason)

    # A parameter literally named ``required`` or ``description`` must be judged as
    # a parameter, not as the ``required`` list or a description string.
    if is_parameter_root:
        if change_type == "ADDED":
            return (
                "HIGH",
                "New parameter added to inputSchema: the tool's LLM-visible input surface grew",
            )
        if change_type == "REMOVED":
            return ("MEDIUM", "Parameter removed from inputSchema: the tool's input surface shrank")
        return (
            "MEDIUM",
            "Parameter schema modified: the declared shape of one parameter changed",
        )

    if path == "description":
        return (
            "HIGH",
            "Tool description modified after approval (tool poisoning: instructions the model trusts changed)",
        )

    if last == "description":
        return (
            "HIGH",
            "Parameter or schema description modified after approval (tool poisoning)",
        )

    if last == "required":
        if change_type == "REMOVED" or _is_relaxed_required(old_value, new_value):
            return ("HIGH", "required list relaxed: previously mandatory parameters are now optional")
        return ("MEDIUM", "required list changed: validation contract for callers changed")

    if last in DISPLAY_ONLY_FIELDS or segments[0] in DISPLAY_ONLY_FIELDS:
        return ("LOW", "Display-only metadata changed; behaviour and descriptions are unchanged")

    if segments[0] == "outputSchema":
        return ("MEDIUM", "outputSchema modified: the declared response contract changed")

    if segments[0] == "annotations":
        return ("MEDIUM", "Tool annotation modified")

    if segments[0] not in KNOWN_TOOL_FIELDS:
        return ("MEDIUM", "Unknown extension field modified (_meta or vendor extension)")

    if is_input_schema and len(segments) >= 4 and segments[1] == "properties":
        verb = {"ADDED": "added", "REMOVED": "removed"}.get(change_type, "changed")
        return ("MEDIUM", f"Parameter constraint {last!r} {verb}")

    if change_type == "ADDED":
        return ("MEDIUM", "Field added to the tool definition")
    if change_type == "REMOVED":
        return ("MEDIUM", "Field removed from the tool definition")
    return ("MEDIUM", "Tool definition field modified")


def _append_change(
    changes: list[FieldChange],
    path: str,
    change_type: ChangeType,
    old_value: Any,
    new_value: Any,
) -> None:
    severity, reason = _classify(path, change_type, old_value, new_value)
    changes.append(
        FieldChange(
            path=path,
            change_type=change_type,
            old_value=old_value,
            new_value=new_value,
            risk_reason=reason,
            severity=severity,
        )
    )

    node = new_value if change_type == "ADDED" else old_value
    if isinstance(node, dict):
        for key in sorted(node):
            child = f"{path}.{key}" if path else str(key)
            if change_type == "ADDED":
                _append_change(changes, child, "ADDED", None, node[key])
            else:
                _append_change(changes, child, "REMOVED", node[key], None)


def _walk(pinned: Any, current: Any, path: str, changes: list[FieldChange]) -> None:
    if isinstance(pinned, dict) and isinstance(current, dict):
        for key in sorted(set(pinned) | set(current)):
            child = f"{path}.{key}" if path else str(key)
            if key in pinned and key in current:
                _walk(pinned[key], current[key], child, changes)
            elif key in current:
                _append_change(changes, child, "ADDED", None, current[key])
            else:
                _append_change(changes, child, "REMOVED", pinned[key], None)
        return

    if pinned is None and isinstance(current, dict):
        _append_change(changes, path, "ADDED", None, current)
        return
    if current is None and isinstance(pinned, dict):
        _append_change(changes, path, "REMOVED", pinned, None)
        return

    if type(pinned) is type(current) and pinned == current:
        return

    # ``False == 0`` and ``True == 1`` in Python, so comparing values alone would
    # report a type-juggled default as "no change" and leave an empty LOW diff.
    _append_change(changes, path, "MODIFIED", pinned, current)


def diff_tool_definitions(
    pinned_canonical_json: str, current_tool: ToolDefinition
) -> tuple[list[FieldChange], Severity]:
    """Explain every difference between a pinned tool and ``current_tool``.

    Returns the field changes plus the highest severity among them (``LOW``
    when nothing changed).
    """

    try:
        pinned = json.loads(pinned_canonical_json)
    except json.JSONDecodeError as exc:
        raise ProbeError(f"pinned canonical JSON is not valid JSON: {exc}") from exc
    if not isinstance(pinned, dict):
        raise ProbeError("pinned canonical JSON must be a JSON object")

    changes: list[FieldChange] = []
    _walk(pinned, canonical_payload(current_tool), "", changes)

    return changes, highest_severity([change.severity for change in changes])
