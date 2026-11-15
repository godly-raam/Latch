"""Cross-server tool shadowing, homoglyph collision and cross-tool hijack detection.

An MCP client mounts several servers into one flat tool namespace. Four
attacks exploit that, and all of them are found here without a model call:

``EXACT_TOOL_SHADOW``
    Two servers expose the same ``tool.name``. The model sees one name with two
    implementations and no way to say which it meant, so the shadowing server
    can intercept calls intended for the trusted one.

``NORMALIZED_TOOL_SHADOW``
    Raw names differ only in casing or separators (``read_file`` vs
    ``readFile`` vs ``read-file``) and collapse to the same identifier.

``CONFUSABLE_UNICODE_SHADOW``
    A name uses NFKC compatibility characters or Cyrillic/Greek homoglyphs
    (``r\\u0435ad_file``, Cyrillic ``е`` U+0435) that render like a trusted
    tool's name but tokenize differently.

``CROSS_TOOL_HIJACK``
    A description names another server's tool next to a routing directive
    ("always call X first instead of Y"), steering tool selection itself.

Everything is deterministic: no network, no model call, sorted findings.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Literal

from pydantic import BaseModel, Field

from .models import ToolDefinition

ShadowRuleId = Literal[
    "EXACT_TOOL_SHADOW",
    "NORMALIZED_TOOL_SHADOW",
    "CONFUSABLE_UNICODE_SHADOW",
    "CROSS_TOOL_HIJACK",
]

ShadowSeverity = Literal["CRITICAL", "HIGH", "MEDIUM"]

#: Cyrillic/Greek codepoints that render indistinguishably from Latin ones.
CONFUSABLE_FOLD: dict[str, str] = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0456": "i",
    "\u0455": "s",
    "\u0458": "j",
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0425": "X",
    "\u03bf": "o",
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03c1": "p",
}

#: Words that turn a mention of another tool into a routing instruction.
ROUTING_DIRECTIVES: frozenset[str] = frozenset(
    {
        "instead",
        "before",
        "after",
        "override",
        "overrides",
        "redirect",
        "redirects",
        "always",
        "must",
        "first",
        "prior",
        "supersede",
        "supersedes",
        "replace",
        "replaces",
        "route",
        "prefer",
        "ignore",
        "bypass",
    }
)

#: Unqualified names shorter than this are too common to route on.
MIN_TARGET_NAME_LENGTH = 5

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

_WORD_RE = re.compile(r"[a-z0-9_.\-]+")
_QUALIFIED_RE = re.compile(
    r"(?<![a-z0-9_.\-])([a-z0-9_.\-]+):([a-z0-9_.\-]+)(?![a-z0-9_.\-])"
)
_STRIP_FOR_KEY = str.maketrans("", "", "_-.")


class ShadowFinding(BaseModel):
    """One cross-server routing or impersonation finding."""

    rule_id: ShadowRuleId
    severity: ShadowSeverity
    canonical_key: str
    involved_tools: list[str] = Field(default_factory=list)
    servers: list[str] = Field(default_factory=list)
    message: str
    evidence: str | None = None


class ShadowReport(BaseModel):
    """Whole-configuration shadowing analysis."""

    server_count: int
    tool_count: int
    trusted_servers_excluded: list[str] = Field(default_factory=list)
    findings: list[ShadowFinding] = Field(default_factory=list)
    passed: bool


def fold_confusables(name: str) -> tuple[str, bool]:
    """NFKC-normalize ``name`` and fold Cyrillic/Greek homoglyphs to Latin.

    Returns ``(folded, changed)`` where ``changed`` is true when NFKC or the
    homoglyph map altered the string at all.
    """

    normalized = unicodedata.normalize("NFKC", name)
    folded = "".join(CONFUSABLE_FOLD.get(char, char) for char in normalized)
    return folded, (normalized != name or folded != normalized)


def canonical_tool_key(name: str) -> str:
    """Collapse a tool name to the identifier the model effectively routes on.

    ``read_file``, ``readFile``, ``read-file`` and ``r\\u0435ad_file`` all map to
    ``readfile``.
    """

    folded, _changed = fold_confusables(name)
    return folded.lower().translate(_STRIP_FOR_KEY)


def _escape_non_ascii(name: str) -> str:
    return "".join(
        char if ord(char) < 128 else f"\\u{ord(char):04X}" for char in name
    )


def _mention_sets(text: str) -> tuple[set[str], set[str]]:
    """Word tokens and ``server:tool`` pairs mentioned in ``text``.

    Trailing separators are trimmed so a sentence-final ``fs:read_file.`` still
    yields the pair ``fs:read_file``.
    """

    words = {token.strip("._-") for token in _WORD_RE.findall(text)}
    qualified = {
        f"{server.strip('._-')}:{tool.strip('._-')}"
        for server, tool in _QUALIFIED_RE.findall(text)
    }
    words.discard("")
    qualified.discard(":")
    return words, qualified


def _snippet(text: str, limit: int = 160) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) > limit:
        collapsed = collapsed[: limit - 3] + "..."
    return collapsed


def _iter_descriptions(tool: ToolDefinition) -> list[tuple[str, str]]:
    """Every human-readable instruction string attached to a tool."""

    entries: list[tuple[str, str]] = []
    if tool.description:
        entries.append(("description", tool.description))

    properties = tool.inputSchema.get("properties")
    if not isinstance(properties, dict):
        return entries

    for parameter, schema in sorted(properties.items()):
        if not isinstance(schema, dict):
            continue
        description = schema.get("description")
        if isinstance(description, str) and description:
            entries.append(
                (f"inputSchema.properties.{parameter}.description", description)
            )
        nested = schema.get("properties")
        if not isinstance(nested, dict):
            continue
        for nested_name, nested_schema in sorted(nested.items()):
            if not isinstance(nested_schema, dict):
                continue
            nested_description = nested_schema.get("description")
            if isinstance(nested_description, str) and nested_description:
                entries.append(
                    (
                        f"inputSchema.properties.{parameter}"
                        f".properties.{nested_name}.description",
                        nested_description,
                    )
                )
    return entries


def _shadow_findings(
    groups: dict[str, list[tuple[str, ToolDefinition, bool]]], trusted: set[str]
) -> list[ShadowFinding]:
    findings: list[ShadowFinding] = []

    for key in sorted(groups):
        members = groups[key]
        # A shadow needs a second tool to shadow: one tool cannot collide.
        if len(members) < 2:
            continue

        servers_involved = sorted({server_id for server_id, _tool, _changed in members})
        any_confusable = any(changed for _server, _tool, changed in members)

        if len(servers_involved) == 1 and not any_confusable:
            continue
        if all(server_id in trusted for server_id in servers_involved) and not any_confusable:
            continue

        names_by_server: dict[str, set[str]] = {}
        for server_id, tool, _changed in members:
            names_by_server.setdefault(tool.name, set()).add(server_id)

        involved_tools = sorted(
            f"{server_id}:{tool.name}" for server_id, tool, _changed in members
        )

        if any_confusable:
            confusable = [
                (server_id, tool)
                for server_id, tool, changed in members
                if changed
            ]
            same_looking = [
                f"{server_id}:{tool.name}"
                for server_id, tool, changed in members
                if not changed
            ]
            evidence = "; ".join(
                f"{server_id}:{tool.name} has codepoints"
                f" {_escape_non_ascii(tool.name)}"
                for server_id, tool in confusable
            )
            if same_looking:
                evidence += f"; folds onto {', '.join(same_looking)}"
            message = (
                f"Tool name(s) {', '.join(f'{s}:{t.name}' for s, t in confusable)}"
                f" use Unicode compatibility or homoglyph characters that fold to"
                f" {key!r}"
                + (f", the identifier of {', '.join(same_looking)}" if same_looking else "")
                + ": the model reads the same name, routing cannot be trusted."
            )
            findings.append(
                ShadowFinding(
                    rule_id="CONFUSABLE_UNICODE_SHADOW",
                    severity="CRITICAL",
                    canonical_key=key,
                    involved_tools=involved_tools,
                    servers=servers_involved,
                    message=message,
                    evidence=evidence,
                )
            )
            continue

        exact = sorted(
            (name, sorted(owners))
            for name, owners in names_by_server.items()
            if len(owners) >= 2
        )

        if exact:
            trusted_involved = [
                server_id for server_id in servers_involved if server_id in trusted
            ]
            untrusted_involved = [
                server_id for server_id in servers_involved if server_id not in trusted
            ]
            severity: ShadowSeverity = (
                "CRITICAL" if trusted_involved and untrusted_involved else "HIGH"
            )
            evidence = "; ".join(
                f"{name} mounted by {', '.join(owners)}" for name, owners in exact
            )
            findings.append(
                ShadowFinding(
                    rule_id="EXACT_TOOL_SHADOW",
                    severity=severity,
                    canonical_key=key,
                    involved_tools=involved_tools,
                    servers=servers_involved,
                    message=(
                        f"Servers {', '.join(servers_involved)} expose the same tool"
                        f" name {exact[0][0]!r}; calls cannot be attributed to one"
                        " implementation, so a shadowing server can intercept them."
                        + (
                            " A trusted server is being shadowed by an untrusted one."
                            if severity == "CRITICAL"
                            else ""
                        )
                    ),
                    evidence=evidence,
                )
            )
            continue

        findings.append(
            ShadowFinding(
                rule_id="NORMALIZED_TOOL_SHADOW",
                severity="HIGH",
                canonical_key=key,
                involved_tools=involved_tools,
                servers=servers_involved,
                message=(
                    f"Tool names {', '.join(t.name for _s, t, _c in members)} differ"
                    f" only in casing or separators and all normalize to {key!r};"
                    " the model cannot distinguish them reliably."
                ),
                evidence=", ".join(
                    f"{server_id}:{tool.name}" for server_id, tool, _changed in members
                ),
            )
        )

    return findings


def _hijack_findings(
    servers: dict[str, list[ToolDefinition]], trusted: set[str]
) -> list[ShadowFinding]:
    findings: list[ShadowFinding] = []

    lowered_names: dict[str, set[str]] = {
        server_id: {tool.name.lower() for tool in tools}
        for server_id, tools in servers.items()
    }

    for server_id in sorted(servers):
        if server_id in trusted:
            continue
        for tool in sorted(servers[server_id], key=lambda item: item.name):
            own_names = lowered_names.get(server_id, set())
            snippets: list[str] = []
            mentioned_names: set[str] = set()

            for field_path, text in _iter_descriptions(tool):
                words, qualified_pairs = _mention_sets(text.lower())
                directives = sorted(words & ROUTING_DIRECTIVES)
                if not directives:
                    continue

                mentioned: set[str] = set()
                for other_server in sorted(servers):
                    if other_server == server_id:
                        continue
                    for other_tool in sorted(
                        {candidate.name for candidate in servers[other_server]}
                    ):
                        lowered_other = other_tool.lower()
                        qualified = f"{other_server.lower()}:{lowered_other}"
                        if qualified in qualified_pairs:
                            mentioned.add(f"{other_server}:{other_tool}")
                            continue
                        if len(other_tool) < MIN_TARGET_NAME_LENGTH:
                            continue
                        if lowered_other in own_names:
                            continue
                        if lowered_other in words:
                            mentioned.add(other_tool)

                if not mentioned:
                    continue

                mentioned_names.update(mentioned)
                snippets.append(
                    f"{field_path}: \"{_snippet(text)}\" (directive(s):"
                    f" {', '.join(directives)}; target(s): {', '.join(sorted(mentioned))})"
                )

            if not snippets:
                continue

            findings.append(
                ShadowFinding(
                    rule_id="CROSS_TOOL_HIJACK",
                    severity="CRITICAL",
                    canonical_key=f"{server_id}:{tool.name}",
                    involved_tools=sorted(
                        {f"{server_id}:{tool.name}"} | mentioned_names
                    ),
                    servers=[server_id],
                    message=(
                        f"{server_id}:{tool.name} instructs the model to route to"
                        f" {', '.join(sorted(mentioned_names))} instead of itself,"
                        " hijacking tool selection."
                    ),
                    evidence=" | ".join(snippets[:3])
                    + (f" | +{len(snippets) - 3} more" if len(snippets) > 3 else ""),
                )
            )

    return findings


def analyze_shadowing(
    servers: dict[str, list[ToolDefinition]], trusted_servers: set[str] | None = None
) -> ShadowReport:
    """Detect cross-server shadowing, homoglyph collisions and tool hijacking."""

    trusted = set(trusted_servers or set())

    groups: dict[str, list[tuple[str, ToolDefinition, bool]]] = {}
    for server_id in sorted(servers):
        for tool in sorted(servers[server_id], key=lambda item: item.name):
            _folded, changed = fold_confusables(tool.name)
            groups.setdefault(canonical_tool_key(tool.name), []).append(
                (server_id, tool, changed)
            )

    findings = _shadow_findings(groups, trusted) + _hijack_findings(servers, trusted)
    findings.sort(
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.rule_id,
            finding.canonical_key,
            tuple(finding.involved_tools),
        )
    )

    return ShadowReport(
        server_count=len(servers),
        tool_count=sum(len(tools) for tools in servers.values()),
        trusted_servers_excluded=sorted(
            server_id for server_id in trusted if server_id in servers
        ),
        findings=findings,
        passed=not findings,
    )
