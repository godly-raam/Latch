"""SARIF 2.1.0 export.

SARIF is what CI systems, GitHub code scanning and security dashboards ingest.
Latch maps every finding onto it without inventing new severities: drift, audit
findings and lethal-trifecta chains become results, with CWE tags attached so
the report is actionable outside this tool.

Levels follow SARIF's own vocabulary:

``CRITICAL`` / ``HIGH`` -> ``error``, ``MEDIUM`` -> ``warning``, ``LOW`` -> ``note``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from . import __version__
from .auditor import AuditReport
from .chain_prober import ChainVerificationReport
from .graph import GraphReport
from .lockfile import VerificationReport
from .oauth_audit import AuthAuditReport
from .shadow import ShadowReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

#: Used when the scanned target was a live stdio/HTTP server, not a file.
LIVE_TARGET_URI = "mcp://live-target"

_LEVEL_BY_SEVERITY = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_DRIFT_RULE_IDS = {
    "ADDED_TOOL": "LATCH-DRIFT-ADDED",
    "REMOVED_TOOL": "LATCH-DRIFT-REMOVED",
    "MODIFIED_TOOL": "LATCH-DRIFT-MODIFIED",
}

_TRIFECTA_RULE_ID = "LATCH-GRAPH-TRIFECTA"

_RULES: dict[str, dict[str, Any]] = {
    "LATCH-DRIFT-ADDED": {
        "name": "ToolAddedAfterPin",
        "short": "Tool added after the lockfile was pinned",
        "full": (
            "The live server exposes a tool that is absent from the approved"
            " lockfile, expanding the LLM-visible tool surface."
        ),
        "tags": ["CWE-345", "CWE-284"],
        "level": "error",
    },
    "LATCH-DRIFT-REMOVED": {
        "name": "ToolRemovedAfterPin",
        "short": "Tool removed after the lockfile was pinned",
        "full": "A tool present in the approved lockfile is no longer served.",
        "tags": ["CWE-345"],
        "level": "note",
    },
    "LATCH-DRIFT-MODIFIED": {
        "name": "ToolModifiedAfterPin",
        "short": "Tool definition changed after approval",
        "full": (
            "The tool's canonical SHA-256 no longer matches the pin: description,"
            " schema, annotations or extension fields changed (rug pull)."
        ),
        "tags": ["CWE-345", "CWE-116"],
        "level": "error",
    },
    "LATCH-AUDIT-UNICODE_TAG_BLOCK": {
        "name": "UnicodeTagBlock",
        "short": "Invisible Unicode tag-block characters",
        "full": (
            "Codepoints U+E0000-U+E007F render as nothing but are tokenized by the"
            " model, allowing concealed prompt injection."
        ),
        "tags": ["CWE-116", "CWE-74"],
        "level": "error",
    },
    "LATCH-AUDIT-UNICODE_BIDI_OVERRIDE": {
        "name": "UnicodeBidiOverride",
        "short": "Bidirectional control characters",
        "full": "BiDi controls can visually reorder metadata so it reads differently than reviewed.",
        "tags": ["CWE-116", "CWE-74"],
        "level": "error",
    },
    "LATCH-AUDIT-UNICODE_ZERO_WIDTH": {
        "name": "UnicodeZeroWidth",
        "short": "Zero-width or BOM characters",
        "full": "Zero-width characters hide markers inside otherwise identical-looking text.",
        "tags": ["CWE-116"],
        "level": "warning",
    },
    "LATCH-AUDIT-HEADER_PRIVILEGED_INJECTION": {
        "name": "PrivilegedHeaderBinding",
        "short": "x-mcp-header bound to a privileged HTTP header",
        "full": (
            "An LLM-controlled parameter feeds a privileged header such as"
            " Authorization, Cookie or X-Forwarded-For."
        ),
        "tags": ["CWE-74", "CWE-284"],
        "level": "error",
    },
    "LATCH-AUDIT-HEADER_CRLF_CONTROL": {
        "name": "HeaderControlCharacters",
        "short": "Control characters in an x-mcp-header value",
        "full": "CR/LF/NUL in a header binding enables HTTP header splitting.",
        "tags": ["CWE-74", "CWE-93"],
        "level": "error",
    },
    "LATCH-AUDIT-HEADER_SPEC_VIOLATION": {
        "name": "HeaderSpecViolation",
        "short": "x-mcp-header violates MCP 2026-07-28 rules",
        "full": (
            "Header names must be unique, non-empty strings and may only bind"
            " string, integer or boolean parameters."
        ),
        "tags": ["CWE-284", "CWE-20"],
        "level": "error",
    },
    "LATCH-AUDIT-TOOL_NAME_SPEC_VIOLATION": {
        "name": "ToolNameSpecViolation",
        "short": "Tool name violates the MCP naming pattern",
        "full": "Names must match ^[A-Za-z0-9_.-]{1,128}$.",
        "tags": ["CWE-284"],
        "level": "warning",
    },
    "LATCH-AUDIT-ANNOTATION_CONTRADICTION": {
        "name": "AnnotationContradiction",
        "short": "Contradictory tool annotations",
        "full": (
            "readOnlyHint=true alongside destructiveHint=true or x-mcp-header"
            " bindings: the declared safety contract does not hold."
        ),
        "tags": ["CWE-284", "CWE-345"],
        "level": "warning",
    },
    _TRIFECTA_RULE_ID: {
        "name": "LethalTrifecta",
        "short": "Lethal-trifecta exfiltration chain",
        "full": (
            "Untrusted input, private data read and external egress line up in one"
            " chain, letting third-party content drive private data out of the agent."
        ),
        "tags": ["CWE-284", "CWE-200"],
        "level": "error",
    },
    "LATCH-SHADOW-EXACT_TOOL_SHADOW": {
        "name": "ExactToolShadow",
        "short": "Two servers mount the same tool name",
        "full": (
            "Duplicate tool names across servers make routing ambiguous: a"
            " shadowing server can intercept calls meant for another server."
        ),
        "tags": ["security", "CWE-284"],
        "level": "error",
    },
    "LATCH-SHADOW-NORMALIZED_TOOL_SHADOW": {
        "name": "NormalizedToolShadow",
        "short": "Tool names collide after normalization",
        "full": (
            "Names differing only in casing or separators (read_file vs readFile)"
            " collapse to one identifier, so the model cannot tell them apart."
        ),
        "tags": ["security", "CWE-284"],
        "level": "error",
    },
    "LATCH-SHADOW-CONFUSABLE_UNICODE_SHADOW": {
        "name": "ConfusableUnicodeShadow",
        "short": "Homoglyph tool name impersonation",
        "full": (
            "NFKC compatibility characters or Cyrillic/Greek homoglyphs render"
            " like another tool's name while tokenizing differently."
        ),
        "tags": ["security", "CWE-1007", "CWE-116"],
        "level": "error",
    },
    "LATCH-SHADOW-CROSS_TOOL_HIJACK": {
        "name": "CrossToolHijack",
        "short": "Description redirects tool selection to another server",
        "full": (
            "A tool description names another server's tool alongside a routing"
            " directive, hijacking which tool the model chooses."
        ),
        "tags": ["security", "CWE-74", "CWE-284"],
        "level": "error",
    },
    "LATCH-AUTH-HARDCODED_STATIC_CREDENTIAL": {
        "name": "HardcodedStaticCredential",
        "short": "Literal credential committed to configuration",
        "full": (
            "A header or environment entry carries a real credential instead of"
            " an environment reference, so the secret lives in the repository."
        ),
        "tags": ["security", "CWE-798"],
        "level": "error",
    },
    "LATCH-AUTH-CROSS_SERVER_CREDENTIAL_REUSE": {
        "name": "CrossServerCredentialReuse",
        "short": "Same credential shared by multiple servers",
        "full": (
            "Two or more servers present the same credential, so one compromised"
            " server can replay it against the others (confused deputy)."
        ),
        "tags": ["security", "CWE-284", "CWE-441"],
        "level": "error",
    },
    "LATCH-AUTH-INSECURE_HTTP_AUTH_TRANSPORT": {
        "name": "InsecureHttpAuthTransport",
        "short": "Credentials sent over cleartext HTTP",
        "full": (
            "A non-loopback MCP server is reached over http:// while credentials"
            " are configured or probed, exposing them to anyone on the path."
        ),
        "tags": ["security", "CWE-319"],
        "level": "error",
    },
    "LATCH-AUTH-TOKEN_PASSTHROUGH_RISK": {
        "name": "TokenPassthroughRisk",
        "short": "OAuth token accepted as a tool argument",
        "full": (
            "A tool takes an access/refresh token as a parameter or header"
            " binding, allowing user tokens to be forwarded upstream."
        ),
        "tags": ["security", "CWE-441", "CWE-287"],
        "level": "error",
    },
    "LATCH-AUTH-OPEN_UNAUTHENTICATED_REMOTE_MCP": {
        "name": "OpenUnauthenticatedRemoteMcp",
        "short": "Remote MCP server accepts unauthenticated calls",
        "full": (
            "A non-loopback MCP endpoint answers requests without any"
            " authentication challenge."
        ),
        "tags": ["security", "CWE-306"],
        "level": "error",
    },
    "LATCH-AUTH-MISSING_WWW_AUTHENTICATE_PRM": {
        "name": "MissingWwwAuthenticatePrm",
        "short": "401 challenge omits resource_metadata",
        "full": (
            "The server rejects unauthenticated calls but does not point clients"
            " at its protected-resource metadata, so audiences cannot be bound."
        ),
        "tags": ["security", "CWE-287"],
        "level": "error",
    },
    "LATCH-AUTH-MISSING_PROTECTED_RESOURCE_METADATA": {
        "name": "MissingProtectedResourceMetadata",
        "short": "No RFC 9728 protected-resource metadata",
        "full": (
            "The server publishes no usable /.well-known/oauth-protected-resource"
            " document, so clients cannot discover the canonical resource."
        ),
        "tags": ["security", "CWE-287"],
        "level": "warning",
    },
    "LATCH-CHAIN-CONFIRMED": {
        "name": "ConfirmedExploitableChain",
        "short": "Lethal-trifecta chain confirmed at runtime",
        "full": (
            "A read tool returned data and an egress tool forwarded the canary"
            " payload to a loopback sink, so the static chain is exploitable."
        ),
        "tags": ["security", "CWE-200", "CWE-284"],
        "level": "error",
    },
    "LATCH-AUTH-PRM_RESOURCE_MISMATCH": {
        "name": "PrmResourceMismatch",
        "short": "Metadata resource does not match the endpoint",
        "full": (
            "The advertised resource points at a different scheme, host or path"
            " than the server actually reached, enabling token substitution."
        ),
        "tags": ["security", "CWE-290", "CWE-441"],
        "level": "error",
    },
}

_FALLBACK_META: dict[str, Any] = {
    "name": "UnknownRule",
    "short": "Unrecognized Latch rule",
    "full": "Reported by Latch with default metadata.",
    "tags": ["CWE-345"],
    "level": "warning",
}


def severity_to_level(severity: str) -> str:
    """Map a Latch severity onto a SARIF result level."""

    return _LEVEL_BY_SEVERITY.get(severity, "warning")


def _rule_definition(rule_id: str) -> dict[str, Any]:
    meta = _RULES.get(rule_id, _FALLBACK_META)
    return {
        "id": rule_id,
        "name": meta["name"],
        "shortDescription": {"text": meta["short"]},
        "fullDescription": {"text": meta["full"]},
        "defaultConfiguration": {"level": meta["level"]},
        "properties": {"tags": list(meta["tags"])},
    }


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


def _result(
    rule_id: str,
    severity: str,
    message: str,
    artifact_uri: str,
    properties: dict[str, Any],
) -> dict[str, Any]:
    tags = list(_RULES.get(rule_id, _FALLBACK_META)["tags"])
    return {
        "ruleId": rule_id,
        "level": severity_to_level(severity),
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}
        ],
        "partialFingerprints": {
            "latch/v1": _fingerprint(
                rule_id,
                artifact_uri,
                str(properties.get("toolName", "")),
                str(properties.get("pathId", "")),
                str(properties.get("fieldPath", "")),
            )
        },
        "properties": {**properties, "severity": severity, "tags": tags},
    }


def _drift_message(item: Any) -> str:
    message = f"{item.kind.value} {item.tool_name} [{item.severity}]"
    if item.changes:
        rendered = ", ".join(
            f"{change.change_type} {change.path}" for change in item.changes[:5]
        )
        if len(item.changes) > 5:
            rendered += f", +{len(item.changes) - 5} more"
        message += f": {rendered}"
    return message


def to_sarif(
    *,
    verifications: Sequence[VerificationReport] = (),
    audits: Sequence[AuditReport] = (),
    graphs: Sequence[GraphReport] = (),
    shadow: ShadowReport | None = None,
    auth: AuthAuditReport | None = None,
    chain: ChainVerificationReport | None = None,
    artifact_uri: str = LIVE_TARGET_URI,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from any combination of Latch reports."""

    results: list[dict[str, Any]] = []

    for report in verifications:
        for item in report.drift:
            rule_id = _DRIFT_RULE_IDS.get(item.kind.value, "LATCH-DRIFT-MODIFIED")
            results.append(
                _result(
                    rule_id,
                    item.severity,
                    _drift_message(item),
                    artifact_uri,
                    {"kind": item.kind.value, "toolName": item.tool_name},
                )
            )

    for report in audits:
        for finding in report.findings:
            rule_id = f"LATCH-AUDIT-{finding.rule_id}"
            message = f"{finding.rule_id}: {finding.message}"
            if finding.evidence:
                message += f" (evidence: {finding.evidence})"
            results.append(
                _result(
                    rule_id,
                    finding.severity,
                    message,
                    artifact_uri,
                    {"toolName": finding.tool_name, "fieldPath": finding.field_path},
                )
            )

    for report in graphs:
        for path in report.trifecta_paths:
            results.append(
                _result(
                    _TRIFECTA_RULE_ID,
                    path.severity,
                    path.attack_narrative,
                    artifact_uri,
                    {
                        "pathId": path.path_id,
                        "toolName": path.ingest_tool,
                        "servers": path.servers,
                        "crossServer": path.cross_server,
                        "ingestTool": path.ingest_tool,
                        "readTool": path.read_tool,
                        "egressTool": path.egress_tool,
                    },
                )
            )

    if shadow is not None:
        for finding in shadow.findings:
            rule_id = f"LATCH-SHADOW-{finding.rule_id}"
            message = f"{finding.rule_id}: {finding.message}"
            if finding.evidence:
                message += f" (evidence: {finding.evidence})"
            results.append(
                _result(
                    rule_id,
                    finding.severity,
                    message,
                    artifact_uri,
                    {
                        "toolName": (
                            finding.involved_tools[0]
                            if finding.involved_tools
                            else finding.canonical_key
                        ),
                        "pathId": finding.canonical_key,
                        "shadowRule": finding.rule_id,
                        "servers": finding.servers,
                        "involvedTools": finding.involved_tools,
                    },
                )
            )

    if auth is not None:
        for finding in auth.findings:
            rule_id = f"LATCH-AUTH-{finding.rule_id}"
            message = f"{finding.rule_id}: {finding.message}"
            if finding.evidence:
                message += f" (evidence: {finding.evidence})"
            results.append(
                _result(
                    rule_id,
                    finding.severity,
                    message,
                    artifact_uri,
                    {
                        "toolName": (
                            finding.servers[0] if finding.servers else ""
                        ),
                        "pathId": finding.field_path,
                        "authRule": finding.rule_id,
                        "servers": finding.servers,
                        "fieldPath": finding.field_path,
                    },
                )
            )

    if chain is not None:
        for probe in chain.results:
            if probe.status != "CONFIRMED_EXPLOITABLE":
                continue
            message = (
                f"Confirmed exploitable chain {probe.path_id}:"
                f" {probe.ingest_tool} -> {probe.read_tool} -> {probe.egress_tool}"
                f" reached {probe.sink_request_summary or 'the canary sink'}"
                " with a live canary token."
            )
            results.append(
                _result(
                    "LATCH-CHAIN-CONFIRMED",
                    probe.verified_severity,
                    message,
                    artifact_uri,
                    {
                        "pathId": probe.path_id,
                        "toolName": probe.ingest_tool,
                        "servers": [],
                        "chainStatus": probe.status,
                        "canaryToken": probe.canary_token,
                        "sink": probe.sink_request_summary,
                    },
                )
            )

    rule_ids = sorted({str(result["ruleId"]) for result in results})

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Latch",
                        "semanticVersion": __version__,
                        "rules": [_rule_definition(rule_id) for rule_id in rule_ids],
                    }
                },
                "results": results,
            }
        ],
    }
