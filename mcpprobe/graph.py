"""Deterministic Lethal-Trifecta capability graph analyzer.

A "lethal trifecta" needs three capabilities to line up:

1. ``UNTRUSTED_INPUT`` -- third-party content enters the model context,
2. ``PRIVATE_DATA_READ`` -- sensitive local/tenant data is readable,
3. ``EXTERNAL_EGRESS`` -- data can leave to an attacker-chosen destination.

Any chain ``ingest -> read -> egress`` is an exfiltration path. Latch finds
them across servers, ranks them, and explains the attack.

Everything here is rule-based and deterministic: identifiers are *tokenized*
(``readFile`` -> ``read``, ``file``), never substring-matched, so a tool called
``asset_manager`` cannot masquerade as ``ssh`` access. No model call, no
network, no random ordering.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from .auditor import iter_header_bindings
from .models import ToolDefinition

CapabilityTag = Literal["UNTRUSTED_INPUT", "PRIVATE_DATA_READ", "EXTERNAL_EGRESS"]

CAPABILITY_ORDER: tuple[CapabilityTag, ...] = (
    "UNTRUSTED_INPUT",
    "PRIVATE_DATA_READ",
    "EXTERNAL_EGRESS",
)

INGEST_VERBS = frozenset(
    {
        "get",
        "read",
        "fetch",
        "list",
        "search",
        "find",
        "query",
        "browse",
        "scrape",
        "crawl",
        "load",
        "pull",
        "receive",
        "inspect",
        "view",
    }
)

EXTERNAL_CONTENT_NOUNS = frozenset(
    {
        "issue",
        "issues",
        "pr",
        "pull",
        "comment",
        "comments",
        "email",
        "mail",
        "inbox",
        "message",
        "messages",
        "slack",
        "discord",
        "ticket",
        "web",
        "webpage",
        "page",
        "html",
        "url",
        "uri",
        "link",
        "feed",
        "rss",
        "search",
        "browser",
        "scrape",
        "crawl",
        "webhook",
        "event",
        "log",
        "logs",
        "review",
        "document",
        "doc",
    }
)

READ_VERBS = frozenset(
    {
        "get",
        "read",
        "list",
        "query",
        "select",
        "find",
        "search",
        "dump",
        "export",
        "inspect",
        "show",
        "cat",
        "load",
        "fetch",
        "balance",
        "ledger",
    }
)

SENSITIVE_TOKENS = frozenset(
    {
        "file",
        "files",
        "filesystem",
        "dir",
        "directory",
        "path",
        "env",
        "dotenv",
        "secret",
        "secrets",
        "token",
        "tokens",
        "credential",
        "credentials",
        "key",
        "keys",
        "ssh",
        "wallet",
        "account",
        "accounts",
        "transaction",
        "transactions",
        "payment",
        "db",
        "database",
        "sql",
        "postgres",
        "mysql",
        "sqlite",
        "mongo",
        "redis",
        "vault",
        "kms",
        "customer",
        "customers",
        "user",
        "users",
        "profile",
        "pii",
        "private",
        "internal",
        "memory",
        "config",
    }
)

OUTBOUND_VERBS = frozenset(
    {
        "send",
        "post",
        "put",
        "patch",
        "upload",
        "publish",
        "create",
        "reply",
        "forward",
        "share",
        "invite",
        "email",
        "mail",
        "message",
        "notify",
        "alert",
        "webhook",
        "push",
        "transfer",
        "pay",
        "execute",
        "exec",
        "run",
        "shell",
        "bash",
        "curl",
        "http",
        "request",
        "write",
        "append",
        "update",
    }
)

EXTERNAL_TARGETS = frozenset(
    {
        "url",
        "uri",
        "webhook",
        "endpoint",
        "http",
        "https",
        "recipient",
        "to",
        "cc",
        "bcc",
        "email",
        "channel",
        "slack",
        "discord",
        "issue",
        "comment",
        "pr",
        "gist",
        "repo",
        "bucket",
        "s3",
        "external",
        "remote",
    }
)

OUTBOUND_SINK_PARAMS = frozenset(
    {
        "webhook",
        "webhook_url",
        "callback_url",
        "recipient",
        "to",
        "cc",
        "bcc",
        "target_url",
        "destination_url",
    }
)

#: Parameters that let a caller choose *where* data goes (used for severity).
ARBITRARY_DESTINATION_PARAMS = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "webhook",
        "webhook_url",
        "callback_url",
        "target_url",
        "destination_url",
        "recipient",
        "to",
        "cc",
        "bcc",
    }
)

#: Parameters that carry the payload being sent (used with a destination param).
PAYLOAD_PARAMS = frozenset(
    {"body", "data", "content", "payload", "query", "text", "message", "params"}
)

RESOURCE_IDENTIFIER_PARAMS = frozenset(
    {"path", "file", "query", "sql", "id", "account_id", "user_id"}
)

_CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


class CapabilityEvidence(BaseModel):
    """Why a tool received a capability tag."""

    tag: CapabilityTag
    signal: str
    weight: float
    detail: str


class ToolNode(BaseModel):
    """One tool in the capability graph."""

    qualified_name: str
    server_id: str
    tool_name: str
    capabilities: list[CapabilityTag] = Field(default_factory=list)
    evidence: list[CapabilityEvidence] = Field(default_factory=list)
    annotations: dict[str, Any] | None = None


class FlowEdge(BaseModel):
    """A directed capability step between two tools."""

    source: str
    target: str
    stage: Literal["INGEST_TO_READ", "READ_TO_EGRESS"]
    cross_server: bool


class TrifectaPath(BaseModel):
    """A complete ingest -> read -> egress exfiltration chain."""

    path_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    cross_server: bool
    servers: list[str]
    ingest_tool: str
    read_tool: str
    egress_tool: str
    attack_narrative: str


class GraphReport(BaseModel):
    """Whole-configuration capability analysis."""

    server_count: int
    tool_count: int
    trusted_servers_excluded: list[str] = Field(default_factory=list)
    nodes: list[ToolNode] = Field(default_factory=list)
    edges: list[FlowEdge] = Field(default_factory=list)
    trifecta_paths: list[TrifectaPath] = Field(default_factory=list)
    passed: bool


def tokenize_identifier(value: str) -> list[str]:
    """Split an identifier into lowercase word tokens.

    Handles camelCase, PascalCase, snake_case, kebab-case and dotted names.
    Matching later happens on whole tokens only, never on substrings.
    """

    tokens: list[str] = []
    for chunk in _SPLIT_RE.split(value):
        if not chunk:
            continue
        tokens.extend(part.lower() for part in _CAMEL_RE.findall(chunk))
    return tokens


def _parameter_names(tool: ToolDefinition) -> list[str]:
    properties = tool.inputSchema.get("properties")
    if not isinstance(properties, dict):
        return []
    return [str(name) for name in properties]


def _tool_tokens(tool: ToolDefinition) -> set[str]:
    tokens = set(tokenize_identifier(tool.name))
    for parameter in _parameter_names(tool):
        tokens.update(tokenize_identifier(parameter))
    return tokens


def _lowered_params(tool: ToolDefinition) -> set[str]:
    return {name.lower() for name in _parameter_names(tool)}


def has_header_binding(tool: ToolDefinition) -> bool:
    """True when any parameter carries an ``x-mcp-header`` binding."""

    return next(iter_header_bindings(tool.inputSchema), None) is not None


def has_arbitrary_destination(tool: ToolDefinition) -> bool:
    """True when the caller can choose where data is sent."""

    if has_header_binding(tool):
        return True
    return bool(_lowered_params(tool) & ARBITRARY_DESTINATION_PARAMS)


def _add(
    capabilities: list[CapabilityTag],
    evidence: list[CapabilityEvidence],
    tag: CapabilityTag,
    signal: str,
    weight: float,
    detail: str,
) -> None:
    if tag not in capabilities:
        capabilities.append(tag)
    evidence.append(CapabilityEvidence(tag=tag, signal=signal, weight=weight, detail=detail))


def classify_tool(server_id: str, tool: ToolDefinition) -> ToolNode:
    """Classify one tool into zero, one, or several capability roles."""

    tokens = _tool_tokens(tool)
    params = _lowered_params(tool)
    annotations = tool.annotations or {}

    capabilities: list[CapabilityTag] = []
    evidence: list[CapabilityEvidence] = []

    # -- UNTRUSTED_INPUT ---------------------------------------------------
    ingest_verbs = sorted(tokens & INGEST_VERBS)
    content_nouns = sorted(tokens & EXTERNAL_CONTENT_NOUNS)
    if ingest_verbs and content_nouns:
        _add(
            capabilities,
            evidence,
            "UNTRUSTED_INPUT",
            "identifier.ingest_pair",
            1.0,
            f"ingestion verb(s) {ingest_verbs} paired with external content noun(s)"
            f" {content_nouns}",
        )

    open_world = annotations.get("openWorldHint") is True
    if open_world and annotations.get("destructiveHint") is not True:
        _add(
            capabilities,
            evidence,
            "UNTRUSTED_INPUT",
            "annotation.openWorldHint",
            0.8,
            "openWorldHint=true and not destructive: the tool reaches third-party content",
        )

    # -- PRIVATE_DATA_READ -------------------------------------------------
    read_verbs = sorted(tokens & READ_VERBS)
    sensitive = sorted(tokens & SENSITIVE_TOKENS)
    if read_verbs and sensitive:
        _add(
            capabilities,
            evidence,
            "PRIVATE_DATA_READ",
            "identifier.read_pair",
            1.0,
            f"read/query verb(s) {read_verbs} paired with sensitive resource token(s)"
            f" {sensitive}",
        )

    if (
        annotations.get("readOnlyHint") is True
        and annotations.get("openWorldHint") is False
        and params & RESOURCE_IDENTIFIER_PARAMS
    ):
        _add(
            capabilities,
            evidence,
            "PRIVATE_DATA_READ",
            "annotation.readOnlyClosedWorld",
            0.6,
            "readOnlyHint=true with openWorldHint=false and a resource identifier"
            f" parameter {sorted(params & RESOURCE_IDENTIFIER_PARAMS)}",
        )

    # -- EXTERNAL_EGRESS ---------------------------------------------------
    outbound_verbs = sorted(tokens & OUTBOUND_VERBS)
    external_targets = sorted(tokens & EXTERNAL_TARGETS)
    if outbound_verbs and external_targets:
        _add(
            capabilities,
            evidence,
            "EXTERNAL_EGRESS",
            "identifier.egress_pair",
            1.0,
            f"outbound/mutating verb(s) {outbound_verbs} paired with external target(s)"
            f" {external_targets}",
        )

    sinks = sorted(params & OUTBOUND_SINK_PARAMS)
    if sinks:
        _add(
            capabilities,
            evidence,
            "EXTERNAL_EGRESS",
            "schema.outbound_sink",
            0.9,
            f"inputSchema declares an outbound sink parameter {sinks}",
        )

    if has_header_binding(tool):
        _add(
            capabilities,
            evidence,
            "EXTERNAL_EGRESS",
            "schema.x-mcp-header",
            1.0,
            "parameter values are bound to an HTTP header via x-mcp-header",
        )

    if open_world and annotations.get("readOnlyHint") is not True:
        _add(
            capabilities,
            evidence,
            "EXTERNAL_EGRESS",
            "annotation.openWorldEgress",
            0.8,
            "openWorldHint=true without readOnlyHint: the tool can reach external systems",
        )

    if params & ARBITRARY_DESTINATION_PARAMS and params & PAYLOAD_PARAMS:
        _add(
            capabilities,
            evidence,
            "EXTERNAL_EGRESS",
            "schema.arbitrary_destination_payload",
            0.7,
            "inputSchema accepts both a caller-chosen destination and a payload to send",
        )

    capabilities.sort(key=CAPABILITY_ORDER.index)

    return ToolNode(
        qualified_name=f"{server_id}:{tool.name}",
        server_id=server_id,
        tool_name=tool.name,
        capabilities=capabilities,
        evidence=evidence,
        annotations=dict(annotations) if annotations else None,
    )


def _build_path(
    ingest: ToolNode, read: ToolNode, egress: ToolNode, egress_tool: ToolDefinition
) -> TrifectaPath:
    servers = sorted({ingest.server_id, read.server_id, egress.server_id})
    cross_server = len(servers) >= 2
    arbitrary_sink = has_arbitrary_destination(egress_tool)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    if cross_server or arbitrary_sink:
        severity = "CRITICAL"
    else:
        severity = "HIGH"

    narrative = (
        f"{ingest.qualified_name} pulls untrusted third-party content into the model context;"
        f" {read.qualified_name} can read private data;"
        f" {egress.qualified_name} sends it to an attacker-reachable destination"
    )
    if cross_server:
        narrative += f" across {len(servers)} servers ({', '.join(servers)})"
    if arbitrary_sink:
        narrative += " using a caller-controlled URL/recipient sink"

    return TrifectaPath(
        path_id="",
        severity=severity,
        cross_server=cross_server,
        servers=servers,
        ingest_tool=ingest.qualified_name,
        read_tool=read.qualified_name,
        egress_tool=egress.qualified_name,
        attack_narrative=narrative + ".",
    )


def analyze_capability_graph(
    servers: dict[str, list[ToolDefinition]], trusted_servers: set[str] | None = None
) -> GraphReport:
    """Classify every tool and enumerate ranked lethal-trifecta chains."""

    trusted = set(trusted_servers or set())

    tool_index: dict[str, ToolDefinition] = {}
    nodes: list[ToolNode] = []
    for server_id in sorted(servers):
        for tool in sorted(servers[server_id], key=lambda item: item.name):
            node = classify_tool(server_id, tool)
            node.capabilities.sort(key=CAPABILITY_ORDER.index)
            nodes.append(node)
            tool_index[node.qualified_name] = tool

    nodes.sort(key=lambda node: node.qualified_name)
    excluded = sorted(server_id for server_id in trusted if server_id in servers)

    ingest_nodes = [
        node
        for node in nodes
        if "UNTRUSTED_INPUT" in node.capabilities and node.server_id not in trusted
    ]
    read_nodes = [node for node in nodes if "PRIVATE_DATA_READ" in node.capabilities]
    egress_nodes = [
        node
        for node in nodes
        if "EXTERNAL_EGRESS" in node.capabilities and node.server_id not in trusted
    ]

    edges: list[FlowEdge] = []
    for source in ingest_nodes:
        for target in read_nodes:
            if source.qualified_name == target.qualified_name:
                continue
            edges.append(
                FlowEdge(
                    source=source.qualified_name,
                    target=target.qualified_name,
                    stage="INGEST_TO_READ",
                    cross_server=source.server_id != target.server_id,
                )
            )
    for source in read_nodes:
        for target in egress_nodes:
            if source.qualified_name == target.qualified_name:
                continue
            edges.append(
                FlowEdge(
                    source=source.qualified_name,
                    target=target.qualified_name,
                    stage="READ_TO_EGRESS",
                    cross_server=source.server_id != target.server_id,
                )
            )
    edges.sort(key=lambda edge: (edge.stage, edge.source, edge.target))

    by_name = {node.qualified_name: node for node in nodes}
    ingest_edges = [edge for edge in edges if edge.stage == "INGEST_TO_READ"]
    read_edges = [edge for edge in edges if edge.stage == "READ_TO_EGRESS"]

    candidates: dict[tuple[str, str, str], TrifectaPath] = {}
    for first in ingest_edges:
        for second in read_edges:
            if second.source != first.target:
                continue
            key = (first.source, first.target, second.target)
            if key in candidates:
                continue
            candidates[key] = _build_path(
                by_name[first.source],
                by_name[first.target],
                by_name[second.target],
                tool_index[second.target],
            )

    trifecta_paths = sorted(
        candidates.values(),
        key=lambda path: (
            SEVERITY_ORDER[path.severity],
            0 if path.cross_server else 1,
            path.ingest_tool,
            path.read_tool,
            path.egress_tool,
        ),
    )
    for index, path in enumerate(trifecta_paths, start=1):
        path.path_id = f"trifecta-{index:03d}"

    return GraphReport(
        server_count=len(servers),
        tool_count=sum(len(tools) for tools in servers.values()),
        trusted_servers_excluded=excluded,
        nodes=nodes,
        edges=edges,
        trifecta_paths=trifecta_paths,
        passed=not trifecta_paths,
    )


_CLASS_FOR_TAG = {
    "UNTRUSTED_INPUT": "untrusted",
    "PRIVATE_DATA_READ": "private",
    "EXTERNAL_EGRESS": "egress",
}


def _escape_label(value: str) -> str:
    return value.replace('"', "'").replace("\n", " ")


def _safe_id(value: str) -> str:
    return "srv_" + re.sub(r"[^A-Za-z0-9_]", "_", value)


def render_mermaid(report: GraphReport) -> str:
    """Render the capability graph as a Mermaid ``flowchart LR`` diagram."""

    lines = ["flowchart LR"]
    lines.append("  classDef untrusted fill:#fff8e1,stroke:#b8860b,stroke-width:2px")
    lines.append("  classDef private fill:#fde2e4,stroke:#b02a37,stroke-width:2px")
    lines.append("  classDef egress fill:#dcfce7,stroke:#15803d,stroke-width:2px")

    ids = {node.qualified_name: f"n{index}" for index, node in enumerate(report.nodes)}

    by_server: dict[str, list[ToolNode]] = {}
    for node in report.nodes:
        by_server.setdefault(node.server_id, []).append(node)

    for server_id in sorted(by_server):
        lines.append(f'  subgraph {_safe_id(server_id)}["{_escape_label(server_id)}"]')
        for node in sorted(by_server[server_id], key=lambda item: item.tool_name):
            badges = "<br/>".join(node.capabilities) if node.capabilities else "NO_CAPABILITY"
            label = _escape_label(f"{node.qualified_name}<br/>{badges}")
            lines.append(f'    {ids[node.qualified_name]}["{label}"]')
        lines.append("  end")

    exfil_edges = {
        (path.read_tool, path.egress_tool) for path in report.trifecta_paths
    }
    for edge in report.edges:
        source = ids[edge.source]
        target = ids[edge.target]
        if edge.stage == "READ_TO_EGRESS" and (edge.source, edge.target) in exfil_edges:
            lines.append(f"  {source} -.->|EXFIL| {target}")
        else:
            lines.append(f"  {source} -->|{edge.stage}| {target}")

    for node in report.nodes:
        for tag in node.capabilities:
            lines.append(f"  class {ids[node.qualified_name]} {_CLASS_FOR_TAG[tag]}")

    return "\n".join(lines) + "\n"
