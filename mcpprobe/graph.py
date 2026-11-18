"""Deterministic Lethal-Trifecta capability graph analyzer.

A "lethal trifecta" needs three capabilities to line up:

1. ``UNTRUSTED_INPUT`` -- third-party content enters the model context,
2. ``PRIVATE_DATA_READ`` -- sensitive local/tenant data is readable,
3. ``EXTERNAL_EGRESS`` -- data can leave to an attacker-chosen destination.

A tool that mutates *local* state (``git_commit``, ``write_file``,
``create_entities`` -- a write verb with no network, recipient or
remote-publishing target) is ``LOCAL_WRITE``, not ``EXTERNAL_EGRESS``: a commit
lands in the local repository, so it cannot exfiltrate anything. Only a chain
``ingest -> read -> egress`` is an exfiltration path, and paths are collapsed per
``(ingest, egress)`` pair so a server with 15 read tools yields one path, not
fifteen. Latch finds them across servers, ranks them, and explains the attack.

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

CapabilityTag = Literal[
    "UNTRUSTED_INPUT", "PRIVATE_DATA_READ", "LOCAL_WRITE", "EXTERNAL_EGRESS"
]

CAPABILITY_ORDER: tuple[CapabilityTag, ...] = (
    "UNTRUSTED_INPUT",
    "PRIVATE_DATA_READ",
    "LOCAL_WRITE",
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
        "harvest",
        "extract",
        "navigate",
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
        "tickets",
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
        "harvest",
        "extract",
    }
)

SENSITIVE_RESOURCE_TOKENS = frozenset(
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
        "ledger",
        "ledgers",
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
        "dispatch",
        "relay",
        "emit",
        "write",
        "append",
        "update",
        # A browser navigation is a request to a caller-chosen URL, which is a
        # destination the caller controls (``puppeteer_navigate``).
        "navigate",
    }
)

#: Verbs that mutate state which stays on this machine or in this account.
LOCAL_MUTATION_VERBS = frozenset(
    {
        "write",
        "edit",
        "move",
        "rename",
        "mkdir",
        "commit",
        "merge",
        "reset",
        "checkout",
        "init",
        "insert",
        "upsert",
        "append",
        "save",
        "store",
        "persist",
        "truncate",
    }
)

#: Mutating verbs that are also everyday math/API words (``add``, ``set``).
#: They only count as a local write together with a local object noun.
GENERIC_MUTATION_VERBS = frozenset(
    {"add", "set", "apply", "modify", "update", "create", "delete", "remove"}
)

#: Nouns naming state that lives on this machine or in this repository.
LOCAL_OBJECT_TOKENS = frozenset(
    {
        "file",
        "files",
        "repo",
        "repository",
        "git",
        "vcs",
        "branch",
        "directory",
        "dir",
        "path",
        "entity",
        "entities",
        "relation",
        "relations",
        "observation",
        "observations",
        "record",
        "records",
        "row",
        "rows",
        "table",
        "memory",
        "note",
        "notes",
        "workspace",
        "node",
        "nodes",
        "graph",
        "kb",
        "db",
        "database",
        "config",
        "document",
        "doc",
        "docs",
        "tag",
        "tags",
    }
)

#: Verbs that publish outward. Used only to veto a local-write classification
#: (``publish_post`` publishes; it does not merely write local state); making a
#: remote sink is still decided by the destination/sink rules below.
REMOTE_PUBLISH_VERBS = frozenset(
    {
        "send",
        "post",
        "put",
        "patch",
        "upload",
        "publish",
        "push",
        "reply",
        "forward",
        "share",
        "invite",
        "notify",
        "webhook",
        "transfer",
        "pay",
        "dispatch",
        "relay",
        "emit",
    }
)

#: Tool-name tokens that name a genuinely remote destination.
REMOTE_TARGET_TOKENS = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "webhook",
        "http",
        "https",
        "remote",
        "gist",
        "bucket",
        "s3",
        "external",
        "dest",
        "destination",
        "sink",
        "recipient",
        "issue",
        "pr",
        "comment",
        "email",
        "mail",
        "slack",
        "discord",
        "channel",
        "message",
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
        "pull",
        "gist",
        "repo",
        "bucket",
        "s3",
        "external",
        "remote",
        "dest",
        "destination",
        "sink",
    }
)

#: Tool-name tokens for MCP *client-protocol callbacks*. ``sampling`` and
#: ``elicitation`` ask the connected client to do work -- return a completion, or
#: prompt the user -- so they are JSON-RPC calls back to the client, not network
#: sinks: nothing leaves for a third party.
MCP_CLIENT_PROTOCOL_TOKENS = frozenset({"sampling", "elicitation", "elicit"})

#: ``trigger`` is the SDK's verb for firing those callbacks. On its own it names
#: a local protocol test, so it only counts as outbound together with a real
#: remote destination noun (``trigger_url_webhook``).
LOCAL_PROTOCOL_VERBS = frozenset({"trigger"})

#: Destination nouns that do make an identifier genuinely outward-facing.
#: ``uri`` is deliberately absent: a bare resource URI is a protocol identifier
#: (``trigger-resource-update`` notifies the client about a resource), not a
#: caller-chosen destination.
NETWORK_TARGET_TOKENS = frozenset(
    {
        "url",
        "http",
        "https",
        "webhook",
        "endpoint",
        "upload",
        "email",
        "mail",
        "slack",
        "discord",
        "channel",
        "recipient",
        "dest",
        "destination",
        "sink",
        "s3",
        "bucket",
        "gist",
        "remote",
        "external",
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
    """A complete ingest -> read -> egress exfiltration chain.

    Paths are collapsed per ``(ingest_tool, egress_tool)`` pair: every
    ``PRIVATE_DATA_READ`` tool that feeds the same pair is listed in
    ``read_tools`` instead of producing another near-identical path.
    """

    path_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    cross_server: bool
    servers: list[str]
    ingest_tool: str
    read_tool: str
    read_tools: list[str] = Field(default_factory=list)
    collapsed_read_count: int = 1
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
    #: Local mutations, reported for visibility and never as an exfil sink.
    local_write_tools: list[str] = Field(default_factory=list)
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


def _enum_value_tokens(tool: ToolDefinition) -> set[str]:
    """Tokens from string ``enum`` values on parameter schemas.

    A generic dispatcher (``invoke_connector(action: enum["read","upload"])``)
    hides its real capability in the enum, not in its name, so the enum values
    are tokenized exactly like identifiers.
    """

    tokens: set[str] = set()
    properties = tool.inputSchema.get("properties")
    if not isinstance(properties, dict):
        return tokens
    for schema in properties.values():
        if not isinstance(schema, dict):
            continue
        values = schema.get("enum")
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str):
                tokens.update(tokenize_identifier(value))
    return tokens


def _tool_tokens(tool: ToolDefinition) -> set[str]:
    tokens = set(tokenize_identifier(tool.name))
    for parameter in _parameter_names(tool):
        tokens.update(tokenize_identifier(parameter))
    tokens.update(_enum_value_tokens(tool))
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
    sensitive = sorted(tokens & SENSITIVE_RESOURCE_TOKENS)
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

    # -- LOCAL_WRITE --------------------------------------------------------
    # A mutation that cannot leave the machine is not an exfiltration sink.
    # Decided from the tool *name* (a parameter called ``message`` must not turn
    # ``git_commit`` into an outbound sender) and vetoed by any real outbound
    # signal: a destination/recipient parameter, a header binding, or an
    # open-world non-read-only annotation.
    name_tokens = set(tokenize_identifier(tool.name))
    strong_local_verbs = sorted(name_tokens & LOCAL_MUTATION_VERBS)
    generic_local_verbs = sorted(name_tokens & GENERIC_MUTATION_VERBS)
    local_objects = sorted(name_tokens & LOCAL_OBJECT_TOKENS)
    local_verbs = sorted(set(strong_local_verbs) | set(generic_local_verbs))
    # ``add``/``create`` alone is too generic (a math ``add`` tool); it only
    # counts as a local write beside a local object noun (``create_entities``).
    mutates_local_state = bool(strong_local_verbs) or bool(
        generic_local_verbs and local_objects
    )
    name_publishes = sorted(name_tokens & REMOTE_PUBLISH_VERBS)
    name_remote_targets = sorted(name_tokens & REMOTE_TARGET_TOKENS)
    destination_params = sorted(
        params & (ARBITRARY_DESTINATION_PARAMS | OUTBOUND_SINK_PARAMS)
    )
    local_write = mutates_local_state and not (
        name_publishes
        or name_remote_targets
        or destination_params
        or has_header_binding(tool)
        or open_world
    )
    if local_write:
        _add(
            capabilities,
            evidence,
            "LOCAL_WRITE",
            "identifier.local_mutation",
            0.8,
            f"local mutation verb(s) {local_verbs} with no outbound network,"
            " recipient or remote-publishing target: state stays on this machine",
        )

    # -- EXTERNAL_EGRESS ---------------------------------------------------
    # MCP client-protocol callbacks (``sampling``, ``elicitation``, a bare
    # ``trigger``) ask the *connected client* to run a completion or prompt a
    # user. They are server -> client JSON-RPC calls, so an SDK diagnostics
    # tool like ``triggerSamplingRequest`` must not become an exfiltration sink
    # just because its name contains ``trigger``/``request``.
    local_protocol_callback = bool(
        tokens & MCP_CLIENT_PROTOCOL_TOKENS
        or (tokens & LOCAL_PROTOCOL_VERBS and not tokens & NETWORK_TARGET_TOKENS)
    )

    outbound_verbs = sorted(tokens & OUTBOUND_VERBS)
    external_targets = sorted(tokens & EXTERNAL_TARGETS)
    if outbound_verbs and external_targets and not local_write and not local_protocol_callback:
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

    if (
        open_world
        and annotations.get("readOnlyHint") is not True
        and not local_protocol_callback
    ):
        _add(
            capabilities,
            evidence,
            "EXTERNAL_EGRESS",
            "annotation.openWorldEgress",
            0.8,
            "openWorldHint=true without readOnlyHint: the tool can reach external systems",
        )

    if (
        params & ARBITRARY_DESTINATION_PARAMS
        and params & PAYLOAD_PARAMS
        and not local_protocol_callback
    ):
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
    ingest: ToolNode,
    reads: list[ToolNode],
    egress: ToolNode,
    egress_tool: ToolDefinition,
) -> TrifectaPath:
    read_tools = sorted(read.qualified_name for read in reads)
    servers = sorted(
        {ingest.server_id, egress.server_id, *(read.server_id for read in reads)}
    )
    cross_server = len(servers) >= 2
    arbitrary_sink = has_arbitrary_destination(egress_tool)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    if cross_server or arbitrary_sink:
        severity = "CRITICAL"
    else:
        severity = "HIGH"

    first_read = read_tools[0]
    if len(read_tools) == 1:
        read_phrase = f" {first_read} can read private data"
    else:
        read_phrase = (
            f" {len(read_tools)} private-data tools ({', '.join(read_tools)})"
            " can read it"
        )

    narrative = (
        f"{ingest.qualified_name} pulls untrusted third-party content into the"
        f" model context;{read_phrase};"
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
        read_tool=first_read,
        read_tools=read_tools,
        collapsed_read_count=len(read_tools),
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

    # Index by source: a full ingest x read product is O(E*E) and dominated by
    # edges that can never join. Appending in edge order keeps it deterministic.
    read_edges_by_source: dict[str, list[FlowEdge]] = {}
    for edge in read_edges:
        read_edges_by_source.setdefault(edge.source, []).append(edge)

    candidates: dict[tuple[str, str], dict[str, ToolNode]] = {}
    for first in ingest_edges:
        for second in read_edges_by_source.get(first.target, []):
            # A tool cannot be both where untrusted input enters and where it
            # leaves: `post_message -> read -> post_message` is an artifact of
            # one node holding two roles, not an exfiltration chain.
            if first.source == second.target:
                continue
            # Collapse every read tool feeding the same (ingest, egress) pair.
            candidates.setdefault((first.source, second.target), {})[
                first.target
            ] = by_name[first.target]

    trifecta_paths = [
        _build_path(
            by_name[ingest_name],
            list(reads.values()),
            by_name[egress_name],
            tool_index[egress_name],
        )
        for (ingest_name, egress_name), reads in candidates.items()
    ]
    trifecta_paths.sort(
        key=lambda path: (
            SEVERITY_ORDER[path.severity],
            0 if path.cross_server else 1,
            path.ingest_tool,
            path.read_tool,
            path.egress_tool,
        )
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
        local_write_tools=sorted(
            node.qualified_name
            for node in nodes
            if "LOCAL_WRITE" in node.capabilities
        ),
        passed=not trifecta_paths,
    )


_CLASS_FOR_TAG = {
    "UNTRUSTED_INPUT": "untrusted",
    "PRIVATE_DATA_READ": "private",
    "LOCAL_WRITE": "local",
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
    lines.append("  classDef local fill:#eef2ff,stroke:#4338ca,stroke-width:1px")
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
        (read_tool, path.egress_tool)
        for path in report.trifecta_paths
        for read_tool in (path.read_tools or [path.read_tool])
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
