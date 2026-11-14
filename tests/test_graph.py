"""Tests for the deterministic capability graph and lethal-trifecta analyzer."""

from __future__ import annotations

from typing import Any

from mcpprobe.graph import (
    analyze_capability_graph,
    classify_tool,
    has_arbitrary_destination,
    render_mermaid,
    tokenize_identifier,
)
from mcpprobe.models import ToolDefinition


def tool(
    name: str,
    properties: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
    description: str = "",
) -> ToolDefinition:
    payload: dict[str, Any] = {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties or {}},
    }
    if annotations is not None:
        payload["annotations"] = annotations
    return ToolDefinition.model_validate(payload)


def trifecta_servers() -> dict[str, list[ToolDefinition]]:
    return {
        "github": [tool("get_issue", {"issue_number": {"type": "integer"}})],
        "postgres": [tool("query_ledger", {"sql": {"type": "string"}})],
        "slack": [
            tool(
                "post_message",
                {"channel": {"type": "string"}, "text": {"type": "string"}},
                annotations={
                    "readOnlyHint": False,
                    "openWorldHint": True,
                    "destructiveHint": False,
                },
            )
        ],
    }


def benign_servers() -> dict[str, list[ToolDefinition]]:
    return {
        "math-calc": [
            tool("add", {"a": {"type": "number"}, "b": {"type": "number"}}),
            tool("multiply", {"a": {"type": "number"}, "b": {"type": "number"}}),
        ],
        "local-formatter": [tool("format_text", {"text": {"type": "string"}})],
    }


# -- tokenizer -------------------------------------------------------------


def test_tokenize_camel_case() -> None:
    assert tokenize_identifier("readFile") == ["read", "file"]
    assert tokenize_identifier("postWebhook") == ["post", "webhook"]
    assert tokenize_identifier("HTMLParser") == ["html", "parser"]


def test_tokenize_snake_kebab_and_dotted() -> None:
    assert tokenize_identifier("get_issue_comments") == ["get", "issue", "comments"]
    assert tokenize_identifier("x-api-key") == ["x", "api", "key"]
    assert tokenize_identifier("files.read") == ["files", "read"]
    assert tokenize_identifier("") == []


def test_tokenize_does_not_produce_substring_matches() -> None:
    assert "ssh" not in tokenize_identifier("asset_manager")
    assert "ssh" not in tokenize_identifier("passhash")


# -- classification --------------------------------------------------------


def test_classify_ingest_tool() -> None:
    node = classify_tool("github", tool("get_issue", {"issue_number": {"type": "integer"}}))

    assert node.qualified_name == "github:get_issue"
    assert node.server_id == "github"
    assert node.tool_name == "get_issue"
    assert node.capabilities == ["UNTRUSTED_INPUT"]
    assert node.evidence
    assert node.evidence[0].signal == "identifier.ingest_pair"


def test_classify_private_read_tool() -> None:
    node = classify_tool("fs", tool("read_file", {"path": {"type": "string"}}))

    assert node.capabilities == ["PRIVATE_DATA_READ"]


def test_classify_database_query_tool() -> None:
    node = classify_tool("postgres", tool("query_ledger", {"sql": {"type": "string"}}))

    assert node.capabilities == ["PRIVATE_DATA_READ"]


def test_classify_egress_tool_from_annotations() -> None:
    node = classify_tool(
        "slack",
        tool(
            "post_message",
            {"channel": {"type": "string"}},
            annotations={"readOnlyHint": False, "openWorldHint": True, "destructiveHint": False},
        ),
    )

    assert "EXTERNAL_EGRESS" in node.capabilities
    assert any(entry.signal == "annotation.openWorldEgress" for entry in node.evidence)


def test_fetch_url_is_untrusted_input_only() -> None:
    node = classify_tool("net", tool("fetch_url", {"url": {"type": "string"}}))

    assert node.capabilities == ["UNTRUSTED_INPUT"]


def test_fetch_url_with_payload_is_also_egress() -> None:
    node = classify_tool(
        "net", tool("fetch_url", {"url": {"type": "string"}, "body": {"type": "string"}})
    )

    assert node.capabilities == ["UNTRUSTED_INPUT", "EXTERNAL_EGRESS"]


def test_x_mcp_header_binding_is_egress() -> None:
    node = classify_tool(
        "crm", tool("sync_tenant", {"tenant": {"type": "string", "x-mcp-header": "X-Tenant"}})
    )

    assert node.capabilities == ["EXTERNAL_EGRESS"]
    assert any(entry.signal == "schema.x-mcp-header" for entry in node.evidence)


def test_outbound_sink_parameter_is_egress() -> None:
    node = classify_tool("hooks", tool("dispatch", {"webhook_url": {"type": "string"}}))

    assert node.capabilities == ["EXTERNAL_EGRESS"]


def test_read_only_closed_world_resource_identifier_is_private_read() -> None:
    node = classify_tool(
        "fs",
        tool(
            "lookup",
            {"path": {"type": "string"}},
            annotations={"readOnlyHint": True, "openWorldHint": False},
        ),
    )

    assert node.capabilities == ["PRIVATE_DATA_READ"]
    assert any(entry.signal == "annotation.readOnlyClosedWorld" for entry in node.evidence)


def test_tool_can_hold_all_three_capabilities() -> None:
    node = classify_tool(
        "mix", tool("get_issue_log_files", {"webhook_url": {"type": "string"}})
    )

    assert node.capabilities == [
        "UNTRUSTED_INPUT",
        "PRIVATE_DATA_READ",
        "EXTERNAL_EGRESS",
    ]


def test_substring_lookalike_tools_have_no_capabilities() -> None:
    assert classify_tool("x", tool("asset_manager", {"asset_id": {"type": "string"}})).capabilities == []
    assert classify_tool("x", tool("passhash", {"value": {"type": "string"}})).capabilities == []
    assert classify_tool("x", tool("add", {"a": {"type": "number"}})).capabilities == []


def test_has_arbitrary_destination() -> None:
    assert has_arbitrary_destination(tool("send", {"url": {"type": "string"}})) is True
    assert has_arbitrary_destination(tool("send", {"channel": {"type": "string"}})) is False
    assert (
        has_arbitrary_destination(
            tool("sync", {"t": {"type": "string", "x-mcp-header": "X-Tenant"}})
        )
        is True
    )


# -- graph -----------------------------------------------------------------


def test_cross_server_trifecta_is_critical() -> None:
    report = analyze_capability_graph(trifecta_servers())

    assert report.server_count == 3
    assert report.tool_count == 3
    assert report.passed is False
    assert len(report.trifecta_paths) == 1

    path = report.trifecta_paths[0]
    assert path.path_id == "trifecta-001"
    assert path.severity == "CRITICAL"
    assert path.cross_server is True
    assert path.servers == ["github", "postgres", "slack"]
    assert path.ingest_tool == "github:get_issue"
    assert path.read_tool == "postgres:query_ledger"
    assert path.egress_tool == "slack:post_message"
    assert "get_issue" in path.attack_narrative
    assert "3 servers" in path.attack_narrative

    assert all(item.severity == "CRITICAL" for item in report.trifecta_paths)


def test_benign_two_server_setup_has_no_paths() -> None:
    report = analyze_capability_graph(benign_servers())

    assert report.passed is True
    assert report.trifecta_paths == []
    assert report.edges == []
    assert report.server_count == 2
    assert report.tool_count == 3
    assert all(node.capabilities == [] for node in report.nodes)


def test_single_server_chain_without_sink_is_high() -> None:
    servers = {
        "workspace": [
            tool("get_issue", {"issue_number": {"type": "integer"}}),
            tool("read_file", {"path": {"type": "string"}}),
            tool("post_issue", {"comment": {"type": "string"}}),
        ]
    }

    report = analyze_capability_graph(servers)

    assert len(report.trifecta_paths) == 1
    path = report.trifecta_paths[0]
    assert path.severity == "HIGH"
    assert path.cross_server is False
    assert path.servers == ["workspace"]


def test_single_server_chain_with_arbitrary_destination_is_critical() -> None:
    servers = {
        "workspace": [
            tool("get_issue", {"issue_number": {"type": "integer"}}),
            tool("read_file", {"path": {"type": "string"}}),
            tool("post_webhook", {"webhook": {"type": "string"}}),
        ]
    }

    report = analyze_capability_graph(servers)

    path = report.trifecta_paths[0]
    assert path.cross_server is False
    assert path.severity == "CRITICAL"
    assert "caller-controlled" in path.attack_narrative


def test_trusted_server_is_not_an_egress_sink() -> None:
    report = analyze_capability_graph(trifecta_servers(), trusted_servers={"slack"})

    assert report.passed is True
    assert report.trifecta_paths == []
    assert report.trusted_servers_excluded == ["slack"]
    assert any(node.qualified_name == "slack:post_message" for node in report.nodes)
    assert all(edge.stage != "READ_TO_EGRESS" for edge in report.edges)


def test_trusted_server_is_not_an_untrusted_source() -> None:
    report = analyze_capability_graph(trifecta_servers(), trusted_servers={"github"})

    assert report.trusted_servers_excluded == ["github"]
    assert report.trifecta_paths == []
    assert all(
        not edge.source.startswith("github:")
        for edge in report.edges
        if edge.stage == "INGEST_TO_READ"
    )


def test_self_loop_trifecta_is_suppressed() -> None:
    servers = {
        "slack": [
            tool(
                "post_message",
                {"channel": {"type": "string"}},
                annotations={"readOnlyHint": False, "openWorldHint": True},
            )
        ],
        "db": [tool("query_ledger", {"sql": {"type": "string"}})],
    }

    report = analyze_capability_graph(servers)

    assert report.trifecta_paths == []
    assert report.passed is True
    # The capability graph itself still exists; only the degenerate chain is dropped.
    assert any(edge.stage == "INGEST_TO_READ" for edge in report.edges)
    assert any(edge.stage == "READ_TO_EGRESS" for edge in report.edges)


def test_ledger_is_a_sensitive_resource_token() -> None:
    read_ledger = classify_tool(
        "wallet", tool("read_ledger", {"ledger": {"type": "string"}})
    )
    get_ledger = classify_tool(
        "wallet", tool("get_ledger", {"ledgers": {"type": "string"}})
    )

    assert read_ledger.capabilities == ["PRIVATE_DATA_READ"]
    assert get_ledger.capabilities == ["PRIVATE_DATA_READ"]


def test_fintech_chain_uses_ledger_token() -> None:
    servers = {
        "gmail": [tool("list_messages", {"max_results": {"type": "integer"}})],
        "wallet": [tool("read_ledger", {"ledger": {"type": "string"}})],
        "webhook": [
            tool(
                "send_payload",
                {"payload": {"type": "string"}},
                annotations={"readOnlyHint": False, "openWorldHint": True},
            )
        ],
    }

    report = analyze_capability_graph(servers)

    assert len(report.trifecta_paths) == 1
    assert report.trifecta_paths[0].read_tool == "wallet:read_ledger"
    assert report.trifecta_paths[0].severity == "CRITICAL"


def test_unknown_trusted_server_is_not_recorded() -> None:
    report = analyze_capability_graph(trifecta_servers(), trusted_servers={"not-configured"})

    assert report.trusted_servers_excluded == []
    assert report.trifecta_paths


def test_edges_are_directed_and_labelled() -> None:
    report = analyze_capability_graph(trifecta_servers())
    stages = {(edge.stage, edge.source, edge.target) for edge in report.edges}

    assert (
        "INGEST_TO_READ",
        "github:get_issue",
        "postgres:query_ledger",
    ) in stages
    assert (
        "READ_TO_EGRESS",
        "postgres:query_ledger",
        "slack:post_message",
    ) in stages
    read_edges = [edge for edge in report.edges if edge.stage == "READ_TO_EGRESS"]
    assert read_edges[0].cross_server is True


def test_paths_are_deduplicated_and_deterministic() -> None:
    first = analyze_capability_graph(trifecta_servers())
    second = analyze_capability_graph(trifecta_servers())

    assert first == second
    keys = [(path.ingest_tool, path.read_tool, path.egress_tool) for path in first.trifecta_paths]
    assert len(keys) == len(set(keys))


def test_paths_sort_critical_before_high() -> None:
    servers = {
        "alpha": [
            tool("get_issue", {"issue_number": {"type": "integer"}}),
            tool("read_file", {"path": {"type": "string"}}),
            tool("post_webhook", {"webhook": {"type": "string"}}),
        ],
        "beta": [
            tool("get_issue", {"issue_number": {"type": "integer"}}),
            tool("read_ledger", {"sql": {"type": "string"}}),
            tool("post_issue", {"comment": {"type": "string"}}),
        ],
    }

    report = analyze_capability_graph(servers)
    severities = [path.severity for path in report.trifecta_paths]

    assert severities[0] == "CRITICAL"
    assert "HIGH" in severities
    assert severities == sorted(severities, key=lambda value: 0 if value == "CRITICAL" else 1)
    assert [path.path_id for path in report.trifecta_paths] == [
        f"trifecta-{index:03d}" for index in range(1, len(report.trifecta_paths) + 1)
    ]


def test_empty_configuration_passes() -> None:
    report = analyze_capability_graph({})

    assert report.server_count == 0
    assert report.tool_count == 0
    assert report.nodes == []
    assert report.passed is True


def test_report_is_json_serializable() -> None:
    payload = analyze_capability_graph(trifecta_servers()).model_dump(mode="json")

    assert payload["passed"] is False
    assert payload["trifecta_paths"][0]["severity"] == "CRITICAL"
    assert payload["nodes"][0]["capabilities"]


# -- mermaid ---------------------------------------------------------------


def test_mermaid_groups_tools_and_highlights_exfil() -> None:
    report = analyze_capability_graph(trifecta_servers())

    diagram = render_mermaid(report)

    assert diagram.startswith("flowchart LR")
    assert 'subgraph srv_github["github"]' in diagram
    assert 'subgraph srv_postgres["postgres"]' in diagram
    assert 'subgraph srv_slack["slack"]' in diagram
    assert "github:get_issue<br/>UNTRUSTED_INPUT" in diagram
    assert "-.->|EXFIL|" in diagram
    assert "classDef untrusted" in diagram
    assert "class n" in diagram
    assert diagram.endswith("\n")


def test_mermaid_for_empty_graph_is_valid() -> None:
    diagram = render_mermaid(analyze_capability_graph({}))

    assert diagram.startswith("flowchart LR")
    assert "subgraph" not in diagram


def test_mermaid_escapes_quotes_in_labels() -> None:
    report = analyze_capability_graph({"weird": [tool('say"hi', {})]})

    diagram = render_mermaid(report)

    assert '"weird"' in diagram
    assert "say'hi" in diagram
