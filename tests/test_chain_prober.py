"""Tests for the execution-aware lethal-trifecta canary prober."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner

from mcpprobe.chain_prober import (
    CanarySinkServer,
    _error_text,
    _result_text,
    _tool_allowed,
    synthesize_egress_args,
    synthesize_read_args,
    validate_tool_allowlist,
)
from mcpprobe.cli import cli
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.models import ProbeError, ToolDefinition
from mcpprobe.sarif import to_sarif
from mcpprobe.transport import HttpHarvester

FIXTURE = Path(__file__).parent / "fixtures" / "mock_chain_stdio.py"


def tool(
    name: str,
    properties: dict[str, Any] | None = None,
    required: list[str] | None = None,
) -> ToolDefinition:
    schema: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = required
    return ToolDefinition.model_validate(
        {"name": name, "description": "", "inputSchema": schema}
    )


SAFETY = ("--i-understand-this-executes-tools", "--allow-all-tools")


def fixture_args(*roles: str) -> list[str]:
    args = [str(FIXTURE)]
    for role in roles:
        args.extend(["--role", role])
    return args


def write_chain_config(tmp_path: Path, *roles: str) -> Path:
    payload = {
        "mcpServers": {"chain": {"command": sys.executable, "args": fixture_args(*roles)}}
    }
    path = tmp_path / "chain.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def write_two_chain_config(tmp_path: Path, *roles: str) -> Path:
    payload = {
        "mcpServers": {
            server_id: {"command": sys.executable, "args": fixture_args(*roles)}
            for server_id in ("alpha", "beta")
        }
    }
    path = tmp_path / "two-chains.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run_probe(config: Path, *extra: str, safety: tuple[str, ...] = SAFETY) -> Any:
    return CliRunner().invoke(
        cli,
        [
            "probe-chain",
            "--config",
            str(config),
            "--format",
            "json",
            *safety,
            *extra,
        ],
    )


# -- loopback sink ----------------------------------------------------------


def test_canary_sink_binds_loopback_and_captures_requests() -> None:
    async def scenario() -> tuple[str, int, dict[str, str], int]:
        async with CanarySinkServer() as sink:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{sink.base_url}/exfil?marker=LATCH-CANARY-abc123",
                    headers={"X-Trace": "1"},
                    json={"payload": "LATCH-CANARY-abc123"},
                )
            return (
                sink.base_url,
                response.status_code,
                response.json(),
                len(sink.captured_requests),
            )

    base_url, status, body, captured = asyncio.run(scenario())

    assert base_url.startswith("http://127.0.0.1:")
    assert status == 200
    assert body == {"ok": True}
    assert captured == 1


def test_canary_sink_records_method_path_headers_and_body() -> None:
    async def scenario() -> Any:
        async with CanarySinkServer() as sink:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{sink.base_url}/exfil",
                    headers={"X-Canary": "LATCH-CANARY-abc123"},
                    content=b"hello",
                )
            return sink, sink.find_canary("LATCH-CANARY-abc123")

    sink, match = asyncio.run(scenario())

    record = sink.captured_requests[0]
    assert record["method"] == "POST"
    assert record["path"] == "/exfil"
    assert record["headers"]["X-Canary"] == "LATCH-CANARY-abc123"
    assert record["body"] == "hello"
    assert match is not None
    assert match[0] == "POST /exfil"
    assert match[1] == "header:X-Canary"


def test_canary_sink_reports_misses() -> None:
    async def scenario() -> bool:
        async with CanarySinkServer() as sink:
            async with httpx.AsyncClient() as client:
                await client.post(f"{sink.base_url}/exfil", content=b"nope")
            return sink.find_canary("LATCH-CANARY-missing") is None

    assert asyncio.run(scenario()) is True


# -- argument synthesis -----------------------------------------------------


def test_synthesize_read_args_maps_common_parameters() -> None:
    tool_definition = tool(
        "query_everything",
        {
            "query": {"type": "string"},
            "path": {"type": "string"},
            "account_id": {"type": "string"},
            "limit": {"type": "integer"},
            "verbose": {"type": "boolean"},
            "label": {"type": "string"},
        },
        required=["query", "limit", "verbose"],
    )

    args = synthesize_read_args(tool_definition, "LATCH-CANARY-deadbeef")

    assert args["query"] == "SELECT * FROM records LIMIT 1"
    assert args["path"] == "canary.txt"
    assert args["account_id"] == "canary-1"
    assert args["limit"] == 1
    assert args["verbose"] is True
    # Optional parameters outside the read vocabulary are left untouched.
    assert "label" not in args


def test_synthesize_egress_args_wires_sink_and_payload() -> None:
    tool_definition = tool(
        "post_webhook",
        {
            "webhook_url": {"type": "string"},
            "payload": {"type": "string"},
            "recipient": {"type": "string"},
            "retries": {"type": "integer"},
        },
        required=["webhook_url", "payload", "retries"],
    )

    args, has_channel = synthesize_egress_args(
        tool_definition, "http://127.0.0.1:9000", "LATCH-CANARY-deadbeef"
    )

    assert has_channel is True
    assert args["webhook_url"] == "http://127.0.0.1:9000/exfil"
    assert args["payload"] == "LATCH-CANARY-deadbeef"
    assert args["recipient"] == "canary@127.0.0.1.invalid"
    assert args["retries"] == 1


def test_synthesize_egress_args_without_channel_is_inconclusive() -> None:
    tool_definition = tool(
        "delete_record", {"record_id": {"type": "string"}}, required=["record_id"]
    )

    args, has_channel = synthesize_egress_args(
        tool_definition, "http://127.0.0.1:9000", "LATCH-CANARY-deadbeef"
    )

    assert has_channel is False
    assert args == {"record_id": "canary"}


# -- transport call_tool ----------------------------------------------------


def test_http_call_tool_returns_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"content": [{"type": "text", "text": "ok"}]},
            },
        )

    async def scenario() -> dict[str, Any]:
        harvester = HttpHarvester(
            "https://mcp.example.com/mcp", transport=httpx.MockTransport(handler)
        )
        try:
            return await harvester.call_tool("read_ledger", {"query": "x"})
        finally:
            await harvester.close()

    result = asyncio.run(scenario())

    assert result == {"content": [{"type": "text", "text": "ok"}]}


def test_http_call_tool_normalizes_jsonrpc_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32602, "message": "invalid params"},
            },
        )

    async def scenario() -> dict[str, Any]:
        harvester = HttpHarvester(
            "https://mcp.example.com/mcp", transport=httpx.MockTransport(handler)
        )
        try:
            return await harvester.call_tool("read_ledger", {})
        finally:
            await harvester.close()

    result = asyncio.run(scenario())

    assert result["isError"] is True
    assert result["error"]["code"] == -32602
    assert "invalid params" in result["content"][0]["text"]


# -- static context ---------------------------------------------------------


def static_chain_manifests() -> dict[str, list[ToolDefinition]]:
    return {
        "chain": [
            tool(
                "fetch_issue",
                {"issue_number": {"type": "integer"}},
                required=["issue_number"],
            ),
            tool("read_ledger", {"query": {"type": "string"}}, required=["query"]),
            tool(
                "post_webhook",
                {
                    "webhook_url": {"type": "string"},
                    "payload": {"type": "string"},
                },
                required=["webhook_url", "payload"],
            ),
        ]
    }


def test_static_graph_flags_the_fixture_chain_as_critical() -> None:
    graph = analyze_capability_graph(static_chain_manifests())

    assert len(graph.trifecta_paths) == 1
    assert graph.trifecta_paths[0].severity == "CRITICAL"


# -- end-to-end probing -----------------------------------------------------


def test_confirmed_exploitable_chain(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(config)

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["static_paths_found"] == 1
    assert payload["confirmed_exploitable"] == 1
    assert payload["passed"] is False
    [probe] = payload["results"]
    assert probe["status"] == "CONFIRMED_EXPLOITABLE"
    assert probe["verified_severity"] == "CRITICAL"
    assert probe["canary_captured_at_sink"] is True
    assert probe["read_observed"] is True
    assert probe["egress_invoked"] is True
    assert probe["canary_token"].startswith("LATCH-CANARY-")
    assert "POST /exfil" in probe["sink_request_summary"]


def test_blocked_at_egress_eliminates_static_false_positive(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-allowlisted")

    result = run_probe(config)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["static_paths_found"] == 1
    assert payload["confirmed_exploitable"] == 0
    assert payload["blocked_count"] == 1
    assert payload["passed"] is True
    [probe] = payload["results"]
    assert probe["status"] == "BLOCKED_AT_EGRESS"
    assert probe["verified_severity"] == "LOW"
    assert probe["canary_captured_at_sink"] is False
    assert "allowlist" in probe["block_reason"]


def test_blocked_at_read_eliminates_static_false_positive(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-denied", "egress-open")

    result = run_probe(config)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["confirmed_exploitable"] == 0
    [probe] = payload["results"]
    assert probe["status"] == "BLOCKED_AT_READ"
    assert probe["read_observed"] is False
    assert probe["egress_invoked"] is False
    assert "RBAC denied" in probe["block_reason"]


def test_no_seed_canary_cannot_confirm_propagation(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(config, "--no-seed-canary")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["confirmed_exploitable"] == 0
    [probe] = payload["results"]
    assert probe["status"] == "BLOCKED_AT_EGRESS"
    assert "without forwarding the canary payload" in probe["block_reason"]


def test_trusted_servers_remove_the_chain(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(config, "--trust-server", "chain")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["static_paths_found"] == 0
    assert payload["results"] == []


def test_probe_chain_requires_live_servers(tmp_path: Path) -> None:
    manifest = tmp_path / "static.json"
    manifest.write_text(json.dumps({"tools": []}), encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["probe-chain", "--server-manifest", f"static={manifest}"]
    )

    assert result.exit_code == 2, result.output
    combined = result.output + getattr(result, "stderr", "")
    assert "live stdio or http" in combined


def test_probe_chain_requires_a_target() -> None:
    result = CliRunner().invoke(cli, ["probe-chain"])

    assert result.exit_code == 2, result.output


def test_probe_chain_malformed_manifest_exits_two() -> None:
    result = CliRunner().invoke(cli, ["probe-chain", "--server-manifest", "nope"])

    assert result.exit_code == 2, result.output


def test_cli_text_output_prints_status_and_evidence(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = CliRunner().invoke(
        cli, ["probe-chain", "--config", str(config), *SAFETY]
    )

    assert result.exit_code == 1, result.output
    assert "CONFIRMED_EXPLOITABLE" in result.output
    assert "sink: POST /exfil" in result.output
    assert "RESULT: 1 confirmed exploitable chain(s)" in result.output


# -- SARIF ------------------------------------------------------------------


def test_sarif_emits_confirmed_chain_only(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")
    sarif_path = tmp_path / "chain.sarif"

    result = CliRunner().invoke(
        cli,
        [
            "probe-chain",
            "--config",
            str(config),
            "--sarif",
            str(sarif_path),
            *SAFETY,
        ],
    )

    assert result.exit_code == 1, result.output
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    [entry] = sarif["runs"][0]["results"]
    assert entry["ruleId"] == "LATCH-CHAIN-CONFIRMED"
    assert entry["level"] == "error"
    assert entry["properties"]["chainStatus"] == "CONFIRMED_EXPLOITABLE"
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["tags"] == ["security", "CWE-200", "CWE-284"]


def test_sarif_has_no_error_for_blocked_chains(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-allowlisted")
    sarif_path = tmp_path / "chain.sarif"

    result = CliRunner().invoke(
        cli,
        [
            "probe-chain",
            "--config",
            str(config),
            "--sarif",
            str(sarif_path),
            *SAFETY,
        ],
    )

    assert result.exit_code == 0, result.output
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"] == []


def test_to_sarif_chain_report_round_trip(tmp_path: Path) -> None:
    from mcpprobe.chain_prober import ChainProbeResult, ChainVerificationReport

    report = ChainVerificationReport(
        server_count=1,
        static_paths_found=1,
        paths_tested=1,
        confirmed_exploitable=1,
        blocked_count=0,
        inconclusive_count=0,
        results=[
            ChainProbeResult(
                path_id="trifecta-001",
                ingest_tool="chain:fetch_issue",
                read_tool="chain:read_ledger",
                egress_tool="chain:post_webhook",
                static_severity="CRITICAL",
                verified_severity="CRITICAL",
                status="CONFIRMED_EXPLOITABLE",
                canary_token="LATCH-CANARY-0123456789abcdef",
                read_observed=True,
                egress_invoked=True,
                canary_captured_at_sink=True,
                sink_request_summary="POST /exfil (matched body)",
            )
        ],
        passed=False,
    )

    sarif = to_sarif(chain=report, artifact_uri="chain.json")

    [entry] = sarif["runs"][0]["results"]
    assert entry["ruleId"] == "LATCH-CHAIN-CONFIRMED"
    assert "POST /exfil" in entry["message"]["text"]
    assert entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "chain.json"
    )


# -- execution safety gates -------------------------------------------------


def test_probe_chain_refuses_to_execute_without_consent(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(config, safety=("--allow-all-tools",))

    assert result.exit_code == 2, result.output
    combined = result.output + getattr(result, "stderr", "")
    assert "i-understand-this-executes-tools" in combined
    assert "--dry-run" in combined


def test_probe_chain_requires_a_tool_allowlist(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(config, safety=("--i-understand-this-executes-tools",))

    assert result.exit_code == 2, result.output
    combined = result.output + getattr(result, "stderr", "")
    assert "--allow-tool" in combined
    assert "--allow-all-tools" in combined


def test_dry_run_synthesizes_arguments_without_executing(tmp_path: Path) -> None:
    # read-denied would block a real probe; a dry run must never call it.
    config = write_chain_config(tmp_path, "read-denied", "egress-open")

    result = run_probe(config, "--dry-run", safety=())

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run_count"] == 1
    assert payload["confirmed_exploitable"] == 0
    assert payload["passed"] is True
    [probe] = payload["results"]
    assert probe["status"] == "DRY_RUN_SKIPPED"
    assert probe["read_observed"] is False
    assert probe["egress_invoked"] is False
    assert probe["read_args"] == {"query": "SELECT * FROM records LIMIT 1"}
    assert probe["egress_args"]["webhook_url"].endswith("/exfil")
    assert "read output from chain:read_ledger" in probe["egress_args"]["payload"]


def test_dry_run_text_output_prints_the_arguments(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = CliRunner().invoke(
        cli, ["probe-chain", "--config", str(config), "--dry-run"]
    )

    assert result.exit_code == 0, result.output
    assert "DRY_RUN_SKIPPED" in result.output
    assert "read args: " in result.output
    assert "egress args: " in result.output


def test_allow_tool_scopes_which_paths_are_invoked(tmp_path: Path) -> None:
    config = write_two_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(
        config,
        "--allow-tool",
        "alpha:*",
        safety=("--i-understand-this-executes-tools",),
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    confirmed = [
        probe
        for probe in payload["results"]
        if probe["status"] == "CONFIRMED_EXPLOITABLE"
    ]
    skipped = [
        probe
        for probe in payload["results"]
        if probe["status"] == "SKIPPED_NOT_ALLOWLISTED"
    ]
    assert payload["confirmed_exploitable"] == len(confirmed) >= 1
    assert payload["skipped_not_allowlisted_count"] == len(skipped) >= 1
    for probe in confirmed:
        assert probe["read_tool"].startswith("alpha:")
        assert probe["egress_tool"].startswith("alpha:")
    for probe in skipped:
        assert not (
            probe["read_tool"].startswith("alpha:")
            and probe["egress_tool"].startswith("alpha:")
        )
        assert probe["egress_invoked"] is False
        assert probe["read_observed"] is False
        assert probe["verified_severity"] == probe["static_severity"]


def test_ssrf_guarded_egress_is_unconfirmed_not_blocked(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-ssrf-guard")

    result = run_probe(config)

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["confirmed_exploitable"] == 0
    assert payload["unconfirmed_ssrf_count"] == 1
    assert payload["blocked_count"] == 0
    assert payload["passed"] is False
    [probe] = payload["results"]
    assert probe["status"] == "UNCONFIRMED_SSRF_GUARD"
    assert probe["verified_severity"] == "CRITICAL"
    assert probe["canary_captured_at_sink"] is False
    assert "SSRF" in probe["block_reason"]
    assert "--sink-url" in probe["block_reason"]


def test_ssrf_guard_emits_sarif_warning(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-ssrf-guard")
    sarif_path = tmp_path / "ssrf.sarif"

    result = CliRunner().invoke(
        cli,
        [
            "probe-chain",
            "--config",
            str(config),
            "--sarif",
            str(sarif_path),
            *SAFETY,
        ],
    )

    assert result.exit_code == 1, result.output
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    [entry] = sarif["runs"][0]["results"]
    assert entry["ruleId"] == "LATCH-CHAIN-UNCONFIRMED-SSRF"
    assert entry["level"] == "warning"
    assert entry["properties"]["chainStatus"] == "UNCONFIRMED_SSRF_GUARD"
    assert entry["properties"]["tags"] == ["security", "CWE-200", "CWE-284"]


def test_sink_url_forwards_canary_to_operator_sink(tmp_path: Path) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    captured: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            captured.append(self.rfile.read(length))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        config = write_chain_config(tmp_path, "read-open", "egress-open")
        result = run_probe(config, "--sink-url", base)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    [probe] = payload["results"]
    assert probe["status"] == "UNCONFIRMED_SSRF_GUARD"
    assert "external operator sink" in (probe["sink_request_summary"] or "")
    assert captured, "operator sink received nothing"
    assert b"LATCH-CANARY-" in b"".join(captured)


def test_sink_url_trailing_slash_is_normalized() -> None:
    tool_definition = tool(
        "send_report",
        {"url": {"type": "string"}, "payload": {"type": "string"}},
        required=["url", "payload"],
    )

    args, has_channel = synthesize_egress_args(
        tool_definition, "https://sink.example/collect/", "payload"
    )

    assert has_channel is True
    assert args["url"] == "https://sink.example/collect/exfil"


def test_egress_rejection_classifier_separates_ssrf_from_allowlist() -> None:
    from mcpprobe.chain_prober import _is_ssrf_or_loopback_rejection

    assert _is_ssrf_or_loopback_rejection(
        "SSRF protection: loopback address 127.0.0.1 is blocked"
    )
    assert _is_ssrf_or_loopback_rejection("blocked private network destination")
    assert not _is_ssrf_or_loopback_rejection(
        "destination '127.0.0.1' is not in the *.corp.internal allowlist"
    )
    assert not _is_ssrf_or_loopback_rejection("rate limited, try later")


def test_canary_sink_rejects_oversized_content_length() -> None:
    async def scenario() -> tuple[bytes, str]:
        async with CanarySinkServer() as sink:
            reader, writer = await asyncio.open_connection("127.0.0.1", sink.port)
            writer.write(
                b"POST /exfil HTTP/1.1\r\n"
                b"Host: sink\r\n"
                b"Content-Length: 4194304\r\n"
                b"\r\n"
            )
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
            await writer.wait_closed()
            return raw, sink.captured_requests[0]["body"]

    raw, captured_body = asyncio.run(scenario())

    assert raw.startswith(b"HTTP/1.1 413")
    assert captured_body == ""


def test_allow_tool_bare_name_requires_single_server_mode() -> None:
    assert _tool_allowed("alpha", "read", {"read"}, allow_bare_names=True) is True
    assert _tool_allowed("beta", "read", {"read"}, allow_bare_names=False) is False
    assert _tool_allowed("beta", "read", {"beta:read"}, allow_bare_names=False) is True
    assert _tool_allowed("beta", "read", {"beta:*"}, allow_bare_names=False) is True
    assert _tool_allowed("beta", "other", {"beta:read"}, allow_bare_names=False) is False
    assert _tool_allowed("beta", "anything", {"*"}, allow_bare_names=False) is True
    assert _tool_allowed("beta", "read", None, allow_bare_names=False) is True


def test_validate_tool_allowlist_rejects_bare_names_for_multiple_servers() -> None:
    with pytest.raises(ProbeError, match="ambiguous --allow-tool"):
        validate_tool_allowlist({"read_ledger"}, ["alpha", "beta"])

    # A single mounted server, an explicit wildcard or a qualified name is fine.
    validate_tool_allowlist({"read_ledger"}, ["alpha"])
    validate_tool_allowlist({"*"}, ["alpha", "beta"])
    validate_tool_allowlist({"alpha:read_ledger"}, ["alpha", "beta"])
    validate_tool_allowlist(None, ["alpha", "beta"])


def test_canary_sink_caps_captured_requests_and_keeps_the_first() -> None:
    async def scenario() -> tuple[int, int, bool, int]:
        async with CanarySinkServer() as sink:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{sink.base_url}/exfil?marker=LATCH-CANARY-first"
                )
                last_status = 0
                for index in range(119):
                    response = await client.post(
                        f"{sink.base_url}/flood", content=f"flood-{index}"
                    )
                    last_status = response.status_code
            return (
                len(sink.captured_requests),
                sink.dropped_request_count,
                sink.find_canary("LATCH-CANARY-first") is not None,
                last_status,
            )

    captured, dropped, found, last_status = asyncio.run(scenario())

    assert CanarySinkServer.MAX_CANARY_REQUESTS == 100
    assert captured == 100
    assert dropped == 20
    assert found is True
    assert last_status == 200


def test_result_text_extracts_string_errors() -> None:
    assert (
        _result_text({"isError": True, "error": "  permission denied  "})
        == "permission denied"
    )
    assert (
        _error_text({"isError": True, "error": "permission denied"})
        == "permission denied"
    )
    assert _error_text({"isError": True}) == "tool returned isError without a message"


def test_probe_chain_rejects_bare_allow_tool_with_multiple_servers(
    tmp_path: Path,
) -> None:
    config = write_two_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(
        config,
        "--allow-tool",
        "read_ledger",
        safety=("--i-understand-this-executes-tools",),
    )

    assert result.exit_code == 2, result.output
    assert "<server>:<tool>" in result.output
    assert "alpha" in result.output and "beta" in result.output
    assert "CONFIRMED_EXPLOITABLE" not in result.output


def test_qualified_allow_tool_only_executes_the_named_server(tmp_path: Path) -> None:
    config = write_two_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(
        config,
        "--allow-tool",
        "alpha:read_ledger",
        "--allow-tool",
        "alpha:post_webhook",
        safety=("--i-understand-this-executes-tools",),
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    confirmed = [
        probe
        for probe in payload["results"]
        if probe["status"] == "CONFIRMED_EXPLOITABLE"
    ]
    assert confirmed
    for probe in confirmed:
        assert probe["read_tool"].startswith("alpha:")
        assert probe["egress_tool"].startswith("alpha:")
    for probe in payload["results"]:
        if probe["status"] == "SKIPPED_NOT_ALLOWLISTED":
            assert probe["egress_invoked"] is False
            assert probe["read_observed"] is False
    assert payload["skipped_not_allowlisted_count"] >= 1


def test_bare_allow_tool_still_works_with_one_server(tmp_path: Path) -> None:
    config = write_chain_config(tmp_path, "read-open", "egress-open")

    result = run_probe(
        config,
        "--allow-tool",
        "read_ledger",
        "--allow-tool",
        "post_webhook",
        safety=("--i-understand-this-executes-tools",),
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["paths_tested"] == 1
    assert payload["skipped_not_allowlisted_count"] == 0
    assert payload["results"][0]["read_tool"] == "chain:read_ledger"
    assert payload["results"][0]["egress_tool"] == "chain:post_webhook"
