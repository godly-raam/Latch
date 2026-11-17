"""Tests for live MCP harvesting over stdio and Streamable HTTP."""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest

from mcpprobe.models import ProbeError
from mcpprobe.transport import (
    PROTOCOL_2025,
    PROTOCOL_2026,
    StdioSession,
    TransportTimeout,
    harvest_http,
    harvest_stdio,
)

FIXTURE = Path(__file__).parent / "fixtures" / "mock_mcp_stdio.py"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "echo",
        "description": "Echo text back.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "add",
        "description": "Add two integers.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
            "required": ["a", "b"],
        },
    },
]


def fixture_command(*args: str) -> str:
    return " ".join([shlex.quote(sys.executable), shlex.quote(str(FIXTURE)), *args])


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def json_result(request: httpx.Request, result: dict[str, Any], **kwargs: Any) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(
        kwargs.pop("status_code", 200),
        json={"jsonrpc": "2.0", "id": body.get("id"), "result": result},
        **kwargs,
    )


def rpc_error(
    request: httpx.Request, code: int, message: str = "error", **kwargs: Any
) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(
        kwargs.pop("status_code", 200),
        json={"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": code, "message": message}},
        **kwargs,
    )


def make_transport(
    routes: dict[str, Callable[[httpx.Request], httpx.Response]]
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body["method"]
        if method not in routes:
            raise AssertionError(f"unexpected MCP method {method}")
        return routes[method](request)

    return httpx.MockTransport(handler)


def discovery_route(
    version: str = PROTOCOL_2026,
) -> Callable[[httpx.Request], httpx.Response]:
    def route(request: httpx.Request) -> httpx.Response:
        return json_result(
            request,
            {
                "protocolVersion": version,
                "serverInfo": {"name": "mock-http", "version": "0.0.1"},
                "capabilities": {"tools": {"listChanged": True}},
            },
        )

    return route


# -- Streamable HTTP -------------------------------------------------------


def test_harvest_http_json_2026() -> None:
    seen: list[httpx.Request] = []

    def discover(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return discovery_route()(request)

    def tools(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return json_result(request, {"tools": TOOLS})

    result = run(
        harvest_http(
            "http://mcp.test/mcp",
            transport=make_transport({"server/discover": discover, "tools/list": tools}),
        )
    )

    assert result.transport == "http"
    assert result.protocol_version == PROTOCOL_2026
    assert result.server_info == {"name": "mock-http", "version": "0.0.1"}
    assert result.capabilities == {"tools": {"listChanged": True}}
    assert result.session_id is None
    assert [tool["name"] for tool in result.tools_payload["tools"]] == ["echo", "add"]

    headers = seen[0].headers
    assert headers["accept"] == "application/json, text/event-stream"
    assert headers["content-type"] == "application/json"
    assert headers["mcp-protocol-version"] == PROTOCOL_2026
    assert headers["mcp-method"] == "server/discover"
    assert "mcp-session-id" not in headers

    body = json.loads(seen[0].content)
    meta = body["params"]["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == PROTOCOL_2026
    assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "latch"
    assert json.loads(seen[1].content)["method"] == "tools/list"


def test_harvest_http_sse_response() -> None:
    def tools(request: httpx.Request) -> httpx.Response:
        request_id = json.loads(request.content)["id"]
        stream = (
            "event: message\n"
            'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
            "event: message\n"
            f"data: {json.dumps({'jsonrpc': '2.0', 'id': request_id, 'result': {'tools': TOOLS}})}\n\n"
        )
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, text=stream
        )

    result = run(
        harvest_http(
            "http://mcp.test/mcp",
            transport=make_transport(
                {"server/discover": discovery_route(), "tools/list": tools}
            ),
        )
    )

    assert [tool["name"] for tool in result.tools_payload["tools"]] == ["echo", "add"]


def test_harvest_http_pagination_follows_next_cursor() -> None:
    cursors: list[Any] = []

    def tools(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        cursor = (body.get("params") or {}).get("cursor")
        cursors.append(cursor)
        if cursor is None:
            return json_result(request, {"tools": TOOLS[:1], "nextCursor": "page-2", "ttlMs": 1000})
        return json_result(request, {"tools": TOOLS[1:]})

    result = run(
        harvest_http(
            "http://mcp.test/mcp",
            transport=make_transport(
                {"server/discover": discovery_route(), "tools/list": tools}
            ),
        )
    )

    assert cursors == [None, "page-2"]
    assert [tool["name"] for tool in result.tools_payload["tools"]] == ["echo", "add"]
    assert result.tools_payload["ttlMs"] == 1000


def test_harvest_http_pagination_loop_is_rejected() -> None:
    def tools(request: httpx.Request) -> httpx.Response:
        return json_result(request, {"tools": TOOLS, "nextCursor": "same"})

    with pytest.raises(ProbeError, match="pagination loop"):
        run(
            harvest_http(
                "http://mcp.test/mcp",
                transport=make_transport(
                    {"server/discover": discovery_route(), "tools/list": tools}
                ),
            )
        )


def test_harvest_http_2025_fallback_captures_session_id() -> None:
    by_method: dict[str, httpx.Request] = {}

    def discover(request: httpx.Request) -> httpx.Response:
        by_method["discover"] = request
        return httpx.Response(404, text="unknown endpoint")

    def initialize(request: httpx.Request) -> httpx.Response:
        by_method["initialize"] = request
        return json_result(
            request,
            {
                "protocolVersion": PROTOCOL_2025,
                "serverInfo": {"name": "legacy"},
                "capabilities": {},
            },
            headers={"Mcp-Session-Id": "sess-123"},
        )

    def initialized(request: httpx.Request) -> httpx.Response:
        by_method["initialized"] = request
        return httpx.Response(202, text="")

    def tools(request: httpx.Request) -> httpx.Response:
        by_method["tools"] = request
        return json_result(request, {"tools": TOOLS})

    result = run(
        harvest_http(
            "http://mcp.test/mcp",
            transport=make_transport(
                {
                    "server/discover": discover,
                    "initialize": initialize,
                    "notifications/initialized": initialized,
                    "tools/list": tools,
                }
            ),
        )
    )

    assert result.protocol_version == PROTOCOL_2025
    assert result.session_id == "sess-123"
    assert result.server_info == {"name": "legacy"}
    assert by_method["initialize"].headers["mcp-protocol-version"] == PROTOCOL_2025
    assert by_method["tools"].headers["mcp-session-id"] == "sess-123"
    assert by_method["tools"].headers["mcp-protocol-version"] == PROTOCOL_2025
    assert by_method["initialized"].headers["mcp-method"] == "notifications/initialized"

    init_body = json.loads(by_method["initialize"].content)
    assert init_body["params"]["protocolVersion"] == PROTOCOL_2025
    assert init_body["params"]["clientInfo"]["name"] == "latch"
    assert init_body["params"]["capabilities"] == {}


def test_harvest_http_2025_fallback_on_method_not_found() -> None:
    def initialize(request: httpx.Request) -> httpx.Response:
        return json_result(
            request, {"protocolVersion": PROTOCOL_2025, "serverInfo": {"name": "legacy"}}
        )

    result = run(
        harvest_http(
            "http://mcp.test/mcp",
            transport=make_transport(
                {
                    "server/discover": lambda request: rpc_error(request, -32601, "Method not found"),
                    "initialize": initialize,
                    "notifications/initialized": lambda request: httpx.Response(202, text=""),
                    "tools/list": lambda request: json_result(request, {"tools": TOOLS}),
                }
            ),
        )
    )

    assert result.protocol_version == PROTOCOL_2025
    assert result.session_id is None


def test_harvest_http_forwards_custom_headers() -> None:
    seen: list[httpx.Request] = []

    def tools(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return json_result(request, {"tools": TOOLS})

    run(
        harvest_http(
            "http://mcp.test/mcp",
            headers={"Authorization": "Bearer test-token"},
            transport=make_transport(
                {"server/discover": discovery_route(), "tools/list": tools}
            ),
        )
    )

    assert seen[0].headers["authorization"] == "Bearer test-token"


def test_harvest_http_jsonrpc_error_is_probe_error() -> None:
    with pytest.raises(ProbeError, match="-32603"):
        run(
            harvest_http(
                "http://mcp.test/mcp",
                transport=make_transport(
                    {
                        "server/discover": discovery_route(),
                        "tools/list": lambda request: rpc_error(request, -32603, "Internal error"),
                    }
                ),
            )
        )


def test_harvest_http_missing_tools_array_is_probe_error() -> None:
    with pytest.raises(ProbeError, match="tools"):
        run(
            harvest_http(
                "http://mcp.test/mcp",
                transport=make_transport(
                    {
                        "server/discover": discovery_route(),
                        "tools/list": lambda request: json_result(request, {}),
                    }
                ),
            )
        )


def test_harvest_http_error_status_is_probe_error() -> None:
    with pytest.raises(ProbeError, match="500"):
        run(
            harvest_http(
                "http://mcp.test/mcp",
                transport=make_transport(
                    {
                        "server/discover": discovery_route(),
                        "tools/list": lambda request: httpx.Response(500, text="boom"),
                    }
                ),
            )
        )


def test_harvest_http_transport_failure_is_probe_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(ProbeError, match="HTTP transport error"):
        run(harvest_http("http://mcp.test/mcp", transport=httpx.MockTransport(boom)))


# -- stdio -----------------------------------------------------------------


def test_harvest_stdio_2026() -> None:
    result = run(harvest_stdio(fixture_command("--mode", "2026")))

    assert result.transport == "stdio"
    assert result.protocol_version == PROTOCOL_2026
    assert result.server_info == {"name": "mock-stdio", "version": "0.0.1"}
    assert result.session_id is None
    assert [tool["name"] for tool in result.tools_payload["tools"]] == ["echo", "add"]


def test_harvest_stdio_2025_fallback() -> None:
    result = run(harvest_stdio(fixture_command("--mode", "2025")))

    assert result.protocol_version == PROTOCOL_2025
    assert result.server_info == {"name": "mock-stdio", "version": "0.0.1"}


def test_harvest_stdio_pagination() -> None:
    result = run(harvest_stdio(fixture_command("--paginate")))

    assert [tool["name"] for tool in result.tools_payload["tools"]] == ["echo", "add"]
    assert result.tools_payload["ttlMs"] == 60_000


def test_harvest_stdio_bad_command_is_probe_error() -> None:
    with pytest.raises(ProbeError, match="cannot start MCP server"):
        run(harvest_stdio("/nonexistent/mcp-server-binary"))


def test_harvest_stdio_timeout_is_probe_error() -> None:
    command = f"{shlex.quote(sys.executable)} -c {shlex.quote('import time; time.sleep(30)')}"

    with pytest.raises(TransportTimeout, match="timed out"):
        run(harvest_stdio(command, timeout=0.3))


def test_harvest_stdio_premature_exit_is_probe_error() -> None:
    script = 'import sys; sys.stderr.write("boom\\n"); sys.exit(3)'
    command = f"{shlex.quote(sys.executable)} -c {shlex.quote(script)}"

    with pytest.raises(ProbeError, match="exited"):
        run(harvest_stdio(command, timeout=5.0))


def test_stdio_session_queues_change_notification() -> None:
    async def scenario() -> tuple[Any, dict[str, Any]]:
        session = StdioSession(fixture_command("--rug-pull"), timeout=5.0)
        await session.start()
        try:
            harvest = await session.harvest()
            loop = asyncio.get_running_loop()
            message = await session.next_notification(loop.time() + 5.0)
            return harvest, message
        finally:
            await session.close()

    harvest, message = run(scenario())

    assert len(harvest.tools_payload["tools"]) == 2
    assert message is not None
    assert message["method"] == "notifications/tools/list_changed"


def test_stdio_session_next_notification_times_out() -> None:
    async def scenario() -> Any:
        session = StdioSession(fixture_command("--mode", "2026"), timeout=5.0)
        await session.start()
        try:
            await session.harvest()
            loop = asyncio.get_running_loop()
            return await session.next_notification(loop.time() + 0.2)
        finally:
            await session.close()

    assert run(scenario()) is None
