"""Live MCP harvesting over ``stdio`` and Streamable HTTP.

Both transports implement the same two-step dance:

1. **2026-07-28 discovery** -- ``server/discover`` with the protocol version and
   client info in ``params._meta``.
2. **2025-11-25 fallback** -- if discovery is rejected (JSON-RPC ``-32601``, or
   HTTP ``400``/``404``), run the classic ``initialize`` handshake, capture any
   ``Mcp-Session-Id`` and send ``notifications/initialized``.

``tools/list`` is then fetched page by page until ``nextCursor`` stops being
returned.

Security posture: harvesting only ever *reads* from the server it is pointed at.
Executing a tool is opt-in and lives in ``call_tool``, which the chain prober uses
for non-destructive canary probes; a JSON-RPC error is normalized into an
``isError`` tool result so one blocked tool cannot abort a batch.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Literal

import httpx
from pydantic import BaseModel

from . import __version__
from .models import ProbeError, ToolDefinition, parse_tools_payload

if TYPE_CHECKING:  # pragma: no cover - annotation only
    from .config_loader import ServerSpec

PROTOCOL_2026 = "2026-07-28"
PROTOCOL_2025 = "2025-11-25"

DEFAULT_TIMEOUT = 10.0

CLIENT_INFO: dict[str, str] = {"name": "latch", "version": __version__}

_SUBSCRIPTIONS_UNSUPPORTED = (
    "server does not support subscriptions/listen (HTTP {status}): it cannot push"
    " notifications/tools/list_changed, so mid-session watching is unavailable."
    " Re-harvest with 'latch verify' or poll instead."
)


class JsonRpcError(ProbeError):
    """A JSON-RPC error response from the server."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.rpc_message = message


class TransportTimeout(ProbeError):
    """The server did not answer within the configured timeout."""


class TransportClosed(ProbeError):
    """The server process or connection closed before answering."""


class _UnsupportedByServer(ProbeError):
    """The server rejected 2026-07-28 discovery, so fall back to 2025-11-25."""


class HarvestResult(BaseModel):
    """A normalized ``tools/list`` snapshot harvested from a live server."""

    tools_payload: dict[str, Any]
    protocol_version: str
    transport: Literal["stdio", "http"]
    server_info: dict[str, Any] | None = None
    capabilities: dict[str, Any] | None = None
    session_id: str | None = None


def request_meta(protocol_version: str = PROTOCOL_2026) -> dict[str, Any]:
    """The ``_meta`` envelope 2026-07-28 servers require on every request.

    Real servers reject a request whose envelope omits
    ``io.modelcontextprotocol/clientCapabilities``, and validate it for
    ``server/discover``, ``initialize`` and ``tools/list`` alike.
    """

    return {
        "io.modelcontextprotocol/protocolVersion": protocol_version,
        "io.modelcontextprotocol/clientInfo": dict(CLIENT_INFO),
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def discover_params() -> dict[str, Any]:
    """``server/discover`` params, including the required ``_meta`` block."""

    return {"_meta": request_meta(PROTOCOL_2026)}


def initialize_params() -> dict[str, Any]:
    """``initialize`` params for the 2025-11-25 handshake.

    Newer servers validate the same ``_meta`` envelope the 2026-07-28
    ``server/discover`` request uses, even while falling back to the older
    handshake, so the envelope is sent in both.
    """

    return {
        "protocolVersion": PROTOCOL_2025,
        "capabilities": {},
        "clientInfo": dict(CLIENT_INFO),
        "_meta": request_meta(PROTOCOL_2025),
    }


def _require_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def normalize_tool_error(error: Any) -> dict[str, Any]:
    """Turn a JSON-RPC error into a tool result the prober can reason about."""

    return {
        "isError": True,
        "error": error,
        "content": [{"type": "text", "text": str(error)}],
    }


def _apply_handshake(target: Any, result: dict[str, Any]) -> None:
    """Copy protocol version, serverInfo and capabilities onto ``target``."""

    version = result.get("protocolVersion")
    if isinstance(version, str) and version:
        target.protocol_version = version
    target.server_info = _require_dict(result.get("serverInfo"))
    target.capabilities = _require_dict(result.get("capabilities"))


async def _paginate(
    fetch: Callable[[str | None], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:
    """Follow ``nextCursor`` until the server stops returning one."""

    tools: list[Any] = []
    extras: dict[str, Any] = {}
    cursor: str | None = None
    seen_cursors: set[str] = set()

    while True:
        result = await fetch(cursor)
        page = result.get("tools")
        if not isinstance(page, list):
            raise ProbeError("tools/list result has no 'tools' array")
        tools.extend(page)
        for key in ("ttlMs", "cacheScope"):
            if key in result and key not in extras:
                extras[key] = result[key]

        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            break
        if not isinstance(next_cursor, str):
            raise ProbeError(f"tools/list returned a non-string nextCursor: {next_cursor!r}")
        if not next_cursor:
            break
        if next_cursor in seen_cursors:
            raise ProbeError(f"tools/list pagination loop detected on cursor {next_cursor!r}")
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return {"tools": tools, **extras}


class StdioSession:
    """A newline-delimited JSON-RPC 2.0 session over a child process."""

    def __init__(
        self,
        command: str | list[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.command = command
        self.timeout = timeout
        self.protocol_version = PROTOCOL_2026
        self.server_info: dict[str, Any] | None = None
        self.capabilities: dict[str, Any] | None = None

        self._cwd = cwd
        self._env = env
        self._proc: asyncio.subprocess.Process | None = None
        self._next_request_id = 0
        self._notifications: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        # Bounded: a chatty server must not grow this list for the life of a watch.
        self._stderr_lines: deque[str] = deque(maxlen=20)
        self._stderr_task: asyncio.Task[None] | None = None

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        argv = (
            shlex.split(self.command)
            if isinstance(self.command, str)
            else list(self.command)
        )
        if not argv:
            raise ProbeError("empty --stdio command")
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._cwd,
                env=self._env,
                # The default 64 KiB StreamReader limit makes readline() raise
                # ValueError on a single large tools/list line.
                limit=16 * 1024 * 1024,
            )
        except OSError as exc:
            raise ProbeError(f"cannot start MCP server {argv[0]!r}: {exc}") from exc

        self._stderr_task = asyncio.create_task(self._drain_stderr())

    async def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        while True:
            line = await proc.stderr.readline()
            if not line:
                return
            self._stderr_lines.append(line.decode("utf-8", "replace"))

    def _stderr_context(self) -> str:
        if not self._stderr_lines:
            return ""
        tail = "".join(list(self._stderr_lines)[-10:]).strip()
        return f"\nserver stderr:\n{tail}" if tail else ""

    async def close(self) -> None:
        """Close stdin, then wait / terminate / kill the child."""

        if self._stderr_task is not None:
            self._stderr_task.cancel()
            self._stderr_task = None

        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin is not None and not proc.stdin.is_closing():
                proc.stdin.close()
        except OSError:  # pragma: no cover - defensive
            pass

        if proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:  # pragma: no cover - stubborn child
                    proc.kill()
                    await proc.wait()
        self._proc = None

    # -- messaging ---------------------------------------------------------

    def _allocate_id(self) -> int:
        self._next_request_id += 1
        return self._next_request_id

    async def _send(self, message: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise TransportClosed("MCP server stdin is not available")
        data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            proc.stdin.write(data)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise TransportClosed(
                f"MCP server closed its stdin before the request was sent{self._stderr_context()}"
            ) from exc

    async def _read_message(self, deadline: float) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        proc = self._proc
        if proc is None or proc.stdout is None:
            raise TransportClosed("MCP server stdout is not available")

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TransportTimeout(
                    f"timed out after {self.timeout:g}s waiting for an MCP response"
                    f"{self._stderr_context()}"
                )
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except asyncio.TimeoutError:
                raise TransportTimeout(
                    f"timed out after {self.timeout:g}s waiting for an MCP response"
                    f"{self._stderr_context()}"
                ) from None
            if not line:
                raise TransportClosed(
                    "MCP server exited before responding"
                    f" (exit code {proc.returncode}){self._stderr_context()}"
                )
            text = line.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                message = json.loads(text)
            except json.JSONDecodeError:
                # Servers sometimes log plain text to stdout; it is not JSON-RPC.
                continue
            if isinstance(message, dict):
                return message

    async def request(
        self, method: str, params: dict[str, Any] | None = None, *, timeout: float | None = None
    ) -> dict[str, Any]:
        """Send a request and return its JSON-RPC ``result`` object."""

        request_id = self._allocate_id()
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        await self._send(message)

        limit = self.timeout if timeout is None else timeout
        deadline = asyncio.get_running_loop().time() + limit
        while True:
            reply = await self._read_message(deadline)
            if "method" in reply and "id" not in reply:
                # Unrelated notification: queue it for watchers, keep waiting.
                self._notifications.put_nowait(reply)
                continue
            if reply.get("id") != request_id:
                continue
            error = reply.get("error")
            if isinstance(error, dict):
                code = error.get("code")
                raise JsonRpcError(
                    int(code) if isinstance(code, int) else -32000,
                    str(error.get("message", "unknown error")),
                )
            result = reply.get("result")
            return result if isinstance(result, dict) else {}

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        await self._send(message)

    async def next_notification(self, deadline: float | None = None) -> dict[str, Any] | None:
        """Return the next notification, or ``None`` when the deadline passes."""

        loop = asyncio.get_running_loop()
        while True:
            try:
                return self._notifications.get_nowait()
            except asyncio.QueueEmpty:
                pass

            remaining = self.timeout if deadline is None else deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                message = await self._read_message(loop.time() + remaining)
            except TransportTimeout:
                return None
            if "method" in message and "id" not in message:
                return message

    # -- MCP operations ----------------------------------------------------

    async def negotiate(self) -> None:
        """Run 2026-07-28 discovery, falling back to the 2025-11-25 handshake."""

        try:
            result = await self.request("server/discover", discover_params())
        except JsonRpcError as exc:
            if exc.code != -32601:
                raise
        else:
            _apply_handshake(self, result)
            return

        self.protocol_version = PROTOCOL_2025
        result = await self.request("initialize", initialize_params())
        _apply_handshake(self, result)
        await self.notify("notifications/initialized")

    async def fetch_tools(self) -> dict[str, Any]:
        async def fetch(cursor: str | None) -> dict[str, Any]:
            params: dict[str, Any] = {"_meta": request_meta(self.protocol_version)}
            if cursor:
                params["cursor"] = cursor
            return await self.request("tools/list", params)

        return await _paginate(fetch)

    async def harvest(self) -> HarvestResult:
        await self.negotiate()
        payload = await self.fetch_tools()
        return HarvestResult(
            tools_payload=payload,
            protocol_version=self.protocol_version,
            transport="stdio",
            server_info=self.server_info,
            capabilities=self.capabilities,
            session_id=None,
        )

    async def list_tools(self) -> list[ToolDefinition]:
        """Return every tool the server currently advertises."""

        return parse_tools_payload(await self.fetch_tools())

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Invoke ``tools/call``; JSON-RPC errors become ``isError`` results."""

        try:
            return await self.request(
                "tools/call", {"name": name, "arguments": arguments or {}}
            )
        except JsonRpcError as exc:
            return normalize_tool_error({"code": exc.code, "message": exc.rpc_message})


def _sse_messages(text: str) -> list[dict[str, Any]]:
    """Extract JSON-RPC messages from the ``data:`` lines of an SSE body."""

    messages: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("data:"):
            continue
        payload = stripped[len("data:") :].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            messages.append(parsed)
    return messages


def _rpc_body(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        data = data[0] if data else None
    return data if isinstance(data, dict) else None


def _rpc_error_code(text: str) -> int | None:
    body = _rpc_body(text)
    if body is None:
        return None
    error = body.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, int) else None


def _select_message(messages: list[dict[str, Any]], request_id: int) -> dict[str, Any]:
    for message in messages:
        if message.get("id") == request_id:
            return message
    for message in messages:
        if isinstance(message.get("error"), dict):
            return message
    raise ProbeError("no JSON-RPC response with a matching id in the HTTP response")


class HttpHarvester:
    """A Streamable HTTP MCP client (POST JSON, JSON or SSE responses)."""

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.custom_headers = dict(headers or {})
        self.protocol_version = PROTOCOL_2026
        self.server_info: dict[str, Any] | None = None
        self.capabilities: dict[str, Any] | None = None
        self.session_id: str | None = None
        self._next_request_id = 0
        self._client = httpx.AsyncClient(transport=transport, timeout=timeout)

    async def close(self) -> None:
        await self._client.aclose()

    def _allocate_id(self) -> int:
        self._next_request_id += 1
        return self._next_request_id

    def _headers(self, method: str) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": self.protocol_version,
            "Mcp-Method": method,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        headers.update(self.custom_headers)
        return headers

    async def _post(
        self, message: dict[str, Any], method: str, *, timeout: float | None = None
    ) -> httpx.Response:
        try:
            return await self._client.post(
                self.url,
                json=message,
                headers=self._headers(method),
                timeout=self.timeout if timeout is None else timeout,
            )
        except httpx.HTTPError as exc:
            raise ProbeError(f"HTTP transport error talking to {self.url}: {exc}") from exc

    def _result_of(self, response: httpx.Response, request_id: int) -> dict[str, Any]:
        if response.status_code in (202, 204):
            return {}
        if response.status_code >= 400:
            code = _rpc_error_code(response.text)
            if code is not None:
                body = _rpc_body(response.text) or {}
                error = body.get("error") or {}
                raise JsonRpcError(code, str(error.get("message", "unknown error")))
            raise ProbeError(
                f"HTTP {response.status_code} from {self.url}: {response.text.strip()[:200]}"
            )
        text = response.text
        if not text.strip():
            return {}

        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            message = _select_message(_sse_messages(text), request_id)
        else:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ProbeError(f"invalid JSON response from {self.url}: {exc}") from exc
            messages = parsed if isinstance(parsed, list) else [parsed]
            message = _select_message(
                [item for item in messages if isinstance(item, dict)], request_id
            )

        error = message.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            raise JsonRpcError(
                int(code) if isinstance(code, int) else -32000,
                str(error.get("message", "unknown error")),
            )
        result = message.get("result")
        return result if isinstance(result, dict) else {}

    async def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        probe: bool = False,
    ) -> dict[str, Any]:
        request_id = self._allocate_id()
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        response = await self._post(message, method)
        if probe and response.status_code in (400, 404):
            raise _UnsupportedByServer(f"server rejected {method} with HTTP {response.status_code}")
        return self._result_of(response, request_id)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        response = await self._post(message, method)
        if response.status_code >= 400:
            code = _rpc_error_code(response.text)
            if code is not None:
                body = _rpc_body(response.text) or {}
                error = body.get("error") or {}
                raise JsonRpcError(code, str(error.get("message", "unknown error")))
            raise ProbeError(
                f"HTTP {response.status_code} from {self.url} for {method}:"
                f" {response.text.strip()[:200]}"
            )

    async def negotiate(self) -> None:
        try:
            result = await self.call("server/discover", discover_params(), probe=True)
        except _UnsupportedByServer:
            pass
        except JsonRpcError as exc:
            if exc.code != -32601:
                raise
        else:
            _apply_handshake(self, result)
            return

        # Legacy handshake: protocol header must be 2025-11-25 for this exchange.
        self.protocol_version = PROTOCOL_2025
        request_id = self._allocate_id()
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": initialize_params(),
        }
        response = await self._post(message, "initialize")
        session_id = response.headers.get("mcp-session-id")
        if session_id:
            self.session_id = session_id
        result = self._result_of(response, request_id)
        _apply_handshake(self, result)
        await self.notify("notifications/initialized")

    async def fetch_tools(self) -> dict[str, Any]:
        async def fetch(cursor: str | None) -> dict[str, Any]:
            params: dict[str, Any] = {"_meta": request_meta(self.protocol_version)}
            if cursor:
                params["cursor"] = cursor
            return await self.call("tools/list", params)

        return await _paginate(fetch)

    async def harvest(self) -> HarvestResult:
        await self.negotiate()
        payload = await self.fetch_tools()
        return HarvestResult(
            tools_payload=payload,
            protocol_version=self.protocol_version,
            transport="http",
            server_info=self.server_info,
            capabilities=self.capabilities,
            session_id=self.session_id,
        )

    async def list_tools(self) -> list[ToolDefinition]:
        """Return every tool the server currently advertises."""

        return parse_tools_payload(await self.fetch_tools())

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Invoke ``tools/call``; JSON-RPC errors become ``isError`` results."""

        try:
            return await self.call(
                "tools/call", {"name": name, "arguments": arguments or {}}
            )
        except JsonRpcError as exc:
            return normalize_tool_error({"code": exc.code, "message": exc.rpc_message})

    async def listen_stream(
        self, params: dict[str, Any] | None = None, *, timeout: float | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """POST ``subscriptions/listen`` and yield JSON-RPC messages from the SSE stream."""

        request_id = self._allocate_id()
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "subscriptions/listen",
            "params": params or {},
        }
        headers = self._headers("subscriptions/listen")
        try:
            async with self._client.stream(
                "POST",
                self.url,
                json=message,
                headers=headers,
                timeout=self.timeout if timeout is None else timeout,
            ) as response:
                if response.status_code in (404, 405):
                    raise ProbeError(
                        _SUBSCRIPTIONS_UNSUPPORTED.format(status=response.status_code)
                    )
                if response.status_code >= 400:
                    body = (await response.aread()).decode("utf-8", "replace")
                    if _rpc_error_code(body) == -32601:
                        raise ProbeError(
                            _SUBSCRIPTIONS_UNSUPPORTED.format(status=response.status_code)
                        )
                    raise ProbeError(
                        f"subscriptions/listen failed with HTTP {response.status_code}:"
                        f" {body.strip()[:200]}"
                    )
                async for line in response.aiter_lines():
                    stripped = line.strip()
                    if not stripped.startswith("data:"):
                        continue
                    payload = stripped[len("data:") :].strip()
                    if not payload or payload == "[DONE]":
                        continue
                    try:
                        parsed = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(parsed, dict):
                        yield parsed
        except httpx.HTTPError as exc:
            raise ProbeError(f"HTTP transport error while listening on {self.url}: {exc}") from exc


@asynccontextmanager
async def open_mcp_session(
    spec: "ServerSpec",
    *,
    timeout: float = DEFAULT_TIMEOUT,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> AsyncIterator[Any]:
    """Negotiate a live MCP session for a stdio or HTTP server spec.

    Yields a session exposing ``list_tools()`` and ``call_tool(name, arguments)``.
    """

    if spec.transport == "stdio":
        command = list(spec.command or [])
        if not command:
            raise ProbeError(f"server {spec.server_id!r} has no command to launch")
        env = {**os.environ, **(spec.env or {})}
        session = StdioSession(command, timeout=timeout, env=env)
        await session.start()
        try:
            await session.negotiate()
            yield session
        finally:
            await session.close()
        return

    if spec.transport == "http":
        if not spec.url:
            raise ProbeError(f"server {spec.server_id!r} has no url to connect to")
        harvester = HttpHarvester(
            spec.url,
            headers=spec.headers or None,
            timeout=timeout,
            transport=http_transport,
        )
        try:
            await harvester.negotiate()
            yield harvester
        finally:
            await harvester.close()
        return

    raise ProbeError(
        f"server {spec.server_id!r} is a static snapshot; live execution requires a"
        " stdio or http server"
    )


async def harvest_stdio(
    command: str | list[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    env: dict[str, str] | None = None,
) -> HarvestResult:
    """Harvest ``tools/list`` from a local MCP server over stdio."""

    process_env = {**os.environ, **env} if env else None
    session = StdioSession(command, timeout=timeout, env=process_env)
    await session.start()
    try:
        return await session.harvest()
    finally:
        await session.close()


async def harvest_http(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    transport: httpx.AsyncBaseTransport | None = None,
) -> HarvestResult:
    """Harvest ``tools/list`` from a Streamable HTTP MCP endpoint."""

    harvester = HttpHarvester(url, headers=headers, timeout=timeout, transport=transport)
    try:
        return await harvester.harvest()
    finally:
        await harvester.close()
