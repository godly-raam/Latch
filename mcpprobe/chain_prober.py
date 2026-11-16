"""Execution-aware lethal-trifecta canary prober.

``analyze_capability_graph`` answers "could untrusted input, private data and
egress line up?" from static metadata, which is deliberately conservative: a
server may reject the read (RBAC) or refuse the destination (allowlist/SSRF
guard), and the chain never fires. This module answers the next question --
"does it actually fire?" -- by executing the two halves of every static chain
against the live server with a canary.

The probe is non-destructive by construction:

* the read tool is called with benign, read-only arguments;
* the egress destination is an ephemeral HTTP sink bound to ``127.0.0.1:0``
  owned by this process, never a third party;
* success is proven by the sink receiving a fresh
  ``LATCH-CANARY-<16hex>`` token, not by trusting the tool's own text.

Every static ``TrifectaPath`` therefore resolves to ``CONFIRMED_EXPLOITABLE``,
``BLOCKED_AT_READ``, ``BLOCKED_AT_EGRESS`` or ``INCONCLUSIVE_SCHEMA``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import re
import uuid
from collections.abc import Sequence
from contextlib import AsyncExitStack
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from .config_loader import ServerSpec
from .graph import TrifectaPath, analyze_capability_graph
from .models import ToolDefinition
from .transport import DEFAULT_TIMEOUT, open_mcp_session

ChainProbeStatus = Literal[
    "CONFIRMED_EXPLOITABLE",
    "BLOCKED_AT_READ",
    "BLOCKED_AT_EGRESS",
    "INCONCLUSIVE_SCHEMA",
]

#: Parameters that make a read-only probe query.
READ_QUERY_PARAMS = frozenset({"query", "sql", "statement"})
READ_PATH_PARAMS = frozenset({"path", "file", "filename", "filepath", "file_path"})
READ_ID_PARAMS = frozenset({"id", "account_id", "user_id", "ledger_id"})

#: Parameters that choose where an egress tool sends data.
URL_PARAMS = frozenset(
    {
        "url",
        "uri",
        "webhook",
        "webhook_url",
        "callback_url",
        "target_url",
        "destination_url",
        "endpoint",
    }
)

RECIPIENT_PARAMS = frozenset({"to", "cc", "bcc", "recipient", "email", "channel"})

PAYLOAD_PARAMS = frozenset(
    {
        "body",
        "content",
        "message",
        "text",
        "payload",
        "data",
        "comment",
        "description",
        "query",
        "title",
        "subject",
        "note",
    }
)

#: How long to wait for the sink to finish recording an in-flight request.
SINK_FLUSH_SECONDS = 0.05

#: Candidate base64 runs inside a captured request field.
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")


def _decode_base64_runs(value: str) -> str:
    """Decode every base64-looking run in ``value`` and join the results.

    Encoding a whole payload is not the same as encoding the needle: the
    base64 of ``prefix + canary`` does not contain the base64 of ``canary``.
    So a base64 body is decoded and searched in the clear rather than being
    compared against precomputed encodings alone.
    """

    decoded_parts: list[str] = []
    for run in _BASE64_RUN_RE.findall(value):
        candidate = run.replace("-", "+").replace("_", "/").rstrip("=")
        candidate += "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded_parts.append(decoded.decode("utf-8", "replace"))
    return "\n".join(decoded_parts)


class ChainProbeResult(BaseModel):
    """The runtime verdict for one static trifecta path."""

    path_id: str
    ingest_tool: str
    read_tool: str
    egress_tool: str
    static_severity: Literal["CRITICAL", "HIGH", "MEDIUM"]
    verified_severity: Literal["CRITICAL", "MEDIUM", "LOW"]
    status: ChainProbeStatus
    canary_token: str
    read_observed: bool
    egress_invoked: bool
    canary_captured_at_sink: bool
    sink_request_summary: str | None = None
    block_reason: str | None = None


class ChainVerificationReport(BaseModel):
    """Whole-configuration chain verification."""

    server_count: int
    static_paths_found: int
    paths_tested: int
    confirmed_exploitable: int
    blocked_count: int
    inconclusive_count: int
    results: list[ChainProbeResult] = Field(default_factory=list)
    passed: bool


# -- loopback canary sink ---------------------------------------------------


class CanarySinkServer:
    """An ephemeral HTTP sink on ``127.0.0.1:0`` that records exfiltration."""

    def __init__(self) -> None:
        self.base_url = ""
        self.captured_requests: list[dict[str, Any]] = []
        self._server: asyncio.AbstractServer | None = None
        self._port = 0

    @property
    def port(self) -> int:
        return self._port

    async def __aenter__(self) -> "CanarySinkServer":
        self._server = await asyncio.start_server(self._handle, host="127.0.0.1", port=0)
        sockets = self._server.sockets or []
        if not sockets:  # pragma: no cover - defensive
            raise RuntimeError("canary sink failed to bind a loopback socket")
        self._port = int(sockets[0].getsockname()[1])
        self.base_url = f"http://127.0.0.1:{self._port}"
        return self

    async def __aexit__(self, *_exc: object) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            head = b""

        lines = head.decode("latin-1").split("\r\n")
        request_line = lines[0] if lines else ""
        parts = request_line.split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                break
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip()] = value.strip()

        body = b""
        length = headers.get("Content-Length") or headers.get("content-length")
        if length and length.isdigit():
            with contextlib.suppress(asyncio.IncompleteReadError):
                body = await reader.readexactly(int(length))

        self.captured_requests.append(
            {
                "method": method,
                "path": path,
                "headers": headers,
                "body": body.decode("utf-8", "replace"),
            }
        )

        payload = b'{"ok": true}'
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: "
            + str(len(payload)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + payload
        )
        with contextlib.suppress(Exception):
            await writer.drain()
            writer.close()
            await writer.wait_closed()

    def find_canary(self, canary_token: str) -> tuple[str, str] | None:
        """Return ``(request summary, matched field)`` for the token, if seen.

        Egress tools routinely encode the payload (base64 JSON bodies, padded
        or URL-safe alphabets), so the raw token plus its two standard base64
        encodings are all accepted. The matched field is suffixed with
        ``(base64)`` when an encoding is what crossed the wire.
        """

        raw = canary_token.encode("utf-8")
        needles: list[tuple[str, str]] = [
            (canary_token, ""),
            (base64.b64encode(raw).decode("ascii"), " (base64)"),
            (base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="), " (base64)"),
        ]

        for request in self.captured_requests:
            fields: list[tuple[str, str]] = [
                ("path", request["path"]),
                ("body", request["body"]),
            ]
            fields.extend(
                (f"header:{name}", value) for name, value in request["headers"].items()
            )
            for field, value in fields:
                for needle, suffix in needles:
                    if needle and needle in value:
                        return f"{request['method']} {request['path']}", f"{field}{suffix}"
                if canary_token and canary_token in _decode_base64_runs(value):
                    return f"{request['method']} {request['path']}", f"{field} (base64)"
        return None


# -- schema-driven argument synthesis ---------------------------------------


def _properties(tool: ToolDefinition) -> dict[str, Any]:
    properties = tool.inputSchema.get("properties")
    return properties if isinstance(properties, dict) else {}


def _required(tool: ToolDefinition) -> list[str]:
    required = tool.inputSchema.get("required")
    return [str(name) for name in required] if isinstance(required, list) else []


def _accepts_string(schema: Any) -> bool:
    if not isinstance(schema, dict):
        return True
    return schema.get("type") in (None, "string")


def _default_for_schema(schema: Any) -> Any:
    if not isinstance(schema, dict):
        return "canary"
    kind = schema.get("type")
    if kind in ("integer", "number"):
        return 1
    if kind == "boolean":
        return True
    if kind == "array":
        return []
    if kind == "object":
        return {}
    return "canary"


def synthesize_read_args(tool: ToolDefinition, canary_token: str) -> dict[str, Any]:
    """Benign, read-only arguments for a ``PRIVATE_DATA_READ`` tool."""

    properties = _properties(tool)
    args: dict[str, Any] = {}

    for name in properties:
        key = name.lower()
        if key in READ_QUERY_PARAMS:
            args[name] = "SELECT * FROM records LIMIT 1"
        elif key in READ_PATH_PARAMS:
            args[name] = "canary.txt"
        elif key in READ_ID_PARAMS:
            args[name] = "canary-1"

    for name in _required(tool):
        if name not in args:
            args[name] = _default_for_schema(properties.get(name))

    return args


def synthesize_egress_args(
    tool: ToolDefinition, sink_url: str, canary_payload: str
) -> tuple[dict[str, Any], bool]:
    """Arguments that point an egress tool at the loopback sink.

    Returns ``(arguments, has_channel)`` where ``has_channel`` is true when the
    schema accepts a URL/sink or a string payload, i.e. when exfiltration can be
    parameterized at all.
    """

    properties = _properties(tool)
    args: dict[str, Any] = {}
    has_channel = False

    for name, schema in properties.items():
        key = name.lower()
        if key in URL_PARAMS:
            args[name] = f"{sink_url}/exfil"
            if _accepts_string(schema):
                has_channel = True
        elif key in PAYLOAD_PARAMS:
            args[name] = canary_payload
            if _accepts_string(schema):
                has_channel = True
        elif key in RECIPIENT_PARAMS:
            args[name] = "canary@127.0.0.1.invalid"

    for name in _required(tool):
        if name not in args:
            args[name] = _default_for_schema(properties.get(name))

    return args, has_channel


# -- probing ----------------------------------------------------------------


def _split_qualified(name: str) -> tuple[str, str]:
    server_id, _, tool_name = name.partition(":")
    return server_id, tool_name


def _find_tool(tools: Sequence[ToolDefinition], name: str) -> ToolDefinition | None:
    for tool in tools:
        if tool.name == name:
            return tool
    return None


def _is_error_result(result: dict[str, Any]) -> bool:
    return result.get("isError") is True or isinstance(result.get("error"), dict)


def _result_text(result: dict[str, Any]) -> str:
    content = result.get("content")
    if isinstance(content, list):
        parts = [
            item["text"]
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        ]
        if parts:
            return "\n".join(parts)
    error = result.get("error")
    return str(error) if isinstance(error, dict) else ""


def _error_text(result: dict[str, Any]) -> str:
    text = _result_text(result).strip()
    return text or "tool returned isError without a message"


async def _probe_path(
    path: TrifectaPath,
    sessions: dict[str, Any],
    manifests: dict[str, list[ToolDefinition]],
    sink: CanarySinkServer,
    seed_canary: bool,
) -> ChainProbeResult:
    canary_token = f"LATCH-CANARY-{uuid.uuid4().hex[:16]}"

    read_server, read_name = _split_qualified(path.read_tool)
    egress_server, egress_name = _split_qualified(path.egress_tool)

    base = {
        "path_id": path.path_id,
        "ingest_tool": path.ingest_tool,
        "read_tool": path.read_tool,
        "egress_tool": path.egress_tool,
        "static_severity": path.severity,
        "canary_token": canary_token,
    }

    read_tool = _find_tool(manifests.get(read_server, []), read_name)
    egress_tool = _find_tool(manifests.get(egress_server, []), egress_name)
    if read_tool is None or egress_tool is None:
        return ChainProbeResult(
            **base,
            verified_severity="LOW",
            status="INCONCLUSIVE_SCHEMA",
            read_observed=False,
            egress_invoked=False,
            canary_captured_at_sink=False,
            block_reason="the live tool list no longer contains every tool in the path",
        )

    read_args = synthesize_read_args(read_tool, canary_token)
    read_result = await sessions[read_server].call_tool(read_name, read_args)

    if _is_error_result(read_result):
        return ChainProbeResult(
            **base,
            verified_severity="LOW",
            status="BLOCKED_AT_READ",
            read_observed=False,
            egress_invoked=False,
            canary_captured_at_sink=False,
            block_reason=_error_text(read_result),
        )

    read_text = _result_text(read_result)
    if canary_token in read_text:
        tainted_payload = read_text
    elif seed_canary:
        tainted_payload = f"{read_text}\n[LATCH_TAINT:{canary_token}]".strip()
    else:
        tainted_payload = read_text

    egress_args, has_channel = synthesize_egress_args(
        egress_tool, sink.base_url, tainted_payload
    )
    if not has_channel:
        return ChainProbeResult(
            **base,
            verified_severity="LOW",
            status="INCONCLUSIVE_SCHEMA",
            read_observed=True,
            egress_invoked=False,
            canary_captured_at_sink=False,
            block_reason=(
                "egress tool exposes no URL/sink or string payload parameter, so"
                " exfiltration cannot be parameterized"
            ),
        )

    egress_result = await sessions[egress_server].call_tool(egress_name, egress_args)
    await asyncio.sleep(SINK_FLUSH_SECONDS)

    match = sink.find_canary(canary_token)
    if match is not None:
        summary, field = match
        return ChainProbeResult(
            **base,
            verified_severity="CRITICAL",
            status="CONFIRMED_EXPLOITABLE",
            read_observed=True,
            egress_invoked=True,
            canary_captured_at_sink=True,
            sink_request_summary=f"{summary} (matched {field})",
        )

    if _is_error_result(egress_result):
        return ChainProbeResult(
            **base,
            verified_severity="LOW",
            status="BLOCKED_AT_EGRESS",
            read_observed=True,
            egress_invoked=True,
            canary_captured_at_sink=False,
            block_reason=_error_text(egress_result),
        )

    return ChainProbeResult(
        **base,
        verified_severity="LOW",
        status="BLOCKED_AT_EGRESS",
        read_observed=True,
        egress_invoked=True,
        canary_captured_at_sink=False,
        block_reason=(
            "egress tool completed without forwarding canary payload to loopback sink"
        ),
    )


async def verify_trifecta_chains(
    specs: Sequence[ServerSpec],
    *,
    trusted_servers: set[str] | None = None,
    seed_canary: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> ChainVerificationReport:
    """Execute every static trifecta path against the live servers."""

    live_specs = [spec for spec in specs if spec.transport in ("stdio", "http")]
    manifests: dict[str, list[ToolDefinition]] = {}
    sessions: dict[str, Any] = {}

    async with AsyncExitStack() as stack:
        for spec in live_specs:
            session = await stack.enter_async_context(
                open_mcp_session(
                    spec, timeout=timeout, http_transport=http_transport
                )
            )
            sessions[spec.server_id] = session
            manifests[spec.server_id] = await session.list_tools()

        sink = await stack.enter_async_context(CanarySinkServer())
        graph = analyze_capability_graph(
            manifests, trusted_servers=trusted_servers or None
        )

        results = [
            await _probe_path(path, sessions, manifests, sink, seed_canary)
            for path in graph.trifecta_paths
        ]

    confirmed = sum(1 for result in results if result.status == "CONFIRMED_EXPLOITABLE")
    blocked = sum(
        1
        for result in results
        if result.status in ("BLOCKED_AT_READ", "BLOCKED_AT_EGRESS")
    )
    inconclusive = sum(
        1 for result in results if result.status == "INCONCLUSIVE_SCHEMA"
    )

    return ChainVerificationReport(
        server_count=len(live_specs),
        static_paths_found=len(graph.trifecta_paths),
        paths_tested=len(results),
        confirmed_exploitable=confirmed,
        blocked_count=blocked,
        inconclusive_count=inconclusive,
        results=results,
        passed=confirmed == 0,
    )
