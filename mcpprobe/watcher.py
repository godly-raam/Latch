"""Real-time mid-session rug-pull watcher.

A server that passed review can still swap its tool definitions *after* the
client has approved them. The watcher keeps a live session open, waits for
``notifications/tools/list_changed``, and re-verifies the instant tools mutate:
field-level diff, severity, protocol audit -- all against the same pin.

Over stdio the notification arrives as a JSON-RPC notification line. Over
Streamable HTTP it arrives through a ``subscriptions/listen`` SSE stream.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from .auditor import AuditReport, audit_manifest
from .lockfile import VerificationReport, create_lockfile, verify_manifest
from .models import Lockfile
from .transport import (
    DEFAULT_TIMEOUT,
    HarvestResult,
    HttpHarvester,
    StdioSession,
)

LIST_CHANGED = "notifications/tools/list_changed"


class WatchEvent(BaseModel):
    """One snapshot evaluation: the baseline or a post-mutation re-check."""

    sequence: int
    timestamp: str
    trigger: Literal["initial", "list_changed"]
    verification: VerificationReport
    audit: AuditReport | None = None


class WatchReport(BaseModel):
    """Everything the watcher observed during one session."""

    server_id: str
    transport: Literal["stdio", "http"]
    protocol_version: str
    events: list[WatchEvent] = Field(default_factory=list)
    rug_pull_detected: bool


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_server_id(
    server_id: str | None, harvest: HarvestResult, fallback: str
) -> str:
    if server_id:
        return server_id
    info = harvest.server_info or {}
    name = info.get("name")
    if isinstance(name, str) and name:
        return name
    return fallback


def _evaluate(
    lockfile: Lockfile,
    tools_payload: dict[str, Any],
    *,
    sequence: int,
    trigger: Literal["initial", "list_changed"],
    run_audit: bool,
) -> WatchEvent:
    return WatchEvent(
        sequence=sequence,
        timestamp=_now(),
        trigger=trigger,
        verification=verify_manifest(tools_payload, lockfile),
        audit=audit_manifest(tools_payload) if run_audit else None,
    )


def _rug_pull(events: list[WatchEvent]) -> bool:
    return any(event.verification.drift for event in events)


async def watch_stdio(
    command: str,
    *,
    server_id: str | None = None,
    lockfile: Lockfile | None = None,
    duration: float = 15.0,
    max_events: int = 1,
    run_audit: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> WatchReport:
    """Watch a stdio MCP server for ``notifications/tools/list_changed``."""

    session = StdioSession(command, timeout=timeout)
    await session.start()
    try:
        harvest = await session.harvest()
        resolved_id = _resolve_server_id(server_id, harvest, command)
        baseline = lockfile or create_lockfile(harvest.tools_payload, resolved_id)

        events = [
            _evaluate(
                baseline,
                harvest.tools_payload,
                sequence=1,
                trigger="initial",
                run_audit=run_audit,
            )
        ]

        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        processed = 0
        while processed < max_events and loop.time() < deadline:
            message = await session.next_notification(deadline)
            if message is None:
                break
            if message.get("method") != LIST_CHANGED:
                continue
            payload = await session.fetch_tools()
            events.append(
                _evaluate(
                    baseline,
                    payload,
                    sequence=len(events) + 1,
                    trigger="list_changed",
                    run_audit=run_audit,
                )
            )
            processed += 1

        return WatchReport(
            server_id=resolved_id,
            transport="stdio",
            protocol_version=harvest.protocol_version,
            events=events,
            rug_pull_detected=_rug_pull(events),
        )
    finally:
        await session.close()


async def watch_http(
    url: str,
    *,
    server_id: str | None = None,
    headers: dict[str, str] | None = None,
    lockfile: Lockfile | None = None,
    duration: float = 15.0,
    max_events: int = 1,
    run_audit: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    transport: httpx.AsyncBaseTransport | None = None,
) -> WatchReport:
    """Watch a Streamable HTTP MCP server through a ``subscriptions/listen`` SSE stream."""

    harvester = HttpHarvester(url, headers=headers, timeout=timeout, transport=transport)
    try:
        harvest = await harvester.harvest()
        resolved_id = _resolve_server_id(server_id, harvest, url)
        baseline = lockfile or create_lockfile(harvest.tools_payload, resolved_id)

        events = [
            _evaluate(
                baseline,
                harvest.tools_payload,
                sequence=1,
                trigger="initial",
                run_audit=run_audit,
            )
        ]

        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        processed = 0
        stream = harvester.listen_stream({"toolsListChanged": True}, timeout=duration)
        try:
            while processed < max_events:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    message = await asyncio.wait_for(stream.__anext__(), timeout=remaining)
                except (asyncio.TimeoutError, StopAsyncIteration):
                    break
                if message.get("method") != LIST_CHANGED:
                    continue
                payload = await harvester.fetch_tools()
                events.append(
                    _evaluate(
                        baseline,
                        payload,
                        sequence=len(events) + 1,
                        trigger="list_changed",
                        run_audit=run_audit,
                    )
                )
                processed += 1
        finally:
            await stream.aclose()

        return WatchReport(
            server_id=resolved_id,
            transport="http",
            protocol_version=harvest.protocol_version,
            events=events,
            rug_pull_detected=_rug_pull(events),
        )
    finally:
        await harvester.close()
