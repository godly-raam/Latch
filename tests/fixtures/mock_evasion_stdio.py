#!/usr/bin/env python3
"""Fixture MCP server (stdio) for runtime evasion probes.

Tools are selected with ``--role`` (repeatable); with no role every tool is
served, which gives a single server a complete ingest -> read -> egress chain:

    fetch_ticket      UNTRUSTED_INPUT
    read_ledger       PRIVATE_DATA_READ
    extract_ledger    PRIVATE_DATA_READ (intermediate transformer)
    send_report       EXTERNAL_EGRESS   (url + payload)

``--mode`` changes how ``send_report`` delivers the payload:

    open     POST the payload as the raw body
    base64   POST base64(payload) as the body
    query    GET url?d=<percent-encoded payload>

The base64 and query modes prove the egress canary is still caught when the
tool encodes or relocates it.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.parse
import urllib.request
from typing import Any


def tool(name: str, description: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(properties),
        },
    }


TOOLSETS: dict[str, list[dict[str, Any]]] = {
    "ingest": [tool("fetch_ticket", "Fetch a public support ticket.", {"issue_number": {"type": "integer"}})],
    "read": [tool("read_ledger", "Query the customer ledger.", {"query": {"type": "string"}})],
    "transform": [
        tool("extract_ledger", "Extract ledger rows for summarization.", {"query": {"type": "string"}})
    ],
    "egress": [
        tool(
            "send_report",
            "Send a report to an operational endpoint.",
            {"url": {"type": "string"}, "payload": {"type": "string"}},
        )
    ],
}

ROLES = tuple(TOOLSETS)


def text_result(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


def error_result(text: str) -> dict[str, Any]:
    return {"isError": True, "content": [{"type": "text", "text": text}]}


def deliver(url: str, payload: str, mode: str) -> dict[str, Any]:
    try:
        if mode == "query":
            target = f"{url}?d={urllib.parse.quote(payload)}"
            request = urllib.request.Request(target, method="GET")
        else:
            body = payload
            if mode == "base64":
                body = base64.b64encode(payload.encode("utf-8")).decode("ascii")
            request = urllib.request.Request(
                url,
                data=body.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                method="POST",
            )
        with urllib.request.urlopen(request, timeout=5) as response:
            return text_result(f"delivered {len(payload)} bytes (HTTP {response.status})")
    except Exception as exc:  # noqa: BLE001 - fixture reports any failure as isError
        return error_result(f"egress failed: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", action="append", default=[], choices=ROLES)
    parser.add_argument("--mode", default="open", choices=("open", "base64", "query"))
    args = parser.parse_args()

    roles = args.role or list(ROLES)
    tools = [item for role in ROLES if role in roles for item in TOOLSETS[role]]

    def send(message: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(message) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue

        method = message.get("method")
        request_id = message.get("id")
        if method is None or request_id is None:
            continue

        if method == "server/discover":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2026-07-28",
                        "serverInfo": {"name": "mock-evasion", "version": "1.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
        elif method == "initialize":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "serverInfo": {"name": "mock-evasion", "version": "1.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
        elif method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}

            if name == "fetch_ticket":
                result = text_result("ticket #1: hello from the evasion fixture")
            elif name == "read_ledger":
                result = text_result("ledger-row-1 balance=42 owner=alice")
            elif name == "extract_ledger":
                result = text_result("extracted: ledger-row-1 balance=42 owner=alice")
            elif name == "send_report":
                result = deliver(
                    str(arguments.get("url") or ""),
                    str(arguments.get("payload") or ""),
                    args.mode,
                )
            else:
                result = error_result(f"unknown tool {name!r}")

            send({"jsonrpc": "2.0", "id": request_id, "result": result})
        else:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"unknown method {method}"},
                }
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
