#!/usr/bin/env python3
"""Fixture MCP server (stdio) used by Latch's chain-prober tests.

One process serves three tools that form a static lethal trifecta:

    fetch_issue    -> UNTRUSTED_INPUT
    read_ledger    -> PRIVATE_DATA_READ   (query parameter)
    post_webhook   -> EXTERNAL_EGRESS     (webhook_url + payload)

Behaviour is selected by ``--role`` (repeatable):

    --role read-open           read_ledger returns rows
    --role read-denied         read_ledger returns isError (RBAC denial)
    --role egress-open         post_webhook forwards the payload to webhook_url
    --role egress-allowlisted  post_webhook rejects hosts outside *.corp.internal
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from typing import Any
from urllib.parse import urlsplit

TOOLS: list[dict[str, Any]] = [
    {
        "name": "fetch_issue",
        "description": "Fetch a public issue.",
        "inputSchema": {
            "type": "object",
            "properties": {"issue_number": {"type": "integer"}},
            "required": ["issue_number"],
        },
    },
    {
        "name": "read_ledger",
        "description": "Query the customer ledger.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "post_webhook",
        "description": "POST a payload to a webhook.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "webhook_url": {"type": "string"},
                "payload": {"type": "string"},
            },
            "required": ["webhook_url", "payload"],
        },
    },
]

READ_ROLES = {"read-open", "read-denied"}
EGRESS_ROLES = {"egress-open", "egress-allowlisted"}


def text_result(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


def error_result(text: str) -> dict[str, Any]:
    return {"isError": True, "content": [{"type": "text", "text": text}]}


def forward(webhook_url: str, payload: str) -> dict[str, Any]:
    try:
        request = urllib.request.Request(
            webhook_url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return text_result(f"posted {len(payload)} bytes (HTTP {response.status})")
    except Exception as exc:  # noqa: BLE001 - fixture reports any failure as isError
        return error_result(f"egress failed: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", action="append", default=[], choices=sorted(READ_ROLES | EGRESS_ROLES))
    args = parser.parse_args()

    roles = set(args.role)
    if not roles & READ_ROLES:
        roles.add("read-open")
    if not roles & EGRESS_ROLES:
        roles.add("egress-open")

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
        if method is None:
            continue
        if request_id is None:
            # notifications/initialized and friends need no reply.
            continue

        if method == "server/discover":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2026-07-28",
                        "serverInfo": {"name": "mock-chain", "version": "1.0"},
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
                        "serverInfo": {"name": "mock-chain", "version": "1.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}

            if name == "fetch_issue":
                result = text_result("issue #1: hello from the fixture")
            elif name == "read_ledger":
                if "read-denied" in roles:
                    result = error_result(
                        "RBAC denied: caller lacks the ledger:read scope"
                    )
                else:
                    result = text_result("ledger-row-1 balance=42 owner=alice")
            elif name == "post_webhook":
                webhook_url = str(arguments.get("webhook_url") or "")
                payload = str(arguments.get("payload") or "")
                host = (urlsplit(webhook_url).hostname or "").lower()
                if "egress-allowlisted" in roles and not host.endswith(".corp.internal"):
                    result = error_result(
                        f"blocked: destination {host!r} is not in the"
                        " *.corp.internal allowlist"
                    )
                else:
                    result = forward(webhook_url, payload)
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
