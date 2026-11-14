"""Naive keyword/substring baseline.

This models the scanners Latch is meant to replace: a flat keyword list matched
with plain substring search over the raw configuration text. It has no
identifier tokenization, no header allowlist, no canonical hashing and no graph
analysis -- so it fires on ``secret_santa_matcher`` and misses an annotation
flip that contains no suspicious word at all.
"""

from __future__ import annotations

import json
from typing import Any

from .corpus import Case

#: Exactly the words a keyword scanner is likely to grep for.
NAIVE_KEYWORDS: tuple[str, ...] = (
    "ssh",
    "secret",
    "token",
    "pass",
    "curl",
    "sql",
    "webhook",
    "ignore",
    "override",
    "x-mcp-header",
)


def scan_text(text: str) -> list[str]:
    """Return every keyword appearing as a substring of ``text``."""

    lowered = text.lower()
    return [keyword for keyword in NAIVE_KEYWORDS if keyword in lowered]


def searchable_text(case: Case) -> str:
    """Serialize everything the baseline can see for one case."""

    parts: list[str] = []
    for payload in (case.pinned_manifest(), case.current_manifest()):
        if payload is not None:
            parts.append(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if case.servers:
        parts.append(json.dumps(case.servers, ensure_ascii=False, sort_keys=True))
        parts.append(" ".join(sorted(case.servers)))
    return "\n".join(parts)


def naive_hits(case: Case) -> list[str]:
    return scan_text(searchable_text(case))


def naive_flags(case: Case) -> bool:
    return bool(naive_hits(case))


def naive_verdict(case: Case) -> dict[str, Any]:
    hits = naive_hits(case)
    return {"flagged": bool(hits), "hits": hits}
