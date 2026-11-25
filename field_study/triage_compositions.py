"""Reproduce the composition-triage sample and print the evidence behind it.

The composition sweep mounts arbitrary harvested server pairs, so its
aggregates are a stress test, not a prevalence measurement. This module draws
the fixed-seed sample of flagged compositions used for the hand triage in
``FIELD_STUDY_REPORT.md`` and prints, for every sampled composition, the exact
paths and shadow findings that produced the flag, together with the tool
descriptions the verdict was based on.

It is read-only: no detector, capture or report is modified.

    python -m field_study.triage_compositions --captures field_study/captures
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

from mcpprobe.graph import analyze_capability_graph
from mcpprobe.shadow import analyze_shadowing
from mcpprobe.models import ToolDefinition

from field_study.run_field_study import (
    CAPTURE_DIR,
    COMPOSITION_ANCHOR_SLUGS,
    build_compositions,
    load_anchor_manifests,
    load_captures,
)

#: Fixed draw: same seed, same capture directory, same 20 compositions.
TRIAGE_SEED = 20261125
TRIAGE_SAMPLE_SIZE = 20

_DESCRIPTION_LIMIT = 240


def harvested_manifests(
    capture_dir: Path | None = None,
    *,
    excluded: set[str] | None = None,
) -> dict[str, list[ToolDefinition]]:
    """Load the analyzable harvested surfaces exactly as the sweep does."""

    skip = set(excluded or set())
    harvested: dict[str, list[ToolDefinition]] = {}
    for capture in load_captures(capture_dir):
        slug = capture.get("slug") or ""
        if slug in skip or capture.get("harvest_status") != "harvested":
            continue
        tools = [
            ToolDefinition.model_validate(tool)
            for tool in capture.get("tools") or []
            if isinstance(tool, dict)
        ]
        if tools:
            harvested[slug] = tools
    return harvested


def _tool_index(servers: dict[str, list[ToolDefinition]]) -> dict[str, ToolDefinition]:
    return {
        f"{server_id}:{tool.name}": tool
        for server_id, tools in servers.items()
        for tool in tools
    }


def _describe(tool: ToolDefinition | None) -> str:
    if tool is None:
        return ""
    text = " ".join((tool.description or "").split())
    return text[:_DESCRIPTION_LIMIT]


def composition_detail(
    composition: tuple[str, ...],
    servers: dict[str, list[ToolDefinition]],
) -> dict[str, Any]:
    """Run the frozen engines over one composition and keep the evidence."""

    manifests = {server_id: servers[server_id] for server_id in composition}
    graph = analyze_capability_graph(manifests)
    shadow = analyze_shadowing(manifests)
    tools = _tool_index(manifests)

    paths = [
        {
            "cross_server": path.cross_server,
            "egress": path.egress_tool,
            "egress_description": _describe(tools.get(path.egress_tool)),
            "ingest": path.ingest_tool,
            "ingest_description": _describe(tools.get(path.ingest_tool)),
            "reads": path.read_tools,
            "severity": path.severity,
        }
        for path in graph.trifecta_paths
    ]
    shadow_rows = [
        {
            "evidence": finding.evidence,
            "involved_tools": finding.involved_tools,
            "message": finding.message,
            "rule_id": finding.rule_id,
            "servers": finding.servers,
            "severity": finding.severity,
        }
        for finding in shadow.findings
    ]
    rules = sorted(
        {"LETHAL_TRIFECTA" for _ in paths} | {row["rule_id"] for row in shadow_rows}
    )
    return {
        "composition_id": "+".join(composition),
        "cross_server_paths": sum(1 for path in paths if path["cross_server"]),
        "graph_paths": len(paths),
        "paths": paths,
        "rules": rules,
        "servers": list(composition),
        "shadow": shadow_rows,
        "shadow_findings": len(shadow_rows),
    }


def flagged_details(
    capture_dir: Path | None = None,
    *,
    excluded: set[str] | None = None,
    manifest_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Every composition the frozen engines flag, with its evidence."""

    harvested = harvested_manifests(capture_dir, excluded=excluded)
    anchors = load_anchor_manifests(manifest_dir)
    servers = {**anchors, **harvested}
    rows: list[dict[str, Any]] = []
    for composition in build_compositions(harvested):
        if any(server_id not in servers for server_id in composition):
            continue
        detail = composition_detail(composition, servers)
        if detail["graph_paths"] or detail["shadow_findings"]:
            rows.append(detail)
    return sorted(rows, key=lambda row: row["composition_id"])


def sample_details(
    rows: list[dict[str, Any]],
    *,
    seed: int = TRIAGE_SEED,
    size: int = TRIAGE_SAMPLE_SIZE,
) -> list[dict[str, Any]]:
    """Draw the fixed-seed sample from the sorted flagged set."""

    ids = sorted(row["composition_id"] for row in rows)
    chosen = set(random.Random(seed).sample(ids, min(size, len(ids))))
    return [row for row in rows if row["composition_id"] in chosen]


def render_text(detail: dict[str, Any]) -> str:
    """Human-readable evidence block for one sampled composition."""

    lines = [
        f"## {detail['composition_id']}",
        f"servers: {len(detail['servers'])} | rules: {', '.join(detail['rules'])}"
        f" | paths: {detail['graph_paths']} ({detail['cross_server_paths']}"
        " cross-server)"
        f" | shadow: {detail['shadow_findings']}",
    ]
    for index, path in enumerate(detail["paths"], start=1):
        lines.extend(
            [
                f"  path {index} [{path['severity']}]"
                f"{' cross-server' if path['cross_server'] else ''}",
                f"    ingest: {path['ingest']}",
                f"      desc: {path['ingest_description'] or '(none)'}",
                f"    read:   {', '.join(path['reads'])}",
                f"    egress: {path['egress']}",
                f"      desc: {path['egress_description'] or '(none)'}",
            ]
        )
    for index, finding in enumerate(detail["shadow"], start=1):
        lines.extend(
            [
                f"  shadow {index} [{finding['severity']}] {finding['rule_id']}",
                f"    tools: {', '.join(finding['involved_tools'])}",
                f"    message: {finding['message']}",
                f"    evidence: {finding['evidence']}",
            ]
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", type=Path, default=CAPTURE_DIR)
    parser.add_argument("--seed", type=int, default=TRIAGE_SEED)
    parser.add_argument("--sample", type=int, default=TRIAGE_SAMPLE_SIZE)
    parser.add_argument("--json", type=Path, help="write the drawn sample as JSON")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="slug to exclude (the duplicate-name surface behind CASE-01)",
    )
    args = parser.parse_args(argv)

    rows = flagged_details(args.captures, excluded=set(args.exclude))
    drawn = sample_details(rows, seed=args.seed, size=args.sample)
    print(
        f"flagged compositions: {len(rows)}; sampled {len(drawn)}"
        f" (seed {args.seed}) from {args.captures}"
    )
    for detail in drawn:
        print()
        print(render_text(detail))
    if args.json:
        args.json.write_text(
            json.dumps(drawn, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
