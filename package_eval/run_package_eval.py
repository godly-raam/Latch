"""Blind evaluation of Latch against captured real package manifests.

    python -m package_eval.run_package_eval

Loads every verbatim ``tools/list`` capture in
``package_eval/captured_manifests/`` (see ``capture_manifests.py`` for
provenance), evaluates it with Latch's real static engines plus the naive
keyword baseline, and evaluates a few multi-server compositions built directly
from those unmodified captures.

The engine configuration is not tailored to these packages: they are first-party
reference servers, so they are expected to be clean, and any finding is reported
as a finding rather than explained away.

Writes ``package_eval/package_results.json`` and
``package_eval/PACKAGE_EVAL_REPORT.md``. Sorted keys, no timestamps.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmark.naive_baseline import scan_text
from mcpprobe.auditor import audit_manifest
from mcpprobe.config_loader import ServerSpec
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.models import ToolDefinition
from mcpprobe.oauth_audit import run_auth_audit
from mcpprobe.shadow import analyze_shadowing

EVAL_DIR = Path(__file__).resolve().parent
MANIFEST_DIR = EVAL_DIR / "captured_manifests"
RESULTS_JSON = EVAL_DIR / "package_results.json"
REPORT_MD = EVAL_DIR / "PACKAGE_EVAL_REPORT.md"

#: Caps keep the report and JSON reviewable when a real surface is large.
MAX_LISTED_FINDINGS = 20
MAX_LISTED_PATHS = 8

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def severity_counts(severities: list[str]) -> dict[str, int]:
    return {
        severity: sum(1 for value in severities if value == severity)
        for severity in SEVERITY_ORDER
        if any(value == severity for value in severities)
    }


#: Compositions of unmodified captured tool surfaces to test cross-server flows.
COMPOSITIONS: list[dict[str, Any]] = [
    {
        "composition_id": "filesystem-plus-memory",
        "servers": ["npm-server-filesystem", "npm-server-memory"],
        "rationale": (
            "Local file read plus local knowledge-graph memory: both are"
            " first-party reference servers with no network egress."
        ),
    },
    {
        "composition_id": "filesystem-plus-git",
        "servers": ["npm-server-filesystem", "pypi-mcp-server-git"],
        "rationale": (
            "Two repository-oriented servers: file access plus git history"
            " inspection, still with no outbound sink."
        ),
    },
    {
        "composition_id": "filesystem-plus-fetch",
        "servers": ["npm-server-filesystem", "pypi-mcp-server-fetch"],
        "rationale": (
            "File read plus a web fetcher: the closest official pairing to an"
            " ingest/egress chain, so the static graph deserves a look."
        ),
    },
    {
        "composition_id": "everything-plus-filesystem",
        "servers": ["npm-server-everything", "npm-server-filesystem"],
        "rationale": (
            "The SDK's everything server (the largest captured surface) mounted"
            " beside the filesystem server."
        ),
    },
]


def load_captures() -> list[dict[str, Any]]:
    captures: list[dict[str, Any]] = []
    for path in sorted(MANIFEST_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["_path"] = path.name
        captures.append(payload)
    return captures


def _tools(capture: dict[str, Any]) -> list[ToolDefinition]:
    return [ToolDefinition.model_validate(tool) for tool in capture["tools"]]


def _naive_hits(payload: Any) -> list[str]:
    return scan_text(json.dumps(payload, sort_keys=True, ensure_ascii=False))


def evaluate_package(capture: dict[str, Any]) -> dict[str, Any]:
    """Run every static engine against one captured tool surface."""

    slug = capture["slug"]
    tools = _tools(capture)
    manifests = {slug: tools}

    audit = audit_manifest({"tools": capture["tools"]})
    graph = analyze_capability_graph(manifests)
    shadow = analyze_shadowing(manifests)
    auth = run_auth_audit(
        [ServerSpec(server_id=slug, transport="static")], manifests
    )

    naive_hits = _naive_hits(capture["tools"])
    findings = [
        {
            "engine": "audit",
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "tool": finding.tool_name,
        }
        for finding in audit.findings
    ] + [
        {
            "engine": "graph",
            "rule_id": "LETHAL_TRIFECTA",
            "severity": path.severity,
            "tool": path.ingest_tool,
        }
        for path in graph.trifecta_paths
    ] + [
        {
            "engine": "shadow",
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "tool": ", ".join(finding.involved_tools),
        }
        for finding in shadow.findings
    ] + [
        {
            "engine": "auth-audit",
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "tool": finding.field_path,
        }
        for finding in auth.findings
    ]

    return {
        "slug": slug,
        "finding_count": len(findings),
        "severity_counts": severity_counts(
            [finding["severity"] for finding in findings]
        ),
        "package_name": capture["package_name"],
        "package_version": capture["package_version"],
        "ecosystem": capture["ecosystem"],
        "capture_source": capture["capture_source"],
        "protocol_version": capture["protocol_version"],
        "launch_command": capture["launch_command"],
        "manifest_sha256": capture["manifest_sha256"],
        "tool_count": capture["tool_count"],
        "tool_names": sorted(tool.name for tool in tools),
        "latch_flagged": bool(findings),
        "findings": findings[:MAX_LISTED_FINDINGS],
        "naive_flagged": bool(naive_hits),
        "naive_hits": naive_hits,
    }


def evaluate_composition(spec: dict[str, Any], captures: dict[str, dict[str, Any]]) -> dict[str, Any]:
    servers: dict[str, list[ToolDefinition]] = {}
    for slug in spec["servers"]:
        servers[slug] = _tools(captures[slug])

    graph = analyze_capability_graph(servers)
    paths = graph.trifecta_paths
    audit = audit_manifest(
        {
            "tools": [
                tool.model_dump(mode="json", by_alias=True)
                for tools in servers.values()
                for tool in tools
            ]
        }
    )
    shadow = analyze_shadowing(servers)

    naive_payload = {
        slug: [tool.model_dump(mode="json", by_alias=True) for tool in tools]
        for slug, tools in sorted(servers.items())
    }

    return {
        "composition_id": spec["composition_id"],
        "servers": list(spec["servers"]),
        "rationale": spec["rationale"],
        "tool_count": sum(len(tools) for tools in servers.values()),
        "trifecta_path_count": len(paths),
        "cross_server_path_count": sum(1 for path in paths if path.cross_server),
        "severity_counts": severity_counts([path.severity for path in paths]),
        "trifecta_paths": [
            {
                "path_id": path.path_id,
                "severity": path.severity,
                "cross_server": path.cross_server,
                "ingest_tool": path.ingest_tool,
                "read_tool": path.read_tool,
                "egress_tool": path.egress_tool,
            }
            for path in paths[:MAX_LISTED_PATHS]
        ],
        "audit_findings": [
            f"{finding.rule_id} ({finding.tool_name})" for finding in audit.findings
        ],
        "shadow_findings": [
            f"{finding.rule_id} ({finding.canonical_key})"
            for finding in shadow.findings
        ],
        "latch_flagged": bool(paths or audit.findings or shadow.findings),
        "naive_flagged": bool(_naive_hits(naive_payload)),
    }


def compute_results() -> dict[str, Any]:
    captures = load_captures()
    by_slug = {capture["slug"]: capture for capture in captures}

    packages = [evaluate_package(capture) for capture in captures]
    compositions = [
        evaluate_composition(spec, by_slug)
        for spec in COMPOSITIONS
        if all(slug in by_slug for slug in spec["servers"])
    ]

    latch_flagged = [row["slug"] for row in packages if row["latch_flagged"]]
    naive_flagged = [row["slug"] for row in packages if row["naive_flagged"]]

    return {
        "package_count": len(packages),
        "tool_count": sum(row["tool_count"] for row in packages),
        "packages": packages,
        "compositions": compositions,
        "summary": {
            "latch_flagged_packages": latch_flagged,
            "latch_clean_packages": len(packages) - len(latch_flagged),
            "latch_false_positive_rate": round(len(latch_flagged) / len(packages), 4)
            if packages
            else 0.0,
            "naive_flagged_packages": naive_flagged,
            "naive_false_positive_rate": round(len(naive_flagged) / len(packages), 4)
            if packages
            else 0.0,
            "compositions_with_paths": [
                row["composition_id"]
                for row in compositions
                if row["trifecta_path_count"]
            ],
        },
    }


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def render_report(results: dict[str, Any]) -> str:
    """Render ``PACKAGE_EVAL_REPORT.md`` deterministically."""

    summary = results["summary"]
    lines = [
        "# Pinned-package evaluation: real `tools/list` captures",
        "",
        "Blind evaluation of Latch against real MCP servers, launched as a client",
        "would launch them, without tailoring any engine to these packages.",
        "",
        "## Method",
        "",
        "`python -m package_eval.capture_manifests` starts each pinned package over",
        "stdio, captures the `tools/list` response verbatim, resolves the pinned",
        "version from the npm registry or PyPI, and hashes the canonical tool list.",
        "Captures marked `live_subprocess` were harvested here; any kept",
        "`pinned_package_capture` snapshot is a previous verbatim capture of the",
        "same package version. `python -m package_eval.run_package_eval` then runs",
        "`audit_manifest`, `analyze_capability_graph`, `analyze_shadowing` and",
        "`run_auth_audit` against those records plus the naive keyword baseline,",
        "and scores the multi-server compositions built from the unmodified",
        "captures.",
        "",
        "These are first-party reference servers, so the expected result is clean:",
        "any finding below is reported as a finding, not tuned away.",
        "",
        "## Captured packages",
        "",
        _row(
            [
                "Package",
                "Version",
                "Ecosystem",
                "Protocol",
                "Tools",
                "SHA-256",
                "Capture",
            ]
        ),
        _row(["---"] * 7),
    ]

    for row in results["packages"]:
        lines.append(
            _row(
                [
                    f"`{row['package_name']}`",
                    row["package_version"],
                    row["ecosystem"],
                    f"`{row['protocol_version']}`",
                    str(row["tool_count"]),
                    f"`{row['manifest_sha256'][:16]}…`",
                    f"`{row['capture_source']}`",
                ]
            )
        )

    lines.extend(
        [
            "",
            f"Totals: {results['package_count']} packages,"
            f" {results['tool_count']} tools captured.",
            "",
            "## Latch vs. the naive baseline",
            "",
            _row(["Scanner", "Flagged packages", "Clean packages", "False-positive rate"]),
            _row(["---"] * 4),
            _row(
                [
                    "**Latch**",
                    str(len(summary["latch_flagged_packages"])),
                    str(summary["latch_clean_packages"]),
                    f"{summary['latch_false_positive_rate']:.2f}",
                ]
            ),
            _row(
                [
                    "Naive keyword/substring baseline",
                    str(len(summary["naive_flagged_packages"])),
                    str(results["package_count"] - len(summary["naive_flagged_packages"])),
                    f"{summary['naive_false_positive_rate']:.2f}",
                ]
            ),
            "",
        ]
    )

    if summary["latch_flagged_packages"]:
        lines.append(
            "Latch findings on real packages: "
            + ", ".join(f"`{slug}`" for slug in summary["latch_flagged_packages"])
            + "."
        )
    else:
        lines.append(
            "Latch reports no findings on any captured reference-server package."
        )
    lines.append("")

    if summary["naive_flagged_packages"]:
        lines.append(
            "The baseline flags: "
            + ", ".join(
                f"`{slug}`" for slug in summary["naive_flagged_packages"]
            )
            + " -- ordinary tool descriptions (`ignore`, `http://`, `token`, …)"
            " are enough to trip it."
        )
        lines.append("")

    if summary["latch_flagged_packages"] or summary["compositions_with_paths"]:
        lines.extend(
            [
                "## What the real-package findings are telling us",
                "",
                "Two results deserve to be read as limitations rather than",
                "detections, and they are counted against Latch in the numbers",
                "above:",
                "",
                "- **`@modelcontextprotocol/server-everything`** is the SDK's",
                "  diagnostics server. `get-env` really does read environment",
                "  variables, and `get-header-params`, `gzip-file-as-resource` and",
                "  the `trigger-*` tools carry parameter names and open-world",
                "  annotations that Latch's generic egress heuristics match. There",
                "  is no third-party sink in that surface, so the static",
                "  ingest -> read -> egress paths are an over-approximation of a",
                "  capability graph, not a live exfiltration path.",
                "- **`filesystem-plus-git`** pairs file ingestion/reads with",
                "  `git_commit`, `git_create_branch` and `git_merge`. Those are",
                "  write verbs pointing at the local repository, not at an external",
                "  destination, so the cross-server paths are again theoretical.",
                "",
                'This is exactly what the static graph promises -- "could these',
                'capabilities line up?" -- and exactly why `latch probe-chain`',
                "exists: a dry run shows the synthesized calls, and a live probe",
                "with an operator sink settles whether data actually leaves. The",
                "blind evaluation is more useful for surfacing this than a",
                "hand-tuned corpus would be, so it stays in the report.",
                "",
            ]
        )

    lines.extend(
        [
            "## Per-package detail",
            "",
        ]
    )

    for row in results["packages"]:
        lines.append(
            f"### `{row['package_name']}` {row['package_version']}"
            f" ({row['tool_count']} tools)"
        )
        lines.append("")
        lines.append(f"- Tools: {', '.join(f'`{name}`' for name in row['tool_names'])}")
        lines.append(f"- Launched as: `{row['launch_command']}`")
        if row["findings"]:
            for finding in row["findings"]:
                lines.append(
                    f"- Latch `{finding['engine']}` finding:"
                    f" `{finding['rule_id']}` [{finding['severity']}]"
                    f" on `{finding['tool']}`"
                )
            if row["finding_count"] > len(row["findings"]):
                lines.append(
                    f"- +{row['finding_count'] - len(row['findings'])} more"
                    " findings (see `package_results.json`)"
                )
        else:
            lines.append("- Latch: no findings")
        if row["naive_hits"]:
            lines.append(
                "- Naive baseline matched: "
                + ", ".join(f"`{hit}`" for hit in row["naive_hits"])
            )
        else:
            lines.append("- Naive baseline: no keyword matches")
        lines.append("")

    lines.extend(
        [
            "## Multi-server compositions from unmodified captures",
            "",
            _row(
                [
                    "Composition",
                    "Servers",
                    "Tools",
                    "Static trifecta paths",
                    "Audit findings",
                    "Naive",
                ]
            ),
            _row(["---"] * 6),
        ]
    )

    for row in results["compositions"]:
        lines.append(
            _row(
                [
                    f"`{row['composition_id']}`",
                    ", ".join(f"`{slug}`" for slug in row["servers"]),
                    str(row["tool_count"]),
                    str(row["trifecta_path_count"]),
                    str(len(row["audit_findings"])),
                    "flagged" if row["naive_flagged"] else "clean",
                ]
            )
        )

    lines.append("")

    for row in results["compositions"]:
        lines.append(f"- `{row['composition_id']}`: {row['rationale']}")
        for path in row["trifecta_paths"]:
            lines.append(
                f"  - {path['severity']} path {path['path_id']}:"
                f" `{path['ingest_tool']}` -> `{path['read_tool']}` ->"
                f" `{path['egress_tool']}`"
            )
        if not row["trifecta_path_count"]:
            lines.append("  - no ingest -> read -> egress path")
        elif row["trifecta_path_count"] > len(row["trifecta_paths"]):
            lines.append(
                f"  - +{row['trifecta_path_count'] - len(row['trifecta_paths'])}"
                " more paths (see `package_results.json`)"
            )
        for finding in row["shadow_findings"]:
            lines.append(f"  - shadow finding: {finding}")
    lines.append("")

    lines.extend(
        [
            "## What this proves, and what it does not",
            "",
            "- **Real surfaces, real provenance.** Every row above comes from an",
            "  actual package launch with a registry-resolved version and a digest",
            "  of the captured tool list; the JSON under `captured_manifests/` is the",
            "  raw record, not a hand-written model.",
            "- **Blind evaluation.** No rule or vocabulary was adjusted for these",
            "  packages; they are scored exactly as any other configuration would be.",
            "- **Only metadata is exercised.** Captures contain `tools/list` bytes.",
            "  Handler behaviour, RBAC and network policy are not observed here;",
            "  `latch probe-chain` is the execution-aware complement.",
            "- **Small sample.** Five reference servers is not the MCP ecosystem.",
            "  The result is evidence about first-party surfaces, not a claim about",
            "  registry-wide precision.",
            "- **Compositions are still static.** A clean composition means the",
            "  published schemas do not line up into a chain, not that the servers",
            "  can never exfiltrate.",
            "",
        ]
    )

    return "\n".join(lines)


def write_results(results: dict[str, Any]) -> None:
    RESULTS_JSON.write_text(
        json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    REPORT_MD.write_text(render_report(results), encoding="utf-8")


def print_summary(results: dict[str, Any]) -> None:
    summary = results["summary"]
    print(
        f"Packages: {results['package_count']}"
        f"   tools: {results['tool_count']}"
    )
    print(
        f"Latch flagged: {len(summary['latch_flagged_packages'])}"
        f"   clean: {summary['latch_clean_packages']}"
        f"   FPR: {summary['latch_false_positive_rate']:.2f}"
    )
    print(
        f"Naive flagged: {len(summary['naive_flagged_packages'])}"
        f"   FPR: {summary['naive_false_positive_rate']:.2f}"
    )
    for row in results["packages"]:
        state = "flagged" if row["latch_flagged"] else "clean"
        print(
            f"  {row['slug']:26} {row['package_version']:10}"
            f" {row['tool_count']:>3} tools  {state}"
        )
    print(f"Compositions with paths: {summary['compositions_with_paths'] or 'none'}")
    print(f"Wrote {RESULTS_JSON}")
    print(f"Wrote {REPORT_MD}")


def main() -> int:
    results = compute_results()
    write_results(results)
    print_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
