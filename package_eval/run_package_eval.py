"""Blind evaluation of Latch against captured real package manifests.

    python -m package_eval.run_package_eval

Loads every capture in ``package_eval/captured_manifests/`` (see
``capture_manifests.py`` for provenance), evaluates it with Latch's real static
engines plus the naive keyword baseline, and evaluates multi-server compositions
built directly from those unmodified captures.

The corpus mixes three kinds of target:

* **in-model real targets** -- a cleartext-HTTP OAuth proxy, an unauthenticated
  cleartext SSE bridge, and a cross-server fetch + filesystem composition. A
  static manifest auditor can see these, so they are counted in in-scope recall.
* **out-of-model real CVEs** -- pre-patch handler-level path traversal and git
  argument injection. Those live in handler code, not in ``tools/list``, so they
  are captured and reported honestly as misses in overall recall.
* **clean reference servers** -- first-party servers expected to be clean; every
  finding on them is counted as a false positive.

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

#: The one rule a cleartext-transport target must be caught by.
TRANSPORT_RULE = "INSECURE_HTTP_AUTH_TRANSPORT"
GRAPH_RULE = "LETHAL_TRIFECTA"


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
        "expected_positive": False,
        "in_latch_threat_model": True,
        "rationale": (
            "Local file read plus local knowledge-graph memory: every write is"
            " local state, so there is no outbound sink."
        ),
    },
    {
        "composition_id": "filesystem-plus-git",
        "servers": ["npm-server-filesystem", "pypi-mcp-server-git"],
        "expected_positive": False,
        "in_latch_threat_model": True,
        "rationale": (
            "Two repository-oriented servers: file read plus git history and"
            " local commits. No outbound sink exists."
        ),
    },
    {
        "composition_id": "filesystem-plus-fetch",
        "servers": ["npm-server-filesystem", "pypi-mcp-server-fetch"],
        "target_id": "B",
        "expected_positive": True,
        "in_latch_threat_model": True,
        "expected_rule_ids": [GRAPH_RULE],
        "rationale": (
            "Target B: real untrusted web ingestion (mcp-server-fetch) beside"
            " real private workspace reads (server-filesystem)."
        ),
        "miss_rationale": (
            "mcp-server-fetch is GET-only: it has no payload parameter, so the"
            " static graph does not model it as an egress sink. Data can still"
            " leave in a caller-chosen query string, which"
            " `latch probe-chain` verifies at runtime, but the static path"
            " enumeration has nothing to enumerate here."
        ),
    },
    {
        "composition_id": "everything-plus-filesystem",
        "servers": ["npm-server-everything", "npm-server-filesystem"],
        "expected_positive": False,
        "in_latch_threat_model": False,
        "rationale": (
            "The SDK's everything server (the largest captured surface) mounted"
            " beside the filesystem server. Its diagnostics tools have no"
            " third-party sink, so any path is over-approximation."
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


def _outcome(expected_positive: bool, latch_flagged: bool) -> str:
    if expected_positive:
        return "detected" if latch_flagged else "missed"
    return "false_positive" if latch_flagged else "true_negative"


def _target_row(
    *,
    target_id: str,
    label: str,
    capture: dict[str, Any],
    findings: list[dict[str, Any]],
    naive_hits: list[str],
    tool_count: int,
) -> dict[str, Any]:
    rule_ids = sorted({finding["rule_id"] for finding in findings})
    expected_positive = bool(
        capture.get("expected_positive", capture.get("in_latch_threat_model"))
    )
    expected_rules = [
        "LETHAL_TRIFECTA"
        if capture.get("kind") != "proxy_metadata"
        else TRANSPORT_RULE
    ]
    latch_flagged = bool(findings)
    return {
        "target_id": target_id,
        "label": label,
        "slug": capture["slug"],
        "kind": capture["kind"],
        "package_name": capture["package_name"],
        "package_version": capture["package_version"],
        "ecosystem": capture["ecosystem"],
        "capture_source": capture["capture_source"],
        "protocol_version": capture["protocol_version"],
        "launch_command": capture["launch_command"],
        "manifest_sha256": capture["manifest_sha256"],
        "tool_count": tool_count,
        "tool_names": [tool.name for tool in _tools(capture)],
        "in_latch_threat_model": capture["in_latch_threat_model"],
        "vulnerability_class": capture["vulnerability_class"],
        "cve_refs": capture["cve_refs"],
        "note": capture["note"],
        "expected_positive": expected_positive,
        "expected_rule_ids": expected_rules if expected_positive else [],
        "detected_rule_ids": [rule for rule in rule_ids if rule in expected_rules],
        "rule_ids": rule_ids,
        "latch_flagged": latch_flagged,
        "outcome": _outcome(expected_positive, latch_flagged),
        "finding_count": len(findings),
        "severity_counts": severity_counts(
            [finding["severity"] for finding in findings]
        ),
        "findings": findings[:MAX_LISTED_FINDINGS],
        "naive_flagged": bool(naive_hits),
        "naive_hits": naive_hits,
    }


def evaluate_transport_target(capture: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a proxy/transport package from its real exposed configuration."""

    spec = ServerSpec(
        server_id=capture["slug"],
        transport="http",
        url=capture["exposed_url"],
        headers=dict(capture.get("exposed_headers") or {}),
    )
    auth = run_auth_audit([spec], None)
    findings = [
        {
            "engine": "auth-audit",
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "tool": finding.field_path,
        }
        for finding in auth.findings
    ]
    row = _target_row(
        target_id=capture.get("target_id") or capture["slug"],
        label=(
            f"`{capture['package_name']}` {capture['package_version']} over"
            f" `{capture['exposed_url']}`"
        ),
        capture=capture,
        findings=findings,
        naive_hits=_naive_hits(
            {
                "launch_command": capture["launch_command"],
                "exposed_url": capture["exposed_url"],
            }
        ),
        tool_count=0,
    )
    row["exposed_url"] = capture["exposed_url"]
    row["transport_probe"] = capture.get("probe")
    row["exposed_headers"] = capture.get("exposed_headers") or {}
    return row


def evaluate_package(capture: dict[str, Any]) -> dict[str, Any]:
    """Run every static engine against one captured tool surface."""

    if capture.get("kind") == "proxy_metadata":
        return evaluate_transport_target(capture)

    slug = capture["slug"]
    tools = _tools(capture)
    manifests = {slug: tools}

    audit = audit_manifest({"tools": capture["tools"]})
    graph = analyze_capability_graph(manifests)
    shadow = analyze_shadowing(manifests)
    auth = run_auth_audit(
        [ServerSpec(server_id=slug, transport="static")], manifests
    )

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
            "rule_id": GRAPH_RULE,
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

    return _target_row(
        target_id=capture.get("target_id") or slug,
        label=f"`{capture['package_name']}` {capture['package_version']}",
        capture=capture,
        findings=findings,
        naive_hits=_naive_hits(capture["tools"]),
        tool_count=len(tools),
    )


#: Path counts measured with the pre-fix engine (v0.3.1) on these exact
#: captures, before ``LOCAL_WRITE`` existed and before paths were collapsed.
#: Recorded rather than recomputed: the old classifier is gone, so a derived
#: "before" number would be a guess about rules that no longer exist.
LEGACY_GRAPH_COUNTS: dict[str, dict[str, int]] = {
    "filesystem-plus-memory": {"paths": 0, "critical": 0},
    "filesystem-plus-git": {"paths": 27, "critical": 27},
    "filesystem-plus-fetch": {"paths": 0, "critical": 0},
    "everything-plus-filesystem": {"paths": 314, "critical": 302},
}


def evaluate_composition(
    spec: dict[str, Any], captures: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    servers: dict[str, list[ToolDefinition]] = {
        slug: _tools(captures[slug]) for slug in spec["servers"]
    }

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

    rule_ids = sorted(
        ({GRAPH_RULE} if paths else set())
        | {finding.rule_id for finding in audit.findings}
        | {finding.rule_id for finding in shadow.findings}
    )
    expected_positive = bool(spec["expected_positive"])
    latch_flagged = bool(paths or audit.findings or shadow.findings)
    legacy = LEGACY_GRAPH_COUNTS.get(
        spec["composition_id"], {"paths": 0, "critical": 0}
    )

    naive_payload = {
        slug: [tool.model_dump(mode="json", by_alias=True) for tool in tools]
        for slug, tools in sorted(servers.items())
    }

    return {
        "composition_id": spec["composition_id"],
        "target_id": spec.get("target_id"),
        "servers": list(spec["servers"]),
        "rationale": spec["rationale"],
        "miss_rationale": spec.get("miss_rationale"),
        "in_latch_threat_model": spec["in_latch_threat_model"],
        "expected_positive": expected_positive,
        "expected_rule_ids": spec.get("expected_rule_ids", []),
        "detected_rule_ids": [
            rule for rule in rule_ids if rule in spec.get("expected_rule_ids", [])
        ],
        "rule_ids": rule_ids,
        "outcome": _outcome(expected_positive, latch_flagged),
        "tool_count": sum(len(tools) for tools in servers.values()),
        "trifecta_path_count": len(paths),
        "cross_server_path_count": sum(1 for path in paths if path.cross_server),
        "collapsed_read_tools": sum(path.collapsed_read_count for path in paths),
        "local_write_tools": list(graph.local_write_tools),
        "severity_counts": severity_counts([path.severity for path in paths]),
        "legacy_path_count": legacy["paths"],
        "legacy_critical_count": legacy["critical"],
        "trifecta_paths": [
            {
                "path_id": path.path_id,
                "severity": path.severity,
                "cross_server": path.cross_server,
                "ingest_tool": path.ingest_tool,
                "read_tool": path.read_tool,
                "read_tools": path.read_tools,
                "collapsed_read_count": path.collapsed_read_count,
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
        "latch_flagged": latch_flagged,
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

    targets = [row for row in packages + compositions if row["expected_positive"]]
    in_scope = [row for row in targets if row["in_latch_threat_model"]]
    out_of_model = [row for row in targets if not row["in_latch_threat_model"]]
    clean = [row for row in packages if not row["expected_positive"]]

    def _ids(rows: list[dict[str, Any]], outcome: str) -> list[str]:
        return [row["target_id"] for row in rows if row["outcome"] == outcome]

    in_scope_detected = [
        row["target_id"] for row in in_scope if row["outcome"] == "detected"
    ]
    overall_detected = [
        row["target_id"] for row in targets if row["outcome"] == "detected"
    ]
    false_positives = [
        row["target_id"] for row in clean if row["outcome"] == "false_positive"
    ]
    clean_package_count = len(clean)

    naive_flagged = [row["slug"] for row in packages if row["naive_flagged"]]

    return {
        "package_count": len(packages),
        "tool_count": sum(row["tool_count"] for row in packages),
        "packages": packages,
        "compositions": compositions,
        "precision_before_after": [
            {
                "composition_id": row["composition_id"],
                "before_paths": row["legacy_path_count"],
                "before_critical": row["legacy_critical_count"],
                "after_paths": row["trifecta_path_count"],
                "after_critical": row["severity_counts"].get("CRITICAL", 0),
                "collapsed_read_tools": row["collapsed_read_tools"],
            }
            for row in compositions
        ],
        "detection": {
            "in_scope_targets": [row["target_id"] for row in in_scope],
            "in_scope_detected": in_scope_detected,
            "in_scope_missed": _ids(in_scope, "missed"),
            "in_scope_recall": round(
                len(in_scope_detected) / len(in_scope), 4
            )
            if in_scope
            else 0.0,
            "out_of_model_targets": [row["target_id"] for row in out_of_model],
            "out_of_model_detected": _ids(out_of_model, "detected"),
            "out_of_model_missed": _ids(out_of_model, "missed"),
            "overall_targets": len(targets),
            "overall_detected": overall_detected,
            "overall_missed": _ids(targets, "missed"),
            "overall_recall": round(len(overall_detected) / len(targets), 4)
            if targets
            else 0.0,
        },
        "summary": {
            "latch_flagged_packages": [
                row["slug"] for row in packages if row["latch_flagged"]
            ],
            "latch_clean_packages": len(false_positives),
            "latch_false_positive_rate": round(
                len(false_positives) / len(clean), 4
            )
            if clean
            else 0.0,
            "clean_package_count": clean_package_count,
            "false_positive_packages": false_positives,
            "naive_flagged_packages": naive_flagged,
            "naive_false_positive_rate": round(
                len([row for row in clean if row["naive_flagged"]]) / len(clean), 4
            )
            if clean
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


def _mark(value: bool) -> str:
    return "yes" if value else "no"


def render_report(results: dict[str, Any]) -> str:
    """Render ``PACKAGE_EVAL_REPORT.md`` deterministically."""

    summary = results["summary"]
    detection = results["detection"]
    before_after = {
        row["composition_id"]: row for row in results["precision_before_after"]
    }

    lines = [
        "# Pinned-package evaluation: real `tools/list` captures",
        "",
        "Blind evaluation of Latch against real MCP packages, launched as a client",
        "would launch them, without tailoring any engine to these packages.",
        "",
        "## Method",
        "",
        "`python -m package_eval.capture_manifests` starts each pinned package,",
        "records the `tools/list` response verbatim, and resolves the pinned",
        "version from the npm registry or PyPI. Proxy packages (`mcp-remote`,",
        "`mcp-proxy`) advertise no tools of their own, so their real CLI is",
        "invoked and the cleartext endpoint they expose is probed instead.",
        "`python -m package_eval.run_package_eval` then runs `audit_manifest`,",
        "`analyze_capability_graph`, `analyze_shadowing` and `run_auth_audit`",
        "against those records plus the naive keyword baseline.",
        "",
        "Three kinds of target are scored separately:",
        "",
        "- **in-model real targets** -- a cleartext OAuth/transport proxy, an",
        "  unauthenticated cleartext SSE bridge, and a cross-server fetch +",
        "  filesystem composition. A static manifest auditor can see these.",
        "- **out-of-model real CVEs** -- pre-patch handler-level path traversal",
        "  and git argument injection. Those live in handler code, not in",
        "  `tools/list`, so they are counted honestly as misses in overall recall.",
        "- **clean reference servers** -- first-party servers expected to be",
        "  clean; every finding on them is a false positive.",
        "",
        "No rule or vocabulary was adjusted for any of these packages.",
        "",
        "## Captured packages",
        "",
        _row(
            [
                "Package",
                "Version",
                "Kind",
                "Ecosystem",
                "Protocol",
                "Tools",
                "In threat model",
                "SHA-256",
            ]
        ),
        _row(["---"] * 8),
    ]

    for row in results["packages"]:
        lines.append(
            _row(
                [
                    f"`{row['package_name']}`",
                    row["package_version"],
                    f"`{row['kind']}`",
                    row["ecosystem"],
                    f"`{row['protocol_version']}`",
                    str(row["tool_count"]),
                    _mark(row["in_latch_threat_model"]),
                    f"`{row['manifest_sha256'][:16]}…`",
                ]
            )
        )

    lines.extend(
        [
            "",
            f"Totals: {results['package_count']} packages,"
            f" {results['tool_count']} tools captured"
            f" ({sum(1 for row in results['packages'] if row['kind'] == 'proxy_metadata')}"
            " proxy/transport packages expose no tools of their own).",
            "",
            "## Real-package targets",
            "",
            _row(
                [
                    "Target",
                    "Package / composition",
                    "Class",
                    "In model",
                    "Expected",
                    "Latch",
                    "Outcome",
                    "Rules",
                ]
            ),
            _row(["---"] * 8),
        ]
    )

    target_rows = [
        row
        for row in results["packages"] + results["compositions"]
        if row["expected_positive"]
    ]
    for row in target_rows:
        lines.append(
            _row(
                [
                    f"`{row['target_id']}`",
                    row.get("label")
                    or " + ".join(f"`{slug}`" for slug in row["servers"]),
                    f"`{row['vulnerability_class']}`"
                    if row.get("vulnerability_class")
                    else "`cross_server_composition`",
                    _mark(row["in_latch_threat_model"]),
                    _mark(row["expected_positive"]),
                    _mark(row["latch_flagged"]),
                    row["outcome"],
                    ", ".join(f"`{rule}`" for rule in row["rule_ids"]) or "—",
                ]
            )
        )

    lines.extend(
        [
            "",
            "## Detection and false positives",
            "",
            _row(["Metric", "Value"]),
            _row(["---", "---"]),
            _row(
                [
                    "In-scope real-package recall",
                    f"{detection['in_scope_recall']:.2f}"
                    f" ({len(detection['in_scope_detected'])}"
                    f"/{len(detection['in_scope_targets'])})",
                ]
            ),
            _row(
                [
                    "Overall real-package recall",
                    f"{detection['overall_recall']:.2f}"
                    f" ({len(detection['overall_detected'])}"
                    f"/{detection['overall_targets']})",
                ]
            ),
            _row(
                [
                    "Latch false-positive rate on clean packages",
                    f"{summary['latch_false_positive_rate']:.2f}"
                    f" ({len(summary['false_positive_packages'])}"
                    f"/{summary['clean_package_count']})",
                ]
            ),
            _row(
                [
                    "Naive baseline false-positive rate",
                    f"{summary['naive_false_positive_rate']:.2f}",
                ]
            ),
            "",
            "- Detected in scope: "
            + (", ".join(f"`{t}`" for t in detection["in_scope_detected"]) or "none"),
            "- Missed in scope: "
            + (", ".join(f"`{t}`" for t in detection["in_scope_missed"]) or "none"),
            "- Out-of-model CVEs (handler code, not `tools/list`): "
            + (
                ", ".join(
                    f"`{t}` ({', '.join(_target_by_id(results, t)['cve_refs'])})"
                    for t in detection["out_of_model_targets"]
                )
                or "none"
            ),
            "",
        ]
    )

    lines.extend(
        [
            "## Before vs. after the static graph precision fix",
            "",
            "The pre-fix model treated every local state mutation as an",
            "`EXTERNAL_EGRESS` sink and emitted one path per",
            "(ingest, read, egress) triple. The current engine separates",
            "`LOCAL_WRITE`, only emits a path when a real egress sink exists, and",
            "collapses every read tool feeding the same `(ingest, egress)` pair.",
            "",
            _row(
                [
                    "Composition",
                    "Before: paths",
                    "Before: CRITICAL",
                    "After: paths",
                    "After: CRITICAL",
                    "Read tools collapsed into paths",
                ]
            ),
            _row(["---"] * 6),
        ]
    )
    for row in results["precision_before_after"]:
        lines.append(
            _row(
                [
                    f"`{row['composition_id']}`",
                    str(row["before_paths"]),
                    str(row["before_critical"]),
                    str(row["after_paths"]),
                    str(row["after_critical"]),
                    str(row["collapsed_read_tools"]),
                ]
            )
        )
    lines.append("")

    git_row = before_after.get("filesystem-plus-git")
    everything_row = before_after.get("everything-plus-filesystem")
    if git_row is not None:
        lines.append(
            f"- `filesystem-plus-git`: **{git_row['before_critical']} CRITICAL**"
            f" paths become **{git_row['after_critical']} CRITICAL** paths."
            " `git_commit`, `git_merge`, `git_create_branch`, `git_checkout`,"
            " `git_reset` and `git_add` are local state mutations; there is no"
            " network sink in that configuration, so no exfiltration path exists."
        )
        if everything_row is not None:
            before = everything_row["before_paths"]
            after = everything_row["after_paths"]
            reduction = before / after if after else 0
            lines.append(
                f"- `everything-plus-filesystem`: {before} raw combinations"
                f" collapse to {after} unique `(ingest, egress)` pairs"
                f" ({reduction:.1f}x fewer rows), each listing up to"
                f" {everything_row['collapsed_read_tools'] // max(after, 1)} read"
                " tools in `read_tools`."
            )
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
                    "Static paths",
                    "Expected",
                    "Outcome",
                    "Naive",
                ]
            ),
            _row(["---"] * 7),
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
                    _mark(row["expected_positive"]),
                    row["outcome"],
                    "flagged" if row["naive_flagged"] else "clean",
                ]
            )
        )

    lines.append("")
    for row in results["compositions"]:
        lines.append(f"- `{row['composition_id']}`: {row['rationale']}")
        for path in row["trifecta_paths"]:
            reads = (
                f" (+{path['collapsed_read_count'] - 1} more read tools)"
                if path["collapsed_read_count"] > 1
                else ""
            )
            lines.append(
                f"  - {path['severity']} path {path['path_id']}:"
                f" `{path['ingest_tool']}` -> `{path['read_tool']}`{reads} ->"
                f" `{path['egress_tool']}`"
            )
        if not row["trifecta_path_count"]:
            lines.append("  - no ingest -> read -> egress path")
        elif row["trifecta_path_count"] > len(row["trifecta_paths"]):
            lines.append(
                f"  - +{row['trifecta_path_count'] - len(row['trifecta_paths'])}"
                " more paths (see `package_results.json`)"
            )
        if row["miss_rationale"]:
            lines.append(f"  - why it is missed: {row['miss_rationale']}")
        for finding in row["shadow_findings"]:
            lines.append(f"  - shadow finding: {finding}")
    lines.append("")

    lines.extend(
        [
            "## What the real-package findings are telling us",
            "",
            "- **`@modelcontextprotocol/server-everything`** is the SDK's",
            "  diagnostics server. `get-env` really does read environment",
            "  variables, and `get-header-params`, `gzip-file-as-resource` and",
            "  the `trigger-*` tools carry parameter names and open-world",
            "  annotations that Latch's generic egress heuristics match. There is",
            "  no third-party sink in that surface, so the remaining static paths",
            "  are an over-approximation, and they are counted as false positives",
            "  above.",
            "- **The fetch + filesystem composition is a real blind miss.** A",
            "  GET-only fetcher can leak data in a query string, but it has no",
            "  payload parameter, so the static graph has no egress sink to",
            "  enumerate. This is recorded as a miss, not relabelled after the",
            "  fact; `latch probe-chain` is the execution-aware complement.",
            "- **Pre-patch handler CVEs are out of model.** Path traversal and git",
            "  argument injection happen inside the handlers, not in the published",
            "  schema, so `0` findings on those captures is the honest result and",
            "  it is what overall recall is measured against.",
            "",
        ]
    )

    lines.extend(["## Per-package detail", ""])

    for row in results["packages"]:
        lines.append(
            f"### `{row['package_name']}` {row['package_version']}"
            f" ({row['tool_count']} tools, `{row['kind']}`)"
        )
        lines.append("")
        if row["tool_names"]:
            lines.append(
                f"- Tools: {', '.join(f'`{name}`' for name in row['tool_names'])}"
            )
        else:
            lines.append(
                f"- Exposed transport: `{row.get('exposed_url')}`"
                " (no tools of its own)"
            )
            probe = row.get("transport_probe") or {}
            cli = probe.get("cli") or {}
            if cli.get("status") == "ok":
                lines.append(
                    f"- CLI probe: exit {cli.get('exit_code')}"
                    + (f", usage `{cli['usage']}`" if cli.get("usage") else "")
                )
            transport = probe.get("transport") or {}
            if transport.get("status") == "ok":
                lines.append(
                    f"- Cleartext probe: HTTP {transport.get('http_status')}"
                    f" `{transport.get('content_type')}`,"
                    " auth challenge:"
                    f" {'yes' if transport.get('authentication_challenge') else 'none'}"
                )
        lines.append(f"- Launched as: `{' '.join(row['launch_command'])}`")
        lines.append(
            f"- In Latch's threat model: {_mark(row['in_latch_threat_model'])}"
            f" (`{row['vulnerability_class']}`)"
        )
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
            "## What this proves, and what it does not",
            "",
            "- **Real surfaces, real provenance.** Every row above comes from an",
            "  actual package launch with a registry-resolved version and a digest",
            "  of the captured tool list; the JSON under `captured_manifests/` is",
            "  the raw record, not a hand-written model.",
            "- **Real vulnerabilities are included.** The corpus now contains",
            "  genuine pre-patch releases plus real transport exposures, not only",
            "  clean first-party servers, so recall is measured rather than",
            "  assumed.",
            "- **Blind evaluation.** No rule or vocabulary was adjusted for these",
            "  packages; they are scored exactly as any other configuration would",
            "  be.",
            "- **Only metadata is exercised.** Captures contain `tools/list` bytes",
            "  and real transport configuration. Handler behaviour, RBAC and",
            "  network policy are not observed here; `latch probe-chain` is the",
            "  execution-aware complement.",
            "- **Small sample.** Nine packages and four compositions are not the",
            "  MCP ecosystem. The result is evidence about these targets, not a",
            "  claim about registry-wide precision.",
            "- **Compositions are still static.** A clean composition means the",
            "  published schemas do not line up into a chain, not that the servers",
            "  can never exfiltrate.",
            "",
        ]
    )

    return "\n".join(lines)


def _target_by_id(results: dict[str, Any], target_id: str) -> dict[str, Any]:
    for row in results["packages"] + results["compositions"]:
        if row["target_id"] == target_id:
            return row
    raise KeyError(target_id)


def write_results(results: dict[str, Any]) -> None:
    RESULTS_JSON.write_text(
        json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    REPORT_MD.write_text(render_report(results), encoding="utf-8")


def print_summary(results: dict[str, Any]) -> None:
    detection = results["detection"]
    print(
        f"Packages: {results['package_count']}"
        f"   tools: {results['tool_count']}"
    )
    print(
        f"In-scope recall: {detection['in_scope_recall']:.2f}"
        f" ({len(detection['in_scope_detected'])}"
        f"/{len(detection['in_scope_targets'])})"
        f"   overall recall: {detection['overall_recall']:.2f}"
        f" ({len(detection['overall_detected'])}"
        f"/{detection['overall_targets']})"
        f"   FPR: {results['summary']['latch_false_positive_rate']:.2f}"
    )
    for row in results["packages"]:
        state = row["outcome"]
        print(
            f"  {row['slug']:32} {row['package_version']:10} {state}"
        )
    print(f"Compositions with paths: {results['summary']['compositions_with_paths'] or 'none'}")
    print(f"Wrote {RESULTS_JSON}")
    print(f"Wrote {REPORT_MD}")


def main() -> int:
    results = compute_results()
    write_results(results)
    print_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
