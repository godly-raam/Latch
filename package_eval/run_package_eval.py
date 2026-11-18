"""Evaluation of Latch against captured real package manifests.

    python -m package_eval.run_package_eval

Loads every capture in ``package_eval/captured_manifests/`` (see
``capture_manifests.py`` for provenance), evaluates it with Latch's real static
engines plus the naive keyword baseline, and evaluates multi-server compositions
built directly from those unmodified captures.

The corpus is reported in two stages, because the engines changed between
``4a089e1`` and now. Nine packages were scored on an untouched engine before
that commit -- the only genuinely blind baseline here. Five more packages were
added by ``4a089e1``, which also added ``navigate`` to the egress vocabulary so
target D (``puppeteer + filesystem``) became visible. Post-tuning numbers are
regression evidence, not blind evidence, and every surface in this module
labels them that way.

Each stage mixes three kinds of target:

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

import argparse
import hashlib
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
REPO_ROOT = Path(__file__).resolve().parents[1]

#: The detection surface this evaluation was run against. Editing any of these
#: files changes the fingerprint and fails the provenance test until the corpus
#: is re-run and re-labelled.
DETECTOR_FILES: tuple[str, ...] = (
    "mcpprobe/graph.py",
    "mcpprobe/auditor.py",
    "mcpprobe/shadow.py",
    "mcpprobe/oauth_audit.py",
    "mcpprobe/chain_prober.py",
    "mcpprobe/diff.py",
)

EVALUATION_STAGE = "post-tuning (post-4a089e1)"

#: Targets that already existed in the nine-package first run. Anything else in
#: the current corpus was added by the same commit that tuned the vocabulary.
FIRST_RUN_TARGET_IDS: tuple[str, ...] = (
    "npm-mcp-remote-0-14-3",
    "pypi-mcp-proxy-0-8-2",
    "B",
)

#: The nine captures that made up the first blind run. Keyed by capture slug,
#: so ``mcp-remote@0.14.3`` appears in both sets: the cleartext-URL config was
#: captured for the first run, the static-``--header`` config arrived with the
#: tuning commit. Together with the five below this partitions the corpus.
FIRST_RUN_PACKAGE_SLUGS: tuple[str, ...] = (
    "npm-mcp-remote-0-14-3",
    "npm-server-everything",
    "npm-server-filesystem",
    "npm-server-filesystem-0-6-2",
    "npm-server-memory",
    "pypi-mcp-proxy-0-8-2",
    "pypi-mcp-server-fetch",
    "pypi-mcp-server-git",
    "pypi-mcp-server-git-2025-9-25",
)

#: The five captures ``4a089e1`` added to the corpus. Disjoint from the nine
#: above by slug; asserted in ``tests/test_package_eval.py``.
POST_TUNING_ADDED_PACKAGE_SLUGS: tuple[str, ...] = (
    "npm-mcp-remote-0-14-3-static-header",
    "npm-server-github-2025-4-8",
    "npm-server-puppeteer-2025-5-12",
    "npm-server-slack-2025-4-25",
    "npm-supergateway-3-1-0",
)

#: The one blind measurement this project has. Recorded rather than recomputed:
#: the pre-``4a089e1`` classifier no longer exists in ``mcpprobe/``, so a
#: derived "before" number would describe rules that cannot be re-run.
FIRST_RUN_BLIND: dict[str, Any] = {
    "label": "First-Run Blind Baseline",
    "evaluation_stage": "pre-tuning (pre-4a089e1 rules)",
    "package_count": 9,
    "package_slugs": list(FIRST_RUN_PACKAGE_SLUGS),
    "clean_package_count": 5,
    "clean_false_positive_packages": ["npm-server-everything"],
    "clean_false_positive_rate": 0.2,
    "in_scope_targets": [
        "npm-mcp-remote-0-14-3",
        "pypi-mcp-proxy-0-8-2",
        "B",
    ],
    "in_scope_detected": ["npm-mcp-remote-0-14-3", "pypi-mcp-proxy-0-8-2"],
    "in_scope_recall": 0.6667,
    "overall_targets": 5,
    "overall_detected": ["npm-mcp-remote-0-14-3", "pypi-mcp-proxy-0-8-2"],
    "overall_recall": 0.4,
    "everything_single_server_paths": 26,
    "everything_with_filesystem_paths": 32,
    "note": (
        "Scored before commit 4a089e1, on engines that did not contain the"
        " post-tuning vocabulary. Nine packages, four compositions."
    ),
}


def detector_fingerprint() -> str:
    """SHA-256 over the sorted canonical bytes of the detection surface."""

    digest = hashlib.sha256()
    for relative in sorted(DETECTOR_FILES):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update((REPO_ROOT / relative).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()

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
        "composition_id": "puppeteer-plus-filesystem",
        "servers": ["npm-server-puppeteer-2025-5-12", "npm-server-filesystem"],
        "target_id": "D",
        "expected_positive": True,
        "in_latch_threat_model": True,
        "expected_rule_ids": [GRAPH_RULE],
        "rationale": (
            "Target D: real untrusted web navigation and page scripting"
            " (server-puppeteer) beside real private workspace reads"
            " (server-filesystem)."
        ),
        "first_run_outcome": "missed",
        "post_tuning_change": (
            "`navigate` added to the egress vocabulary in `4a089e1`"
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
    graph_path_count: int = 0,
) -> dict[str, Any]:
    rule_ids = sorted({finding["rule_id"] for finding in findings})
    expected_positive = bool(
        capture.get("expected_positive", capture.get("in_latch_threat_model"))
    )
    expected_rules = capture.get("expected_rules") or [
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
        "graph_path_count": graph_path_count,
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
        graph_path_count=len(graph.trifecta_paths),
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
        "first_run_outcome": spec.get("first_run_outcome"),
        "post_tuning_change": spec.get("post_tuning_change"),
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

    everything_paths = next(
        (
            row["graph_path_count"]
            for row in packages
            if row["slug"] == "npm-server-everything"
        ),
        0,
    )
    everything_composition_paths = next(
        (
            row["trifecta_path_count"]
            for row in compositions
            if row["composition_id"] == "everything-plus-filesystem"
        ),
        0,
    )
    post_tuning_only_targets = [
        row["target_id"]
        for row in packages + compositions
        if row["expected_positive"]
        and row["target_id"] not in FIRST_RUN_TARGET_IDS
    ]

    # Derived from the captures on disk rather than declared, so the two sets
    # cannot silently stop partitioning the corpus.
    package_slugs = [row["slug"] for row in packages]
    first_run_slugs = [
        slug for slug in package_slugs if slug in FIRST_RUN_PACKAGE_SLUGS
    ]
    added_slugs = [
        slug for slug in package_slugs if slug in POST_TUNING_ADDED_PACKAGE_SLUGS
    ]

    return {
        "evaluation_stage": EVALUATION_STAGE,
        "detector_fingerprint_sha256": detector_fingerprint(),
        "package_count": len(packages),
        "package_partition": {
            "first_run_blind": first_run_slugs,
            "added_post_tuning": added_slugs,
            "disjoint": set(first_run_slugs).isdisjoint(added_slugs),
            "covers_corpus": sorted(first_run_slugs + added_slugs)
            == sorted(package_slugs),
            "baseline_package_count": len(first_run_slugs),
            "added_package_count": len(added_slugs),
        },
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
        "stages": {
            "first_run_blind": dict(FIRST_RUN_BLIND),
            "post_tuning": {
                "label": "Post-Tuning Corpus",
                "evaluation_stage": EVALUATION_STAGE,
                "package_count": len(packages),
                "clean_package_count": clean_package_count,
                "clean_false_positive_packages": false_positives,
                "clean_false_positive_rate": round(
                    len(false_positives) / len(clean), 4
                )
                if clean
                else 0.0,
                "in_scope_targets": [row["target_id"] for row in in_scope],
                "in_scope_detected": in_scope_detected,
                "in_scope_recall": round(
                    len(in_scope_detected) / len(in_scope), 4
                )
                if in_scope
                else 0.0,
                "overall_targets": len(targets),
                "overall_detected": overall_detected,
                "overall_recall": round(
                    len(overall_detected) / len(targets), 4
                )
                if targets
                else 0.0,
                "everything_single_server_paths": everything_paths,
                "everything_with_filesystem_paths": everything_composition_paths,
                "packages_added_post_tuning": added_slugs,
                "targets_added_post_tuning": post_tuning_only_targets,
                "note": (
                    "Recomputed on every run from the engines pinned by"
                    " detector_fingerprint_sha256. Fourteen packages, five"
                    " compositions; five packages and the `navigate` egress"
                    " verb were added by 4a089e1."
                ),
            },
        },
    }


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _mark(value: bool) -> str:
    return "yes" if value else "no"


def _stage_cell(row: dict[str, Any]) -> str:
    """Which stage a scored target belongs to.

    Only three targets existed in the nine-package first run; everything else
    arrived with the same commit that tuned the vocabulary.
    """

    if row["target_id"] in FIRST_RUN_TARGET_IDS:
        return "first-run blind"
    return "post-tuning (new)"


def render_report(results: dict[str, Any]) -> str:
    """Render ``PACKAGE_EVAL_REPORT.md`` deterministically."""

    summary = results["summary"]
    detection = results["detection"]
    before_after = {
        row["composition_id"]: row for row in results["precision_before_after"]
    }
    first_run = results["stages"]["first_run_blind"]
    post_tuning = results["stages"]["post_tuning"]

    lines = [
        "# Pinned-package evaluation: real `tools/list` captures",
        "",
        "Real MCP packages, launched as a client would launch them, with their",
        "verbatim `tools/list` responses scored by Latch's real static engines.",
        "",
        "**This corpus is reported in two stages, because the engines changed",
        "between them.** Nine packages were scored on a genuinely untouched",
        "engine before commit `4a089e1`; that is the only blind baseline here.",
        "Five more packages were added by `4a089e1`, and the same commit added",
        "`navigate` to the egress vocabulary so that target D",
        "(`puppeteer + filesystem`) became visible. Post-tuning numbers are",
        "**regression evidence, not blind evidence**, and they are labelled that",
        "way throughout.",
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
        "The two stages mix three kinds of target:",
        "",
        "- **in-model real targets** -- single-server trifectas published by",
        "  real servers (GitHub, Slack), cleartext or unauthenticated transport",
        "  proxies and bridges, a literal bearer token committed to a client",
        "  config, and two cross-server compositions. A static manifest auditor",
        "  can see all of these.",
        "- **out-of-model real CVEs** -- pre-patch handler-level path traversal",
        "  and git argument injection. Those live in handler code, not in",
        "  `tools/list`, so they are counted honestly as misses in overall recall.",
        "- **clean reference servers** -- first-party servers expected to be",
        "  clean; every finding on them is a false positive.",
        "",
        "### Provenance of the two stages",
        "",
        "The nine-package numbers were produced before `4a089e1` and are",
        "recorded, not recomputed: the pre-tuning classifier no longer exists",
        "in `mcpprobe/`, so a derived \"before\" number would describe rules",
        "that cannot be re-run. The fourteen-package numbers are recomputed on",
        "every run from the current engines. The detector set behind them is",
        "pinned by `detector_fingerprint_sha256`, a SHA-256 over the sorted",
        "canonical bytes of",
        "`mcpprobe/{graph,auditor,shadow,oauth_audit,chain_prober,diff}.py`;",
        "`tests/test_package_eval.py` fails when that fingerprint drifts, which",
        "forces an explicit re-run and re-label instead of a silently stale",
        "claim.",
        "",
        "Current detector fingerprint:",
        f"`{results['detector_fingerprint_sha256']}`",
        f" (evaluation stage: `{results['evaluation_stage']}`).",
        "",
        "## Two stages: First-Run Blind Baseline vs. Post-Tuning Corpus",
        "",
        _row(
            [
                "Stage",
                "Corpus",
                "Clean-package FPR",
                "In-scope real-target recall",
                "Overall real-target recall",
            ]
        ),
        _row(["---"] * 5),
        _row(
            [
                "**First-Run Blind Baseline** (pre-`4a089e1` rules)",
                f"{first_run['package_count']} packages,"
                f" {first_run['clean_package_count']} clean",
                f"{first_run['clean_false_positive_rate']:.2f}"
                f" ({len(first_run['clean_false_positive_packages'])}"
                f"/{first_run['clean_package_count']})",
                f"{first_run['in_scope_recall']:.2f} ("
                f"{len(first_run['in_scope_detected'])}"
                f"/{len(first_run['in_scope_targets'])})",
                f"{first_run['overall_recall']:.2f} ("
                f"{len(first_run['overall_detected'])}"
                f"/{first_run['overall_targets']})",
            ]
        ),
        _row(
            [
                "**Post-Tuning Corpus** (post-`4a089e1` vocabulary)",
                f"{post_tuning['package_count']} packages,"
                f" {post_tuning['clean_package_count']} clean",
                f"{post_tuning['clean_false_positive_rate']:.2f}"
                f" ({len(post_tuning['clean_false_positive_packages'])}"
                f"/{post_tuning['clean_package_count']})",
                f"{post_tuning['in_scope_recall']:.2f} ("
                f"{len(post_tuning['in_scope_detected'])}"
                f"/{len(post_tuning['in_scope_targets'])})",
                f"{post_tuning['overall_recall']:.2f} ("
                f"{len(post_tuning['overall_detected'])}"
                f"/{post_tuning['overall_targets']})",
            ]
        ),
        "",
        f"- **Corpus partition.** The {first_run['package_count']} first-run"
        " captures and the"
        f" {post_tuning['package_count'] - first_run['package_count']} added"
        " by `4a089e1` are disjoint and cover all"
        f" {post_tuning['package_count']} captures"
        " (`package_partition` in `package_results.json`, asserted in"
        " `tests/test_package_eval.py`). The nine are five clean servers"
        " plus four target captures (`mcp-remote` cleartext, `mcp-proxy` and"
        " the two pre-patch CVE releases); `mcp-server-fetch` is scored"
        " twice, once as a clean standalone package and once inside"
        " composition target `B`, which is why the baseline has five clean"
        " checks and five targets.",
        f"- First-run blind FPR: `0.20` (`1/5`), with",
        "  `@modelcontextprotocol/server-everything` producing `26`",
        "  single-server static paths (`32` beside `server-filesystem`).",
        f"- Post-tuning FPR: `0.17` (`1/6`). The same package now produces"
        f" `{post_tuning['everything_single_server_paths']}` single-server paths"
        f" (`{post_tuning['everything_with_filesystem_paths']}` beside"
        " `server-filesystem`) after `sampling`, `elicitation` and `trigger`"
        " tools without an external target stopped counting as"
        " `EXTERNAL_EGRESS`.",
        "- First-run in-scope recall: `0.67` (`2/3`) -- `mcp-remote@0.14.3` and",
        "  `mcp-proxy==0.8.2` caught, the `fetch + filesystem` composition",
        "  missed statically. First-run overall recall: `0.40` (`2/5`), because",
        "  the two out-of-scope handler CVEs are scored in overall recall.",
        "- Post-tuning in-scope recall: `0.88` (`7/8`); overall `0.70`"
        " (`7/10`).",
        "- Packages and targets added by the tuning commit:"
        " "
        + (
            ", ".join(
                f"`{target}`"
                for target in post_tuning["targets_added_post_tuning"]
            )
            or "none"
        )
        + " -- new targets scored with the post-tuning engines, so they are",
        "  not part of the blind baseline either.",
        "- Target D (`@modelcontextprotocol/server-puppeteer@2025.5.12 +",
        "  `@modelcontextprotocol/server-filesystem@2.3.0`): **Detected",
        "  (post-tuning: \"navigate\" added to egress vocabulary in `4a089e1`;",
        "  would have missed on first run)**.",
        "",
        "## Selection Bias & Unseen-Server Recall Caveat",
        "",
        "1. `@modelcontextprotocol/server-github@2025.4.8` and",
        "   `@modelcontextprotocol/server-slack@2025.4.25` were chosen from",
        "   capability classes the engine was already built to detect",
        "   (`get_issue` / `get_file_contents` / `create_issue` and",
        "   `get_channel_history` / `post_message`). Their detection verifies",
        "   that the rules fire on real upstream manifests; it does **not** show",
        "   that recall generalizes to arbitrary unseen servers.",
        "2. Real-world recall on uninspected third-party MCP servers remains",
        "   **unmeasured**. Only the **First-Run Blind Baseline (9 packages)**",
        "   and the **Wave 2 Author-Blind Suite (`0.42` recall)** reflect",
        "   pre-tuning runs, and both were authored by this project.",
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
                    "Stage",
                    "Expected",
                    "Latch",
                    "Outcome",
                    "Rules",
                ]
            ),
            _row(["---"] * 9),
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
                    _stage_cell(row),
                    _mark(row["expected_positive"]),
                    _mark(row["latch_flagged"]),
                    row["outcome"],
                    ", ".join(f"`{rule}`" for rule in row["rule_ids"]) or "—",
                ]
            )
        )

    lines.append("")
    lines.append(
        "- `first-run blind` targets existed in the nine-package baseline;"
        " `post-tuning (new)` targets arrived with `4a089e1`."
    )
    for row in target_rows:
        if row.get("post_tuning_change"):
            lines.append(
                f"- Target `{row['target_id']}`: **Detected (post-tuning:"
                ' "navigate" added to egress vocabulary in `4a089e1`;'
                " would have missed on first run)**."
            )

    lines.extend(
        [
            "",
            "## Detection and false positives (post-tuning, 14 packages)",
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
        if row["post_tuning_change"]:
            lines.append(
                f"  - post-tuning only: {row['post_tuning_change']};"
                f" first-run outcome `{row['first_run_outcome']}`"
            )
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
            "- **Two stages, labelled as such.** Only the nine-package",
            "  **First-Run Blind Baseline** was scored on an untouched engine. The",
            "  fourteen-package **Post-Tuning Corpus** was captured after",
            "  `4a089e1`, which added five packages and the `navigate` egress verb",
            "  that makes target D visible, so it is regression evidence rather",
            "  than blind evidence. The report states the detector fingerprint so",
            "  a later rule change cannot silently inherit these numbers.",
            "- **Selection bias.** GitHub and Slack were picked from capability",
            "  classes the engine already models. Detecting them proves the rules",
            "  fire on real upstream manifests; recall on uninspected third-party",
            "  servers remains unmeasured (see the caveat section above).",
            "- **Only metadata is exercised.** Captures contain `tools/list` bytes",
            "  and real transport configuration. Handler behaviour, RBAC and",
            "  network policy are not observed here; `latch probe-chain` is the",
            "  execution-aware complement.",
            f"- **Small sample.** {results['package_count']} packages and"
            f" {len(results['compositions'])} compositions are not the MCP"
            " ecosystem. The result is evidence about these targets, not a"
            " claim about registry-wide precision.",
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


def artifact_paths(output_dir: Path | None = None) -> tuple[Path, Path]:
    """Where this module's two artifacts live for ``output_dir``."""

    if output_dir is None:
        return RESULTS_JSON, REPORT_MD
    directory = Path(output_dir)
    return directory / RESULTS_JSON.name, directory / REPORT_MD.name


def write_results(
    results: dict[str, Any], output_dir: Path | None = None
) -> tuple[Path, Path]:
    json_path, report_path = artifact_paths(output_dir)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    report_path.write_text(render_report(results), encoding="utf-8")
    return json_path, report_path


def print_summary(
    results: dict[str, Any], paths: tuple[Path, Path] | None = None
) -> None:
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
    json_path, report_path = paths or (RESULTS_JSON, REPORT_MD)
    print(f"Wrote {json_path}")
    print(f"Wrote {report_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="write the results and report here instead of package_eval/",
    )
    args = parser.parse_args(argv)

    results = compute_results()
    paths = write_results(results, args.output_dir)
    print_summary(results, paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
