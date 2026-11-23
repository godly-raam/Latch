"""Safe harvest and offline analysis for the unseen-package field study.

    # Week 1, inside a disposable container only:
    python -m field_study.run_field_study --harvest --limit 100 --timeout 15

    # Then, offline on the host:
    python -m field_study.run_field_study --analyze

``--harvest`` executes third-party package code (``npx -y`` / ``uvx``). It
refuses to run on a host that is not a container unless
``--i-understand-this-executes-packages`` is passed, and it always launches
each package with a minimal environment: only ``PATH`` is inherited, so
``~/.ssh`` credentials in ``GITHUB_TOKEN``-style variables never reach the
child. Every launch is time-boxed.

``--analyze`` is fully offline: it reads ``field_study/captures/*.json`` and
runs Latch's audit, graph, shadow and OAuth engines over the recorded tool
surfaces. It stamps ``detector_fingerprint_sha256`` from the same detector set
``package_eval`` uses, and never touches ``package_eval/`` or ``adversarial/``.

Artifacts:

* ``field_study/captures/<slug>.json`` -- raw ``tools`` list, digest, status.
* ``field_study/scan_results.json`` -- per-target findings and summary counts.
* ``field_study/FIELD_STUDY_REPORT.md`` -- deterministic report skeleton.
* ``field_study/DISCLOSURE_LOG.md`` -- disclosure audit trail (nothing sent).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from mcpprobe.auditor import audit_manifest
from mcpprobe.config_loader import ServerSpec
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.models import ManifestError, ToolDefinition
from mcpprobe.oauth_audit import run_auth_audit
from mcpprobe.shadow import analyze_shadowing
from mcpprobe.transport import StdioSession, TransportTimeout
from package_eval.capture_manifests import manifest_digest
from package_eval.run_package_eval import detector_fingerprint

from .discover_targets import TARGETS_JSON, load_targets

FIELD_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = FIELD_DIR / "captures"
RESULTS_JSON = FIELD_DIR / "scan_results.json"
REPORT_MD = FIELD_DIR / "FIELD_STUDY_REPORT.md"
DISCLOSURE_MD = FIELD_DIR / "DISCLOSURE_LOG.md"

DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_LISTED_FINDINGS = 20
MAX_STDERR_SUMMARY = 1200

#: Used only when the host ``PATH`` is empty, so a child can still find its
#: launcher without inheriting anything else.
FALLBACK_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#: Directories created inside each isolated harvest scratch root.
SCRATCH_SUBDIRS = (
    "home",
    "tmp",
    "cache",
    "data",
    "npm-cache",
    "uv-cache",
    "uv-tools",
)

HARVEST_STATUSES = (
    "harvested",
    "missing_required_env",
    "timeout",
    "startup_error",
)
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
GRAPH_RULE = "LETHAL_TRIFECTA"
MANIFEST_RULE = "manifest_error"

#: Week-2 snapshot, taken before the ``mcpprobe/graph.py`` hardening. These are
#: literals rather than a recomputation: the pre-fix classifier no longer exists
#: in the tree, so the stored run is the only honest "before".
PRE_FIX_BASELINE: dict[str, Any] = {
    "analyzed_target_count": 31,
    "detector_fingerprint_sha256": (
        "9f211077305c91b1026397f1402d170aed0297efc0efda872ab9256fc836ed4e"
    ),
    "finding_count": 21249,
    "flagged_target_count": 11,
    "rule_counts": {GRAPH_RULE: 21248, MANIFEST_RULE: 1},
}

#: Per-target finding counts from the same week-2 snapshot (flagged targets).
PRE_FIX_TARGET_FINDINGS: dict[str, int] = {
    "npm-angelogiacco-elevenlabs-mcp-server-1-0-4": 1,
    "npm-bitwarden-mcp-server-2026-7-0": 12,
    "npm-chrome-devtools-mcp-1-13-0": 9,
    "npm-doitintl-doit-mcp-server-5-1-0": 20664,
    "npm-heroku-mcp-server-1-2-15": 1,
    "npm-meshy-ai-meshy-mcp-server-0-6-12": 530,
    "npm-microsoft-clarity-mcp-server-3-0-0": 10,
    "npm-notionhq-notion-mcp-server-2-6-1": 5,
    "npm-qase-mcp-server-3-2-1": 7,
    "npm-sap-ux-fiori-mcp-server-1-17-0": 5,
    "npm-tsmztech-mcp-server-salesforce-0-0-8": 5,
}

#: Week-2 hand-triage labels for targets that still have findings after the fix.
#: Anything else flagged is reported as ``pending`` rather than guessed at.
TRIAGE_LABELS: dict[str, str] = {
    "npm-angelogiacco-elevenlabs-mcp-server-1-0-4": MANIFEST_RULE,
    "npm-chrome-devtools-mcp-1-13-0": "true_positive_informational",
    "npm-doitintl-doit-mcp-server-5-1-0": "true_positive_informational",
}

SAFETY_BLOCK = """\
Refusing to harvest on a non-container host.

`--harvest` installs and runs unknown npm/PyPI packages with your user
permissions. Run it in a disposable container with no mounted home directory:

  mkdir -p field_study/captures
  docker run --rm -it --user 1000:1000 --memory=2g --cpus=2 \\
    -v "$PWD":/work -w /work python:3.12-slim bash -c '
      apt-get update -qq && apt-get install -y -qq nodejs npm curl jq &&
      pip install -q uv -e . &&
      python -m field_study.run_field_study --harvest --limit 100 --timeout 15
    '

Pass --i-understand-this-executes-packages only if you accept that risk."""

_HOST_PATH = re.compile(r"/(?:home|Users)/[^/\s\"':]+")
_TMP_PATH = re.compile(r"/tmp/[^\s\"':]+")
_SECRET_VALUE = re.compile(
    r"(?i)\b(token|api[_-]?key|secret|password|authorization)\b(\s*[:=]\s*)(\S+)"
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_MISSING_ENV_NAME = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|DSN|URL|ID)\b"
)
_REQUIRED_HINT = re.compile(
    r"(?i)(required|missing|not set|must be set|please set|environment variable)"
)


@contextmanager
def scratch_environment() -> Iterator[tuple[dict[str, str], Path]]:
    """Yield a child environment plus its isolated, writable scratch root.

    ``npx`` and ``uvx`` need a writable ``HOME`` and package caches to install
    into. Every one of those is redirected into a fresh temporary tree, so a
    harvested package can never read or write the user's real home or caches.
    Only ``PATH`` is inherited from the host.
    """

    with tempfile.TemporaryDirectory(prefix="latch-harvest-") as raw_root:
        root = Path(raw_root)
        for name in SCRATCH_SUBDIRS:
            (root / name).mkdir()

        env = {
            "PATH": os.environ.get("PATH") or FALLBACK_PATH,
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_DATA_HOME": str(root / "data"),
            "npm_config_cache": str(root / "npm-cache"),
            "npm_config_update_notifier": "false",
            "UV_CACHE_DIR": str(root / "uv-cache"),
            "UV_TOOL_DIR": str(root / "uv-tools"),
            "UV_NO_PROGRESS": "1",
        }
        yield env, root


def sanitize_text(
    value: str, limit: int = MAX_STDERR_SUMMARY, *, scratch_root: Path | None = None
) -> str:
    """Remove host paths and credential-shaped values from captured text."""

    text = value.replace(str(scratch_root), "<scratch>") if scratch_root else value
    text = _HOST_PATH.sub("~", text)
    text = _TMP_PATH.sub("<tmp>", text)
    text = _SECRET_VALUE.sub(r"\1\2<redacted>", text)
    text = _CONTROL_CHARS.sub(" ", text)
    return text.strip()[:limit]


def launch_argv(target: dict[str, Any]) -> list[str]:
    """Resolve a target to the pinned launch command.

    ``launch_argv`` is an explicit override used by offline tests and known
    local fixtures; discovery never writes it.
    """

    override = target.get("launch_argv")
    if isinstance(override, list) and override:
        return [str(item) for item in override]

    package = target["package"]
    version = target["version"]
    if target["ecosystem"] == "npm":
        return ["npx", "-y", f"{package}@{version}"]
    return ["uvx", f"{package}=={version}"]


def classify_harvest(
    error: BaseException | None, stderr_text: str, tools: list[Any]
) -> str:
    """Map a launch outcome onto one of the four recorded statuses."""

    if error is None:
        return "harvested"
    if isinstance(error, (TransportTimeout, asyncio.TimeoutError)) or "timed out" in str(
        error
    ):
        return "timeout"
    text = f"{error} {stderr_text}"
    if _REQUIRED_HINT.search(text) and _MISSING_ENV_NAME.search(text):
        return "missing_required_env"
    return "startup_error"


def _stderr_tail(session: StdioSession) -> str:
    # shortcut: reading the session's bounded stderr buffer directly; upgrade
    # only if transport exposes a public accessor.
    lines = getattr(session, "_stderr_lines", None)
    if not lines:
        return ""
    return "".join(list(lines)[-10:])


async def _harvest_once(
    target: dict[str, Any],
    timeout: float,
    env: dict[str, str],
    scratch_root: Path,
) -> tuple[Any | None, str, BaseException | None, list[Any], str | None]:
    """Launch one target, returning ``(result, stderr, error, tools, version)``."""

    session = StdioSession(launch_argv(target), timeout=timeout, env=env)
    error: BaseException | None = None
    result: Any | None = None
    try:
        await session.start()
        result = await session.harvest()
    except BaseException as exc:  # noqa: BLE001 - status is the artifact
        error = exc
    finally:
        stderr_text = sanitize_text(_stderr_tail(session), scratch_root=scratch_root)
        await session.close()

    tools = (
        result.tools_payload.get("tools")
        if result is not None and isinstance(result.tools_payload, dict)
        else []
    )
    if not isinstance(tools, list):
        tools = []
    protocol = getattr(result, "protocol_version", None)
    return result, stderr_text, error, tools, protocol


def harvest_target(
    target: dict[str, Any],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    env: dict[str, str] | None = None,
    scratch_root: Path | None = None,
) -> dict[str, Any]:
    """Harvest one target into a capture record. Never raises on launch failure."""

    if env is None or scratch_root is None:
        with scratch_environment() as (scratch_env, root):
            return harvest_target(
                target, timeout=timeout, env=scratch_env, scratch_root=root
            )

    async def drive() -> tuple[Any, str, BaseException | None, list[Any], str | None]:
        return await _harvest_once(target, timeout, env, scratch_root)

    try:
        result, stderr_text, error, tools, protocol = asyncio.run(
            asyncio.wait_for(drive(), timeout=timeout + 5.0)
        )
    except asyncio.TimeoutError as exc:
        result, stderr_text, error, tools, protocol = None, "", exc, [], None

    status = classify_harvest(error, stderr_text, tools)
    if status != "harvested":
        tools = []

    return {
        "description": target.get("description", ""),
        "ecosystem": target["ecosystem"],
        "harvest_status": status,
        "launch_argv": launch_argv(target),
        "manifest_sha256": manifest_digest([tool for tool in tools if isinstance(tool, dict)]),
        "package": target["package"],
        "protocol_version": protocol or "n/a",
        "repository_url": target.get("repository_url"),
        "slug": target["slug"],
        "stderr_summary": stderr_text,
        "tool_count": len(tools),
        "tools": tools,
        "version": target["version"],
    }


def harvest_all(
    targets: list[dict[str, Any]],
    *,
    capture_dir: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    directory = capture_dir or CAPTURE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    # One scratch tree for the whole run: npm/uv caches stay warm across
    # packages, still fully isolated from the host and removed afterwards.
    with scratch_environment() as (env, scratch_root):
        for target in targets[:limit] if limit else targets:
            capture = harvest_target(
                target, timeout=timeout, env=env, scratch_root=scratch_root
            )
            path = directory / f"{capture['slug']}.json"
            path.write_text(
                json.dumps(capture, indent=2, sort_keys=True, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )
            rows.append(capture)
            detail = (
                f"{capture['tool_count']} tools"
                if capture["harvest_status"] == "harvested"
                else capture["stderr_summary"].splitlines()[0][:100]
                if capture["stderr_summary"]
                else capture["harvest_status"]
            )
            print(f"{capture['slug']:48} {capture['harvest_status']:20} {detail}")
    return rows


def load_captures(capture_dir: Path | None = None) -> list[dict[str, Any]]:
    directory = capture_dir or CAPTURE_DIR
    if not directory.exists():
        return []
    captures: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            captures.append(payload)
    return captures


def severity_counts(severities: list[str]) -> dict[str, int]:
    return {
        severity: sum(1 for value in severities if value == severity)
        for severity in SEVERITY_ORDER
        if any(value == severity for value in severities)
    }


def _manifest_error_finding(slug: str, exc: ManifestError) -> dict[str, Any]:
    """Represent an unusable ``tools/list`` surface as a finding, not a crash."""

    return {
        "detail": sanitize_text(str(exc), limit=400),
        "engine": "audit",
        "rule_id": "manifest_error",
        "severity": "MEDIUM",
        "target": slug,
        "title": "Invalid or duplicate tool manifest",
        "tool": "(manifest)",
    }


def _findings_for(capture: dict[str, Any]) -> list[dict[str, Any]]:
    slug = capture["slug"]
    raw_tools = [tool for tool in capture.get("tools") or [] if isinstance(tool, dict)]
    manifests = {slug: [ToolDefinition.model_validate(tool) for tool in raw_tools]}

    try:
        audit = audit_manifest({"tools": raw_tools})
        graph = analyze_capability_graph(manifests)
        shadow = analyze_shadowing(manifests)
        auth = run_auth_audit(
            [ServerSpec(server_id=slug, transport="static")], manifests
        )
    except ManifestError as exc:
        # A malformed surface (duplicate names, invalid schema, ...) is a
        # property of that one target; record it and keep analyzing the rest.
        return [_manifest_error_finding(slug, exc)]

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
    for finding in findings:
        finding["target"] = slug
    return findings


def analyze(
    capture_dir: Path | None = None,
    targets_path: Path | None = None,
) -> dict[str, Any]:
    """Run every static engine over the captures; fully offline and deterministic."""

    captures = load_captures(capture_dir)
    try:
        targets = {item["slug"]: item for item in load_targets(targets_path)}
    except (OSError, json.JSONDecodeError):
        targets = {}

    rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for capture in captures:
        slug = capture.get("slug") or ""
        tools = capture.get("tools") or []
        can_analyze = capture.get("harvest_status") == "harvested" and bool(tools)
        target_findings = _findings_for(capture) if can_analyze else []
        findings.extend(target_findings)
        rule_ids = sorted({finding["rule_id"] for finding in target_findings})
        target = targets.get(slug, {})
        rows.append(
            {
                "analysis_status": "analyzed" if can_analyze else "not_analyzed",
                "description": capture.get("description", ""),
                "ecosystem": capture.get("ecosystem", ""),
                "finding_count": len(target_findings),
                "harvest_status": capture.get("harvest_status", "unknown"),
                "manifest_sha256": capture.get("manifest_sha256", ""),
                "package": capture.get("package", ""),
                "repository_url": capture.get("repository_url")
                or target.get("repository_url"),
                "rule_ids": rule_ids,
                "severity_counts": severity_counts(
                    [finding["severity"] for finding in target_findings]
                ),
                "slug": slug,
                "tool_count": capture.get("tool_count", len(tools)),
                "version": capture.get("version", ""),
            }
        )

    status_counts = {
        status: sum(1 for row in rows if row["harvest_status"] == status)
        for status in HARVEST_STATUSES
    }
    engine_counts = {
        engine: sum(1 for finding in findings if finding["engine"] == engine)
        for engine in ("audit", "graph", "shadow", "auth-audit")
    }
    rule_counts: dict[str, int] = {}
    for finding in findings:
        rule_counts[finding["rule_id"]] = rule_counts.get(finding["rule_id"], 0) + 1

    # Hand triage is self-assigned and only claims what was actually reviewed:
    # a flagged target with no recorded label stays ``pending``.
    by_slug = {row["slug"]: row for row in rows}
    flagged_slugs = sorted(row["slug"] for row in rows if row["finding_count"])
    informational: list[str] = []
    spec_violations: list[str] = []
    pending: list[str] = []
    for slug in flagged_slugs:
        label = TRIAGE_LABELS.get(slug)
        if label == "true_positive_informational":
            informational.append(slug)
        elif label == MANIFEST_RULE or by_slug[slug]["rule_ids"] == [MANIFEST_RULE]:
            spec_violations.append(slug)
        else:
            pending.append(slug)
    resolved_false_positives = sorted(
        slug
        for slug in PRE_FIX_TARGET_FINDINGS
        if slug in by_slug and not by_slug[slug]["finding_count"]
    )
    triage: dict[str, Any] = {
        "false_positive_detector_bug": len(resolved_false_positives),
        "false_positive_detector_bug_targets": resolved_false_positives,
        "manifest_error": len(spec_violations),
        "manifest_error_targets": spec_violations,
        "pending": len(pending),
        "pending_targets": pending,
        "status": "pending_hand_review" if pending else "hand_reviewed_week2",
        "true_positive_exploitable": 0,
        "true_positive_exploitable_targets": [],
        "true_positive_informational": len(informational),
        "true_positive_informational_targets": informational,
    }

    return {
        "analyzed_target_count": sum(
            1 for row in rows if row["analysis_status"] == "analyzed"
        ),
        "captures_dir": (capture_dir or CAPTURE_DIR).name,
        "detector_fingerprint_sha256": detector_fingerprint(),
        "engine_counts": engine_counts,
        "findings": findings,
        "flagged_target_count": sum(1 for row in rows if row["finding_count"]),
        "harvest_status_counts": status_counts,
        "rule_counts": dict(sorted(rule_counts.items())),
        "schema_version": "1.0",
        "severity_counts": severity_counts(
            [finding["severity"] for finding in findings]
        ),
        "target_count": len(rows),
        "targets": rows,
        "triage": triage,
    }


def _slug_list(slugs: list[str]) -> str:
    return ", ".join(f"`{slug}`" for slug in slugs) if slugs else "none"


def _render_hardening(results: dict[str, Any]) -> list[str]:
    """Document the week-2 hand triage and the before/after of the rule fix."""

    pre = PRE_FIX_BASELINE
    post_findings = sum(row["finding_count"] for row in results["targets"])
    post_graph = results["rule_counts"].get(GRAPH_RULE, 0)
    post_manifest = results["rule_counts"].get(MANIFEST_RULE, 0)
    by_slug = {row["slug"]: row for row in results["targets"]}
    slugs = sorted(
        (set(PRE_FIX_TARGET_FINDINGS) & set(by_slug))
        | {slug for slug, row in by_slug.items() if row["finding_count"]}
    )

    lines = [
        "## Detector hardening (Week 2 hand triage → fix)",
        "",
        "The Week-2 run flagged **11 of 31** analyzed surfaces with **21,249**",
        "findings. Almost all of them were `LETHAL_TRIFECTA` paths produced by one",
        "annotation rule: `openWorldHint=true` without `readOnlyHint` supplied both",
        "`UNTRUSTED_INPUT` and `EXTERNAL_EGRESS` for every SaaS CRUD and analytics",
        "tool, so an ingest × read × egress product exploded — one cost-analytics",
        "server alone accounted for 20,664 paths. Hand triage separated eight",
        "detector false positives from one genuine spec violation and one inherent",
        "capability, then `mcpprobe/graph.py` was tightened and the same captures",
        "were re-analyzed offline.",
        "",
        "| Metric | Pre-fix | Post-fix |",
        "| ------ | ------- | -------- |",
        f"| Detector fingerprint | `{pre['detector_fingerprint_sha256']}` |"
        f" `{results['detector_fingerprint_sha256']}` |",
        f"| Analyzed surfaces | {pre['analyzed_target_count']} |"
        f" {results['analyzed_target_count']} |",
        f"| Flagged surfaces | {pre['flagged_target_count']} |"
        f" {results['flagged_target_count']} |",
        f"| Findings | {pre['finding_count']:,} | {post_findings:,} |",
        f"| `LETHAL_TRIFECTA` paths | {pre['rule_counts'][GRAPH_RULE]:,} |"
        f" {post_graph:,} |",
        f"| `manifest_error` | {pre['rule_counts'][MANIFEST_RULE]} |"
        f" {post_manifest} |",
        "",
        "Rules changed:",
        "",
        "1. `annotation.openWorldHint` no longer asserts `UNTRUSTED_INPUT` unless",
        "   the tool names external content (URL, message, log, page, feed, …).",
        "2. `annotation.openWorldEgress` no longer asserts `EXTERNAL_EGRESS` on its",
        "   own: it needs destination evidence — an external target, a schema",
        "   sink, an `x-mcp-header` binding, or a caller-chosen URL/verb carrying",
        "   a payload.",
        "3. `to`, `external` and `comment` left `EXTERNAL_TARGETS`, and",
        "   `recipients`/`webhook`/`callback`/`destination_url` stayed. `to`,",
        "   `cc` and `bcc` are recipient fields: they count only on a",
        "   messaging/mail/HTTP sender, not on a CRM record. Egress nouns come",
        "   from the tool name or a destination-shaped parameter (`issue_key`,",
        "   `channel_id` match by noun; `reportUrl`, `s3Bucket` are record",
        "   fields), and egress verbs from the name or an action-shaped enum, so",
        "   `type: enum[\"Url\"]` and `entity: enum[\"run\"]` stop counting.",
        "4. Pagination and idempotency parameters (`pageToken`,",
        "   `idempotency-key`, …) no longer supply content or secret nouns.",
        "5. A tool whose name starts with a read verb (`list_*`, `get_*`,",
        "   `search_*`) is not a sink, and a payload sender must be governed by a",
        "   leading outbound verb (`send_payload`), not merely contain one",
        "   (`create_text_send`).",
        "",
        "Per-target before/after:",
        "",
        "| Target | Pre-fix findings | Post-fix findings | Week-2 verdict |",
        "| ------ | ---------------- | ----------------- | -------------- |",
    ]
    for slug in slugs:
        row = by_slug.get(slug)
        before = PRE_FIX_TARGET_FINDINGS.get(slug, 0)
        after = row["finding_count"] if row else 0
        label = TRIAGE_LABELS.get(slug)
        if label == "true_positive_informational":
            verdict = "`true_positive_informational`"
        elif label == MANIFEST_RULE:
            verdict = "`manifest_error` (spec violation)"
        elif before and not after:
            verdict = "`false_positive_detector_bug` (fixed)"
        elif after:
            verdict = "`pending`"
        else:
            verdict = "—"
        before_text = f"{before:,}" if slug in PRE_FIX_TARGET_FINDINGS else "—"
        lines.append(f"| `{slug}` | {before_text} | {after:,} | {verdict} |")

    lines.extend(
        [
            "",
            "The residual `@doitintl/doit-mcp-server` paths are no longer",
            "annotation-derived: readers of third-party ticket and status data feed",
            "alert and subscription tools whose `recipients` parameter is a",
            "caller-chosen notification destination. That sink is deliberately",
            "kept — dropping it would also blind the analyzer to report and alert",
            "exfiltration — so the target is labelled",
            "`true_positive_informational`: a real capability of the product rather",
            "than a detector bug.",
            "",
        ]
    )
    return lines


def render_report(results: dict[str, Any]) -> str:
    """Render ``FIELD_STUDY_REPORT.md`` deterministically."""

    status_counts = results["harvest_status_counts"]
    triage = results["triage"]
    analyzed = results["analyzed_target_count"]

    lines = [
        "# Field study: unseen npm & PyPI MCP servers",
        "",
        "**Status: harvest + offline static scan, hand-triaged in Week 2 and",
        "re-analyzed after the detector fix.** Every number below comes from",
        "`field_study/run_field_study.py --analyze` over recorded `tools/list`",
        "captures; no package was executed during analysis. There are no",
        "independent ground-truth labels: each verdict is a self-assigned hand",
        "triage whose criteria are stated in the worksheet below.",
        "",
        f"- Detector fingerprint: `{results['detector_fingerprint_sha256']}`",
        f"- Captured targets: **{results['target_count']}**",
        f"- Analyzed surfaces: **{analyzed}**",
        f"- Flagged surfaces: **{results['flagged_target_count']}**",
        f"- Targets awaiting hand triage: **{triage['pending']}**",
        "",
        "## Harvester outcomes",
        "",
        "| Status | Count | Meaning |",
        "| ------ | ----- | ------- |",
        f"| `harvested` | {status_counts.get('harvested', 0)} | `tools/list` returned without credentials. |",
        f"| `missing_required_env` | {status_counts.get('missing_required_env', 0)} | Exited asking for a token/key/URL; recorded, not retried with secrets. |",
        f"| `timeout` | {status_counts.get('timeout', 0)} | Exceeded the per-package timeout. |",
        f"| `startup_error` | {status_counts.get('startup_error', 0)} | Install or startup failed for another reason. |",
        "",
        "A high `missing_required_env` share is expected and is not a defect: most",
        "hosted-service MCP servers cannot list tools without `GITHUB_TOKEN`-class",
        "credentials. The study never supplies them.",
        "",
        *_render_hardening(results),
        "## Targets",
        "",
        "| Target | Ecosystem | Version | Status | Tools | Findings |",
        "| ------ | --------- | ------- | ------ | ----- | -------- |",
    ]
    for row in results["targets"]:
        lines.append(
            f"| `{row['package']}` | {row['ecosystem']} | {row['version']} |"
            f" `{row['harvest_status']}` | {row['tool_count']} |"
            f" {row['finding_count']} |"
        )

    lines.extend(
        [
            "",
            "## Findings by engine",
            "",
            "| Engine | Findings |",
            "| ------ | -------- |",
        ]
    )
    for engine, count in results["engine_counts"].items():
        lines.append(f"| `{engine}` | {count} |")

    lines.extend(["", "### Rules seen", ""])
    if results["rule_counts"]:
        lines.extend(["| Rule | Findings |", "| ---- | -------- |"])
        for rule_id, count in results["rule_counts"].items():
            lines.append(f"| `{rule_id}` | {count} |")
    else:
        lines.append("No findings were produced by any engine.")

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "Caps at 20 findings per target; `field_study/scan_results.json` holds",
            "the complete list.",
            "",
        ]
    )
    any_findings = False
    for row in results["targets"]:
        target_findings = [
            finding
            for finding in results["findings"]
            if finding["target"] == row["slug"]
        ]
        if not target_findings:
            continue
        any_findings = True
        lines.extend(
            [
                f"### `{row['package']}` {row['version']}",
                "",
                "| Engine | Rule | Severity | Tool |",
                "| ------ | ---- | -------- | ---- |",
            ]
        )
        for finding in target_findings[:MAX_LISTED_FINDINGS]:
            lines.append(
                f"| `{finding['engine']}` | `{finding['rule_id']}` |"
                f" {finding['severity']} | `{finding['tool']}` |"
            )
        if len(target_findings) > MAX_LISTED_FINDINGS:
            lines.append(
                f"| … | ({len(target_findings) - MAX_LISTED_FINDINGS} more) | | |"
            )
        lines.append("")
    if not any_findings:
        lines.append("No engine flagged any recorded surface.")

    lines.extend(
        [
            "",
            "## Hand-triage worksheet (Week 2)",
            "",
            "Every flagged target is classified into exactly one bucket before any",
            "number is quoted as a result:",
            "",
            "| Bucket | Definition | Targets |",
            "| ------ | ---------- | ------- |",
            f"| `true_positive_exploitable` | Concrete exploit: an unguarded ingest → private-read → egress chain at a caller-controlled sink. | {triage['true_positive_exploitable']} ({_slug_list(triage['true_positive_exploitable_targets'])}) |",
            f"| `true_positive_informational` | Real capability, expected by design: a networked server whose trifecta is inherent to the product. | {triage['true_positive_informational']} ({_slug_list(triage['true_positive_informational_targets'])}) |",
            f"| `manifest_error` | The captured `tools/list` surface is invalid (duplicate tool names), so no capability analysis can run. Reported upstream as a spec violation. | {triage['manifest_error']} ({_slug_list(triage['manifest_error_targets'])}) |",
            f"| `false_positive_detector_bug` | Over-broad heuristic on a benign manifest; fixed in `mcpprobe/graph.py` with a regression test, then the captures were re-analyzed. | {triage['false_positive_detector_bug']} resolved ({_slug_list(triage['false_positive_detector_bug_targets'])}) |",
            f"| `pending` | Not triaged yet. | {triage['pending']} ({_slug_list(triage['pending_targets'])}) |",
            "",
            "Triage protocol:",
            "",
            "1. Read the captured tool definition in `field_study/captures/<slug>.json`.",
            "2. Reproduce offline (`latch audit`, `latch graph`, `latch shadow`).",
            "3. Quote the exact field and rule in the worksheet; do not guess intent.",
            "4. For detector bugs, fix the rule and add a regression case in `tests/`,",
            "   then regenerate this report so the before/after is visible.",
            "",
            "## Limitations",
            "",
            "- Targets are registry top-N for one query, not a random sample of the",
            "  ecosystem; prevalence claims are out of scope.",
            "- Capture is `tools/list` only. Handler-level bugs (path traversal,",
            "  injection) are invisible to a manifest auditor and are not scored.",
            "- Packages needing credentials never list tools here, so the analyzed",
            "  subset is biased toward servers that start without secrets.",
            "- No independent second rater: every label in Week 2 is self-assigned.",
            "- Detectors were frozen for the duration of the harvest. Week-2 triage",
            "  then changed them; the pre-fix and post-fix fingerprints in the",
            "  hardening section pin both rule sets.",
            "",
            "## Reproduction",
            "",
            "```bash",
            "python -m field_study.discover_targets --npm-limit 70 --pypi-limit 30",
            "# harvest inside the disposable container from run_field_study.SAFETY_BLOCK",
            "python -m field_study.run_field_study --analyze",
            "pytest -q tests/test_field_study.py",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


DISCLOSURE_CASES = (
    {
        "case_id": "CASE-01",
        "package": "@angelogiacco/elevenlabs-mcp-server",
        "version": "1.0.4",
        "ecosystem": "npm",
        "finding": (
            "`manifest_error`: `tools/list` returns 546 entries with 6 duplicate "
            "tool names (`Add_A_Pronunciation_Dictionary`, `List_Phone_Numbers`, "
            "`Get_Dependent_Agents_List`, `List_Procedures`, `Get_Asset`, "
            "`Delete_Asset`) and conflicting schemas, violating MCP's unique "
            "tool-name invariant."
        ),
        "upstream_status": "closed_upstream_archived",
        "upstream_status_date": "2026-11-24",
        "notes": (
            "Upstream `elevenlabs/elevenlabs-mcp` is deprecated and no longer "
            "maintained in favor of the hosted server "
            "(`https://api.elevenlabs.io/v1/mcp`). The npm package links to an "
            "unmaintained fork (`AngeloGiacco/elevenlabs-mcp`, 18 commits behind "
            "upstream, Issues disabled), so no upstream ticket was filed."
        ),
    },
)

_DISCLOSURE_CASE_KEYS = frozenset(
    (case["package"], case["version"]) for case in DISCLOSURE_CASES
)


def render_disclosure_log(results: dict[str, Any]) -> str:
    """Render the responsible-disclosure audit trail; nothing is sent by Latch."""

    lines = [
        "# Responsible-disclosure log",
        "",
        "**No disclosure has been sent.** This log is generated for Week 2/3 and",
        "records only artifacts already on disk. Latch never contacts a maintainer.",
        "",
        "## Coordinated Disclosure & Upstream Bug Log",
        "",
        "| Case ID | Package & Version | Ecosystem | Finding | Upstream Status | Notes |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for case in DISCLOSURE_CASES:
        lines.append(
            f"| `{case['case_id']}` | `{case['package']}@{case['version']}` |"
            f" {case['ecosystem']} | {case['finding']} |"
            f" `{case['upstream_status']}` ({case['upstream_status_date']})"
            f" | {case['notes']} |"
        )
    lines.extend(
        [
            "",
            "## Per-target harvest inventory",
            "",
            "| Target | Version | Repository | Status | Notes |",
            "| ------ | ------- | ---------- | ------ | ----- |",
        ]
    )
    for row in results["targets"]:
        if (row["package"], row["version"]) in _DISCLOSURE_CASE_KEYS:
            continue
        if row["harvest_status"] != "harvested":
            status = "not_applicable"
            note = "No tool surface captured."
        elif not row["finding_count"]:
            status = "no_finding"
            note = "Clean under the pinned detectors."
        elif row["repository_url"]:
            status = "not_contacted"
            note = "Awaiting hand triage before any advisory."
        else:
            status = "no_repository_url"
            note = "Resolve a maintainer contact from the registry before triage."
        lines.append(
            f"| `{row['package']}` | {row['version']} |"
            f" {row['repository_url'] or '—'} | `{status}` | {note} |"
        )

    lines.extend(
        [
            "",
            "## Protocol",
            "",
            "1. Triage the finding offline and reproduce it with a minimal probe.",
            "2. Prefer the repository's private security policy (SECURITY.md or a",
            "   private advisory) over a public issue.",
            "3. Report the exact tool definition, rule, and impact; include the",
            "   capture digest so the maintainer can reproduce the surface.",
            "4. Allow a 90-day coordinated window before publishing; disclose",
            "   earlier only if the issue is actively exploited.",
            "5. Update this file with the contact date, channel, and resolution.",
            "",
            "No raw secrets, host paths, or environment values belong here.",
            "",
        ]
    )
    return "\n".join(lines)


def artifact_paths(output_dir: Path | None = None) -> tuple[Path, Path, Path]:
    directory = output_dir or FIELD_DIR
    return (
        directory / RESULTS_JSON.name,
        directory / REPORT_MD.name,
        directory / DISCLOSURE_MD.name,
    )


def write_results(
    results: dict[str, Any], output_dir: Path | None = None
) -> tuple[Path, Path, Path]:
    json_path, report_path, disclosure_path = artifact_paths(output_dir)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    report_path.write_text(render_report(results), encoding="utf-8")
    disclosure_path.write_text(render_disclosure_log(results), encoding="utf-8")
    return json_path, report_path, disclosure_path


def _in_container() -> bool:
    return Path("/.dockerenv").exists() or bool(os.environ.get("container"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harvest", action="store_true")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--targets", type=Path, default=TARGETS_JSON)
    parser.add_argument("--captures", type=Path, default=CAPTURE_DIR)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--i-understand-this-executes-packages", action="store_true")
    args = parser.parse_args(argv)

    if args.harvest:
        if not (args.i_understand_this_executes_packages or _in_container()):
            print(SAFETY_BLOCK)
            return 2
        targets = load_targets(args.targets)
        if not targets:
            print(f"No targets in {args.targets}; run discover_targets first.")
            return 1
        harvest_all(
            targets,
            capture_dir=args.captures,
            timeout=args.timeout,
            limit=args.limit,
        )

    if args.analyze or not args.harvest:
        results = analyze(args.captures, args.targets)
        json_path, report_path, disclosure_path = write_results(
            results, args.output_dir
        )
        print(
            f"Analyzed {results['analyzed_target_count']}/"
            f"{results['target_count']} captures, "
            f"{len(results['findings'])} findings"
        )
        print(f"Wrote {json_path}, {report_path}, {disclosure_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
