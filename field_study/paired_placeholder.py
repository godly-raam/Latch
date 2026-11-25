"""Paired measurement of the placeholder-credential lever.

Both arms run the *same* 100 holdout targets: ``field_study/holdout/captures``
was harvested with no credentials, ``field_study/holdout_placeholder/captures``
with :data:`field_study.run_field_study.PLACEHOLDER_CREDENTIAL_ENV`. Because the
targets are held fixed, the status transitions are the lever's effect in-sample;
the earlier ``field_study/placeholder`` pull is a different sample and is not
used as evidence here.

Usage::

    python -m field_study.paired_placeholder
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .run_field_study import (
    FIELD_DIR,
    HARVEST_STATUSES,
    _findings_for,
    detector_fingerprint,
    load_captures,
    load_targets,
    severity_counts,
)

HOLDOUT_DIR = FIELD_DIR / "holdout"
TREATMENT_DIR = FIELD_DIR / "holdout_placeholder"
BASELINE_CAPTURES = HOLDOUT_DIR / "captures"
TREATMENT_CAPTURES = TREATMENT_DIR / "captures"
TARGETS_JSON = HOLDOUT_DIR / "targets.json"
PAIRED_MD = TREATMENT_DIR / "PAIRED.md"
PAIRED_JSON = TREATMENT_DIR / "paired.json"

MODES = ("none", "placeholder")


def _index(captures: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {capture["slug"]: capture for capture in captures if capture.get("slug")}


def pair_rows(
    baseline: dict[str, dict[str, Any]],
    treatment: dict[str, dict[str, Any]],
    targets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """One row per target present in either arm, keyed by slug."""

    rows: list[dict[str, Any]] = []
    for slug in sorted(set(baseline) | set(treatment)):
        before = baseline.get(slug, {})
        after = treatment.get(slug, {})
        target = targets.get(slug, {})
        before_status = before.get("harvest_status", "absent")
        after_status = after.get("harvest_status", "absent")
        rows.append(
            {
                "baseline_status": before_status,
                "baseline_tools": before.get("tool_count", 0),
                "ecosystem": target.get("ecosystem")
                or after.get("ecosystem")
                or before.get("ecosystem", ""),
                "package": target.get("package") or after.get("package", ""),
                "slug": slug,
                "transition": f"{before_status} -> {after_status}",
                "treatment_status": after_status,
                "treatment_tools": after.get("tool_count", 0),
                "version": target.get("version") or after.get("version", ""),
            }
        )
    return rows


def transition_matrix(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Baseline status -> treatment status counts, in fixed status order."""

    matrix = {
        before: {after: 0 for after in HARVEST_STATUSES}
        for before in HARVEST_STATUSES
    }
    for row in rows:
        before = row["baseline_status"]
        after = row["treatment_status"]
        if before in matrix and after in matrix[before]:
            matrix[before][after] += 1
    return matrix


def new_findings(
    rows: list[dict[str, Any]], treatment: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Findings only for packages the lever newly turned into a surface."""

    findings: list[dict[str, Any]] = []
    for row in rows:
        if row["baseline_status"] == "harvested" or row["treatment_status"] != "harvested":
            continue
        capture = treatment.get(row["slug"])
        if capture is None:
            continue
        findings.extend(_findings_for(capture))
    return findings


def summarize(
    rows: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    keys = {"none": "baseline_status", "placeholder": "treatment_status"}
    status_counts = {
        mode: {
            status: sum(1 for row in rows if row[keys[mode]] == status)
            for status in HARVEST_STATUSES
        }
        for mode in MODES
    }
    newly_harvested = [
        row for row in rows if row["baseline_status"] != "harvested" and row["treatment_status"] == "harvested"
    ]
    newly_lost = [
        row for row in rows if row["baseline_status"] == "harvested" and row["treatment_status"] != "harvested"
    ]
    changed = [row for row in rows if row["baseline_status"] != row["treatment_status"]]
    by_slug: dict[str, dict[str, Any]] = {}
    for finding in findings:
        entry = by_slug.setdefault(
            finding["target"],
            {"findings": 0, "rules": Counter(), "severities": Counter()},
        )
        entry["findings"] += 1
        entry["rules"][finding["rule_id"]] += 1
        entry["severities"][finding["severity"]] += 1
    per_target = [
        {
            "findings": by_slug.get(row["slug"], {}).get("findings", 0),
            "rule_counts": dict(by_slug.get(row["slug"], {}).get("rules", {})),
            "severity_counts": dict(
                by_slug.get(row["slug"], {}).get("severities", {})
            ),
            "slug": row["slug"],
            "tools": row["treatment_tools"],
        }
        for row in newly_harvested
    ]
    return {
        "changed": changed,
        "detector_fingerprint_sha256": detector_fingerprint(),
        "findings": findings,
        "findings_per_new_target": per_target,
        "harvested_counts": {
            mode: status_counts[mode]["harvested"] for mode in MODES
        },
        "net_yield_change": status_counts["placeholder"]["harvested"]
        - status_counts["none"]["harvested"],
        "newly_harvested": newly_harvested,
        "newly_lost": newly_lost,
        "rows": rows,
        "status_counts": status_counts,
        "transition_matrix": transition_matrix(rows),
    }


def _table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Package | Ecosystem | none | placeholder | Tools |",
        "| ------- | --------- | ---- | ----------- | ----- |",
    ]
    for row in rows:
        tools = (
            f"{row['baseline_tools']} -> {row['treatment_tools']}"
            if row["baseline_status"] == row["treatment_status"] == "harvested"
            else "—"
        )
        lines.append(
            f"| `{row['slug']}` | {row['ecosystem']} | "
            f"`{row['baseline_status']}` | `{row['treatment_status']}` | {tools} |"
        )
    return lines


def render_paired(summary: dict[str, Any]) -> str:
    rows = summary["rows"]
    counts = summary["status_counts"]
    matrix = summary["transition_matrix"]
    newly_harvested = summary["newly_harvested"]
    newly_lost = summary["newly_lost"]
    other = [
        row
        for row in summary["changed"]
        if row not in newly_harvested and row not in newly_lost
    ]
    findings = summary["findings"]
    per_target = summary["findings_per_new_target"]
    total_findings = len(findings)

    lines = [
        "# Paired sample: placeholder credentials on the holdout list",
        "",
        "The lever measured **in-sample**: the same 100 holdout targets harvested",
        "twice, once with no credentials and once with the fixed dummy values in",
        "`run_field_study.PLACEHOLDER_CREDENTIAL_ENV`. Same container, memory and CPU",
        "limits, 15-second timeout, and detector fingerprint",
        f"`{summary['detector_fingerprint_sha256']}`. The target list is held fixed,",
        "so a status change is the credential intervention, not a different pull.",
        "",
        "The earlier `field_study/placeholder` pull is a **separate third sample**;",
        "it is not used as evidence for the lever and its yield table does not",
        "belong to this comparison.",
        "",
        "## Status by arm",
        "",
        "| Status | none | placeholder |",
        "| ------ | ---- | ----------- |",
    ]
    for status in HARVEST_STATUSES:
        lines.append(
            f"| `{status}` | {counts['none'][status]} | {counts['placeholder'][status]} |"
        )
    lines += [
        "",
        f"Analyzed surfaces: {summary['harvested_counts']['none']} -> "
        f"{summary['harvested_counts']['placeholder']} "
        f"(net **{summary['net_yield_change']:+d}**).",
        "",
        "## Transitions",
        "",
        "| none \\ placeholder | " + " | ".join(f"`{s}`" for s in HARVEST_STATUSES) + " |",
        "| --- | " + " | ".join("---" for _ in HARVEST_STATUSES) + " |",
    ]
    for before in HARVEST_STATUSES:
        lines.append(
            f"| `{before}` | "
            + " | ".join(str(matrix[before][after]) for after in HARVEST_STATUSES)
            + " |"
        )
    lines += [
        "",
        f"- **Newly harvested:** {len(newly_harvested)}",
        *[
            f"  - `{row['slug']}` ({row['treatment_tools']} tools)"
            for row in newly_harvested
        ],
        f"- **Newly lost:** {len(newly_lost)}",
        *[
            f"  - `{row['slug']}` ({row['baseline_status']} -> "
            f"{row['treatment_status']})"
            for row in newly_lost
        ],
        f"- **Other changes:** {len(other)}",
        *[
            f"  - `{row['slug']}` ({row['baseline_status']} -> "
            f"{row['treatment_status']})"
            for row in other
        ],
        "",
        f"**Net yield change: {summary['net_yield_change']:+d}.** "
        f"{len(newly_harvested)} package(s) that never listed tools now do; "
        f"{len(newly_lost)} that did no longer finish. A placeholder that passes "
        "a presence check can send a server into a network call that does not "
        "return inside the timeout, so part of the loss may be the credential "
        "as well, not a harness regression. One run per arm cannot separate "
        "the two.",
        "",
        "## Findings from newly harvested packages only",
        "",
    ]
    if not newly_harvested:
        lines.append("None: no package changed from a failed status to `harvested`.")
    else:
        lines += [
            f"{total_findings} finding(s) across {len(newly_harvested)} newly "
            "harvested package(s). Packages already harvested without credentials "
            "are excluded here; their findings are unchanged from the holdout.",
            "",
            "| Package | Tools | Findings | Rules |",
            "| ------- | ----- | -------- | ----- |",
        ]
        for entry in per_target:
            rules = (
                ", ".join(
                    f"`{rule}` ×{count}"
                    for rule, count in sorted(entry["rule_counts"].items())
                )
                or "—"
            )
            lines.append(
                f"| `{entry['slug']}` | {entry['tools']} | {entry['findings']} | {rules} |"
            )
        if total_findings:
            severity = severity_counts([f["severity"] for f in findings])
            lines += [
                "",
                "Severity: "
                + ", ".join(f"`{key}` {value}" for key, value in severity.items())
                + ".",
                "",
                "These are target-level findings on surfaces that only existed under",
                "placeholder credentials. They are not compositions and were not",
                "hand-triaged here.",
            ]
    lines += [
        "",
        "## Per-package status",
        "",
        *_table(rows),
        "",
        "## Limits",
        "",
        "- **In-sample, one run per arm.** The comparison holds the target list",
        "  fixed but not the network or the registry state; a package that times",
        "  out can be a transient install or a server waiting on a placeholder",
        "  token to reach a service that never answers.",
        "- **Placeholder is not authentication.** A server that validates its",
        "  token still never lists tools, so the treatment arm stays biased",
        "  toward presence-only startup checks.",
        "- **Not a rate and not recall.** 100 packages from one discovery query,",
        "  no known hostile target.",
        "- **Baseline captures predate the `credential_mode` field.** They were",
        "  harvested with no credentials and are treated as `none` here.",
        "",
    ]
    return "\n".join(lines)


def build(
    baseline_captures: Path = BASELINE_CAPTURES,
    treatment_captures: Path = TREATMENT_CAPTURES,
    targets_path: Path = TARGETS_JSON,
) -> dict[str, Any]:
    baseline = _index(load_captures(baseline_captures))
    treatment = _index(load_captures(treatment_captures))
    targets = {item["slug"]: item for item in load_targets(targets_path)}
    rows = pair_rows(baseline, treatment, targets)
    return summarize(rows, new_findings(rows, treatment))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-captures", type=Path, default=BASELINE_CAPTURES)
    parser.add_argument("--treatment-captures", type=Path, default=TREATMENT_CAPTURES)
    parser.add_argument("--targets", type=Path, default=TARGETS_JSON)
    parser.add_argument("--output-dir", type=Path, default=TREATMENT_DIR)
    args = parser.parse_args(argv)

    summary = build(args.baseline_captures, args.treatment_captures, args.targets)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / PAIRED_JSON.name
    report_path = args.output_dir / PAIRED_MD.name
    json_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    report_path.write_text(render_paired(summary), encoding="utf-8")
    print(
        f"Paired {len(summary['rows'])} targets: "
        f"{summary['harvested_counts']['none']} -> "
        f"{summary['harvested_counts']['placeholder']} harvested "
        f"({summary['net_yield_change']:+d}), "
        f"{len(summary['newly_harvested'])} newly harvested, "
        f"{len(summary['newly_lost'])} newly lost, "
        f"{len(summary['findings'])} new findings"
    )
    print(f"Wrote {json_path}, {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
