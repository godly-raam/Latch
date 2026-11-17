"""Run an independent contributor's black-box probe set against mcpprobe.

    python -m adversarial.run_external_blind --check-template
    python -m adversarial.run_external_blind --input my_probes.json

The external red-team kit exists because every score in this repository before
it was authored by the same people who wrote the rules. Contributions arrive as
a JSON file in the shape documented by ``EXTERNAL_REDTEAM_BRIEF.md`` and
``external_probes_template.json``; this runner validates that file, runs the
shipped engines against every probe, and writes the result unedited.

``--check-template`` validates the shipped template only. That path exists so CI
can prove the schema and the scorer work, and it is **never** presented as a
red-team result: the template probes are illustrative examples, not a
measurement of anything.

Writes ``adversarial/external_blind_results.json`` and
``adversarial/EXTERNAL_BLIND_REPORT.md`` with sorted keys and no timestamps, so
re-running on the same input reproduces both files byte for byte.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from mcpprobe.auditor import audit_manifest
from mcpprobe.config_loader import ServerSpec
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.lockfile import create_lockfile, verify_manifest
from mcpprobe.models import ToolDefinition
from mcpprobe.oauth_audit import run_auth_audit
from mcpprobe.shadow import analyze_shadowing

EVAL_DIR = Path(__file__).resolve().parent
TEMPLATE_JSON = EVAL_DIR / "external_probes_template.json"
RESULTS_JSON = EVAL_DIR / "external_blind_results.json"
REPORT_MD = EVAL_DIR / "EXTERNAL_BLIND_REPORT.md"

SCHEMA_VERSION = 1

#: A submission is expected to be ten probes, 7-8 hostile plus 2-3 benign.
EXPECTED_PROBE_COUNT = 10

TargetSurface = Literal["audit", "graph", "shadow", "auth", "lockfile", "any"]


class ProbeSchemaError(ValueError):
    """Raised when a submission does not match the documented schema."""


class ExternalProbe(BaseModel):
    """One contributor-authored probe, expressed only against MCP metadata."""

    probe_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
    author: str = Field(min_length=1)
    target_surface: TargetSurface
    expected_positive: bool
    description: str = Field(min_length=10)

    manifest: dict[str, Any] | None = None
    servers: dict[str, list[dict[str, Any]]] | None = None
    specs: list[dict[str, Any]] | None = None
    pinned_manifest: dict[str, Any] | None = None
    current_manifest: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _inputs_match_surface(self) -> "ExternalProbe":
        surface = self.target_surface
        if surface == "audit" and self.manifest is None:
            raise ValueError("target_surface 'audit' requires 'manifest'")
        if surface == "graph" and not self.servers:
            raise ValueError("target_surface 'graph' requires 'servers'")
        if surface == "shadow" and not self.servers:
            raise ValueError("target_surface 'shadow' requires 'servers'")
        if surface == "auth" and not self.specs:
            raise ValueError("target_surface 'auth' requires 'specs'")
        if surface == "lockfile" and not (
            self.pinned_manifest is not None and self.current_manifest is not None
        ):
            raise ValueError(
                "target_surface 'lockfile' requires 'pinned_manifest' and"
                " 'current_manifest'"
            )
        if surface == "any" and not any(
            (
                self.manifest is not None,
                bool(self.servers),
                bool(self.specs),
                self.pinned_manifest is not None,
            )
        ):
            raise ValueError("target_surface 'any' requires at least one input")
        return self


class Submission(BaseModel):
    schema_version: int = Field(ge=1)
    author: str = Field(min_length=1)
    probes: list[ExternalProbe] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> "Submission":
        ids = [probe.probe_id for probe in self.probes]
        if len(ids) != len(set(ids)):
            raise ValueError("probe_id values must be unique within a submission")
        return self


def load_submission(path: Path) -> Submission:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProbeSchemaError(f"cannot read {path}: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProbeSchemaError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProbeSchemaError(f"{path}: top-level JSON value must be an object")
    try:
        submission = Submission.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - pydantic's message is the useful part
        raise ProbeSchemaError(str(exc)) from exc
    if submission.schema_version != SCHEMA_VERSION:
        raise ProbeSchemaError(
            f"schema_version {submission.schema_version} is not supported;"
            f" expected {SCHEMA_VERSION}"
        )
    return submission


def _parse_servers(
    servers: dict[str, list[dict[str, Any]]]
) -> dict[str, list[ToolDefinition]]:
    return {
        server_id: [ToolDefinition.model_validate(tool) for tool in tools]
        for server_id, tools in servers.items()
    }


def evaluate_probe(probe: ExternalProbe) -> dict[str, Any]:
    """Run every supplied input through the engine that owns it."""

    signals: dict[str, bool] = {}
    rules: list[str] = []

    try:
        if probe.pinned_manifest is not None and probe.current_manifest is not None:
            lockfile = create_lockfile(probe.pinned_manifest, "external")
            report = verify_manifest(probe.current_manifest, lockfile)
            signals["lockfile"] = not report.passed
            rules.extend(f"verify:{item.kind.value}" for item in report.drift)

        if probe.manifest is not None:
            audit = audit_manifest(probe.manifest)
            signals["audit"] = not audit.passed
            rules.extend(f"audit:{finding.rule_id}" for finding in audit.findings)

        if probe.servers:
            servers = _parse_servers(probe.servers)
            graph = analyze_capability_graph(servers)
            shadow = analyze_shadowing(servers)
            signals["graph"] = not graph.passed
            signals["shadow"] = not shadow.passed
            rules.extend("graph:LETHAL_TRIFECTA" for _ in graph.trifecta_paths)
            rules.extend(
                f"shadow:{finding.rule_id}" for finding in shadow.findings
            )

        if probe.specs:
            specs = [ServerSpec.model_validate(spec) for spec in probe.specs]
            auth = run_auth_audit(specs, None)
            signals["auth-audit"] = not auth.passed
            rules.extend(
                f"auth-audit:{finding.rule_id}" for finding in auth.findings
            )
    except Exception as exc:  # noqa: BLE001 - a broken probe is a probe error
        return {
            "probe_id": probe.probe_id,
            "error": f"{type(exc).__name__}: {exc}"[:300],
            "latch_flagged": False,
            "latch_signals": signals,
            "rules": sorted(set(rules)),
        }

    return {
        "probe_id": probe.probe_id,
        "error": None,
        "latch_flagged": any(signals.values()),
        "latch_signals": signals,
        "rules": sorted(set(rules)),
    }


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    positive = [row for row in rows if row["expected_positive"]]
    negative = [row for row in rows if not row["expected_positive"]]

    tp = sum(1 for row in positive if row["latch_flagged"])
    fn = len(positive) - tp
    fp = sum(1 for row in negative if row["latch_flagged"])
    tn = len(negative) - fp

    return {
        "probe_count": len(rows),
        "hostile_probe_count": len(positive),
        "benign_probe_count": len(negative),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 1.0,
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else 1.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "missed": sorted(row["probe_id"] for row in positive if not row["latch_flagged"]),
        "caught": sorted(row["probe_id"] for row in positive if row["latch_flagged"]),
        "benign_violations": sorted(
            row["probe_id"] for row in negative if row["latch_flagged"]
        ),
        "probe_errors": sorted(row["probe_id"] for row in rows if row["error"]),
    }


def compute_results(
    submission: Submission, *, template_mode: bool
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for probe in submission.probes:
        verdict = evaluate_probe(probe)
        rows.append(
            {
                "probe_id": probe.probe_id,
                "author": probe.author,
                "target_surface": probe.target_surface,
                "expected_positive": probe.expected_positive,
                "description": probe.description,
                **verdict,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "submission_status": (
            "template_validation_only" if template_mode else "external_submission"
        ),
        "author": submission.author,
        "metrics": metrics(rows),
        "probes": rows,
    }


def render_report(results: dict[str, Any]) -> str:
    metrics_row = results["metrics"]
    template_mode = results["submission_status"] == "template_validation_only"

    lines = [
        "# External black-box red-team: status",
        "",
    ]

    if template_mode:
        lines.extend(
            [
                "> **TEMPLATE VALIDATION ONLY — this is not a red-team result.**",
                "> The probes below are the two illustrative examples shipped in",
                "> [`external_probes_template.json`](external_probes_template.json),",
                "> run only to prove the schema and scorer work. No independent",
                "> contributor has submitted a probe set yet, so this file makes no",
                "> claim about detection quality.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                f"Independent submission by **{results['author']}**, run against",
                "the shipped engines without any rule change. The numbers below",
                "are reported exactly as computed, including every miss and every",
                "false positive.",
                "",
            ]
        )

    lines.extend(
        [
            "## Method",
            "",
            "`python -m adversarial.run_external_blind --input <path>` validates",
            "the submission against the documented schema, then runs",
            "`audit_manifest`, `analyze_capability_graph`, `analyze_shadowing`,",
            "`run_auth_audit` and the lockfile verifier on each probe. A probe",
            "counts as detected when any engine fires on it.",
            "",
            "## Metrics",
            "",
            "| TP | FP | TN | FN | Precision | Recall | FPR |",
            "| -- | -- | -- | -- | --------- | ------ | --- |",
            f"| {metrics_row['true_positives']} | {metrics_row['false_positives']}"
            f" | {metrics_row['true_negatives']} | {metrics_row['false_negatives']}"
            f" | {metrics_row['precision']:.2f} | {metrics_row['recall']:.2f}"
            f" | {metrics_row['false_positive_rate']:.2f} |",
            "",
            f"- Probes: {metrics_row['probe_count']}"
            f" ({metrics_row['hostile_probe_count']} hostile,"
            f" {metrics_row['benign_probe_count']} benign)",
            "- Caught: " + (", ".join(f"`{p}`" for p in metrics_row["caught"]) or "none"),
            "- Missed: " + (", ".join(f"`{p}`" for p in metrics_row["missed"]) or "none"),
            "- Benign probes wrongly flagged: "
            + (", ".join(f"`{p}`" for p in metrics_row["benign_violations"]) or "none"),
            "- Probe errors: "
            + (", ".join(f"`{p}`" for p in metrics_row["probe_errors"]) or "none"),
            "",
            "## Per-probe results",
            "",
            "| Probe | Surface | Expected | Verdict | Rules | Author description |",
            "| ----- | ------- | -------- | ------- | ----- | ------------------ |",
        ]
    )

    for row in results["probes"]:
        expected = "positive" if row["expected_positive"] else "negative"
        verdict = "detected" if row["latch_flagged"] else "clean"
        if row["error"]:
            verdict = f"error ({row['error']})"
        lines.append(
            f"| `{row['probe_id']}` | `{row['target_surface']}` | {expected} |"
            f" {verdict} | {', '.join(row['rules']) or '—'} |"
            f" {row['description']} |"
        )

    lines.extend(
        [
            "",
            "## How to submit a real probe set",
            "",
            "Read [`EXTERNAL_REDTEAM_BRIEF.md`](EXTERNAL_REDTEAM_BRIEF.md), write",
            "ten probes (7-8 hostile, 2-3 benign controls) in the documented JSON",
            "shape, and run",
            "`python -m adversarial.run_external_blind --input <your-file>`.",
            "Do not read `mcpprobe/` source or the shipped keyword/regex tables",
            "first: the point is an unbiased attempt.",
            "",
            "Self-authored corpora in this repository (Wave 1 and Wave 2) are",
            "upper bounds, not independent measurements. See",
            "[`WAVE2_BLIND_REPORT.md`](WAVE2_BLIND_REPORT.md).",
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


def submission_warnings(submission: Submission) -> list[str]:
    hostile = sum(1 for probe in submission.probes if probe.expected_positive)
    benign = len(submission.probes) - hostile
    warnings: list[str] = []
    if len(submission.probes) != EXPECTED_PROBE_COUNT:
        warnings.append(
            f"expected {EXPECTED_PROBE_COUNT} probes, got {len(submission.probes)}"
        )
    if hostile < 7:
        warnings.append(f"expected at least 7 hostile probes, got {hostile}")
    if benign < 2:
        warnings.append(f"expected at least 2 benign controls, got {benign}")
    return warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="External probe submission in the documented JSON schema.",
    )
    parser.add_argument(
        "--check-template",
        action="store_true",
        help=(
            "Validate and score the shipped template only. Never a red-team"
            " result; used by CI to prove the schema and scorer."
        ),
    )
    args = parser.parse_args(argv)

    if args.check_template and args.input is not None:
        parser.error("pass either --check-template or --input, not both")
    if not args.check_template and args.input is None:
        parser.error("pass --input <path>, or --check-template to validate the template")

    path = TEMPLATE_JSON if args.check_template else args.input
    assert path is not None

    try:
        submission = load_submission(path)
    except ProbeSchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.check_template:
        for warning in submission_warnings(submission):
            print(f"warning: {warning}", file=sys.stderr)

    results = compute_results(submission, template_mode=args.check_template)
    write_results(results)

    metrics_row = results["metrics"]
    print(
        f"Probes: {metrics_row['probe_count']}"
        f" ({metrics_row['hostile_probe_count']} hostile,"
        f" {metrics_row['benign_probe_count']} benign)"
    )
    print(
        f"TP={metrics_row['true_positives']}"
        f" FP={metrics_row['false_positives']}"
        f" TN={metrics_row['true_negatives']}"
        f" FN={metrics_row['false_negatives']}"
        f" (precision {metrics_row['precision']:.2f},"
        f" recall {metrics_row['recall']:.2f},"
        f" FPR {metrics_row['false_positive_rate']:.2f})"
    )
    if args.check_template:
        print("Template mode: schema validation only, not a red-team result.")
    print(f"Wrote {RESULTS_JSON}")
    print(f"Wrote {REPORT_MD}")
    return 1 if metrics_row["probe_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
