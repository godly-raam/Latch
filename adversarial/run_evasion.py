"""Deterministic adversarial self-red-team run over Latch's own engines.

    python -m adversarial.run_evasion

Each probe is evaluated with the engine that must catch it:

* ``graph`` for capability-synonym and enum-indirection probes;
* ``shadow`` for homoglyph collisions and routing-hijack lexicon probes;
* ``audit`` for variation selectors and header-binding obfuscation;
* ``auth-audit`` for token passthrough and query-string credentials;
* ``probe-chain`` for live base64/query/4-hop exfiltration.

Writes ``adversarial/evasion_results.json`` and ``adversarial/EVASION_REPORT.md``
with no timestamps and sorted keys, so a re-run reproduces both byte for byte.
Live probes record only their deterministic verdict fields, never the random
canary token.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from mcpprobe.auditor import audit_manifest
from mcpprobe.chain_prober import verify_trifecta_chains
from mcpprobe.config_loader import ServerSpec
from mcpprobe.graph import analyze_capability_graph
from mcpprobe.models import ToolDefinition
from mcpprobe.oauth_audit import run_auth_audit
from mcpprobe.shadow import analyze_shadowing

from .probes import (  # noqa: F401 - PROBES re-exported for tests
    BOUNDARY_PROBES,
    CAUGHT_PROBES,
    PROBES,
    AdversarialProbe,
)

EVAL_DIR = Path(__file__).resolve().parent
RESULTS_JSON = EVAL_DIR / "evasion_results.json"
REPORT_MD = EVAL_DIR / "EVASION_REPORT.md"


def _parse_tools(raw: dict[str, list[dict[str, Any]]]) -> dict[str, list[ToolDefinition]]:
    return {
        server_id: [ToolDefinition.model_validate(tool) for tool in tools]
        for server_id, tools in raw.items()
    }


def _redacted(summary: str, canary_token: str) -> str:
    """Strip the random canary from a sink summary so artifacts stay stable."""

    cleaned = summary.replace(canary_token, "LATCH-CANARY-<redacted>")
    return cleaned.replace(quote(canary_token), "LATCH-CANARY-<redacted>")


def evaluate_probe(probe: AdversarialProbe) -> dict[str, Any]:
    """Run the engine(s) this probe targets and return its verdict."""

    signals: dict[str, bool] = {}
    live: dict[str, Any] | None = None

    if probe.audit_payload is not None:
        signals["audit"] = not audit_manifest(probe.audit_payload).passed

    if probe.graph_servers:
        graph = analyze_capability_graph(
            _parse_tools(probe.graph_servers),
            trusted_servers=set(probe.trusted_servers) or None,
        )
        signals["graph"] = not graph.passed

    if probe.shadow_servers:
        shadow = analyze_shadowing(
            _parse_tools(probe.shadow_servers),
            trusted_servers=set(probe.trusted_servers) or None,
        )
        signals["shadow"] = not shadow.passed

    if probe.auth_specs:
        auth = run_auth_audit(
            [ServerSpec.model_validate(spec) for spec in probe.auth_specs],
            _parse_tools(probe.auth_manifests) if probe.auth_manifests else None,
        )
        signals["auth-audit"] = not auth.passed

    if probe.live_chain_specs:
        report = asyncio.run(
            verify_trifecta_chains(
                [ServerSpec.model_validate(spec) for spec in probe.live_chain_specs],
                timeout=10.0,
            )
        )
        signals["probe-chain"] = report.confirmed_exploitable > 0
        live = {
            "server_count": report.server_count,
            "paths_tested": report.paths_tested,
            "confirmed_exploitable": report.confirmed_exploitable,
            "statuses": [result.status for result in report.results],
            "sink_request_summaries": [
                _redacted(summary, result.canary_token)
                for result in report.results
                if (summary := result.sink_request_summary)
            ],
        }

    flagged = signals.get("probe-chain", False) if live else any(signals.values())

    return {"flagged": flagged, "signals": signals, "live": live}


def compute_results() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for probe in PROBES:
        verdict = evaluate_probe(probe)
        rows.append(
            {
                "probe_id": probe.probe_id,
                "family": probe.family,
                "title": probe.title,
                "attack_technique": probe.attack_technique,
                "expected_outcome": probe.expected_outcome,
                "boundary_rationale": probe.boundary_rationale,
                "engines_used": probe.engines_used,
                "latch_flagged": verdict["flagged"],
                "latch_signals": verdict["signals"],
                "live": verdict["live"],
            }
        )

    caught_rows = [row for row in rows if row["expected_outcome"] == "CAUGHT"]
    boundary_rows = [
        row for row in rows if row["expected_outcome"] == "IRREDUCIBLE_BOUNDARY"
    ]
    detected = sum(1 for row in caught_rows if row["latch_flagged"])
    boundaries_unflagged = sum(1 for row in boundary_rows if not row["latch_flagged"])

    families: list[dict[str, Any]] = []
    for family in sorted({row["family"] for row in rows}):
        members = [row for row in rows if row["family"] == family]
        families.append(
            {
                "family": family,
                "probes": len(members),
                "caught": sum(
                    1
                    for row in members
                    if row["expected_outcome"] == "CAUGHT" and row["latch_flagged"]
                ),
                "caught_total": sum(
                    1 for row in members if row["expected_outcome"] == "CAUGHT"
                ),
                "boundaries": sum(
                    1
                    for row in members
                    if row["expected_outcome"] == "IRREDUCIBLE_BOUNDARY"
                ),
            }
        )

    return {
        "probe_count": len(rows),
        "caught_probe_count": len(caught_rows),
        "boundary_probe_count": len(boundary_rows),
        "hardened_detected": detected,
        "hardened_detection_rate": round(detected / len(caught_rows), 4),
        "boundaries_documented": len(boundary_rows),
        "boundaries_unflagged": boundaries_unflagged,
        "overall_detection_rate": round(detected / len(rows), 4),
        "families": families,
        "probes": rows,
    }


def _signals_text(row: dict[str, Any]) -> str:
    fired = [engine for engine, hit in sorted(row["latch_signals"].items()) if hit]
    return ", ".join(fired) if fired else "—"


def render_report(results: dict[str, Any]) -> str:
    """Render ``EVASION_REPORT.md`` deterministically."""

    caught = results["hardened_detected"]
    caught_total = results["caught_probe_count"]
    boundaries = results["boundary_probe_count"]
    overall = results["overall_detection_rate"] * 100

    lines = [
        "# Latch adversarial self-red-team: evasion harness",
        "",
        "Latch red-teams itself. Each probe below is a deliberate attempt to slip",
        "past one of its own detectors -- new capability vocabulary, enum",
        "indirection, Unicode confusables and variation selectors, unfamiliar",
        "routing directives, header obfuscation, token passthrough under a new",
        "parameter name, and encoded or multi-hop exfiltration. Probes are",
        "deterministic payloads, not fuzzing: the same 24 always run, and every",
        "verdict is recomputable offline.",
        "",
        "| Metric | Result |",
        "| ------ | ------ |",
        f"| Total probes | {results['probe_count']} |",
        f"| Hardened detections (probes expected to be caught) |"
        f" {caught}/{caught_total} ({caught / caught_total * 100:.0f}%) |",
        f"| Irreducible static boundaries |"
        f" {boundaries} documented, {results['boundaries_unflagged']} left"
        " unflagged by design |",
        f"| Overall detection across the adversarial corpus |"
        f" {caught}/{results['probe_count']} ({overall:.1f}%) |",
        "",
        "The gap between those two numbers is the honest part: five probes are",
        "deliberately not caught, because the only static rules that would catch",
        "them also fire on legitimate tool registries. They are listed with their",
        "rationale below rather than quietly dropped from the corpus.",
        "",
        "## Per-family coverage",
        "",
        "| Family | Probes | Caught | Caught total | Irreducible boundaries |",
        "| ------ | ------ | ------ | ------------ | ---------------------- |",
    ]

    for family in results["families"]:
        lines.append(
            f"| `{family['family']}` | {family['probes']} | {family['caught']} |"
            f" {family['caught_total']} | {family['boundaries']} |"
        )

    lines.extend(
        [
            "",
            "## Hardened catches",
            "",
            "Every probe here was a real bypass before hardening and is caught by",
            "the shipped rules.",
            "",
            "| Probe | Family | Attack technique |",
            "| ----- | ------ | ---------------- |",
        ]
    )
    for row in results["probes"]:
        if row["expected_outcome"] != "CAUGHT":
            continue
        lines.append(
            f"| `{row['probe_id']}` | `{row['family']}` | {row['attack_technique']} |"
        )

    lines.extend(
        [
            "",
            "## Irreducible static boundaries",
            "",
            "These five probes are *not* flagged. Each entry states the technique,",
            "the rule that would be needed to catch it, and why that rule would",
            "cost more precision than the detection is worth.",
            "",
        ]
    )

    for row in results["probes"]:
        if row["expected_outcome"] != "IRREDUCIBLE_BOUNDARY":
            continue
        lines.extend(
            [
                f"### `{row['probe_id']}` — {row['title']}",
                "",
                f"**Technique.** {row['attack_technique']}",
                "",
                f"**Why Latch stays silent.** {row['boundary_rationale']}",
                "",
            ]
        )

    lines.extend(
        [
            "## Per-probe results",
            "",
            "| Probe | Family | Expected | Latch | Fired | Engines |",
            "| ----- | ------ | -------- | ----- | ----- | ------- |",
        ]
    )
    for row in results["probes"]:
        verdict = "detected" if row["latch_flagged"] else "clean"
        lines.append(
            f"| `{row['probe_id']}` | `{row['family']}` | {row['expected_outcome']} |"
            f" {verdict} | {_signals_text(row)} |"
            f" {', '.join(row['engines_used'])} |"
        )

    lines.extend(
        [
            "",
            "## How to read this corpus",
            "",
            "- **CAUGHT** requires the probe's own target engine to fire; a catch",
            "  from an unrelated engine would not count.",
            "- **IRREDUCIBLE_BOUNDARY** requires silence. If Latch starts flagging",
            "  one of these, the corpus fails: that would mean a noisy heuristic",
            "  shipped, and the benchmark and CVE suites would show the false",
            "  positives.",
            "- **Runtime probes are execution-aware.** `probe-chain` must confirm",
            "  the canary at the loopback sink; a base64 body, a GET query string",
            "  and a four-server hop are all verified by capturing the token, not",
            "  by trusting the tool's own output.",
            "- **No timestamps, no randomness in artifacts.** Live probes store",
            "  verdict fields only (status, counts, sink summary), never the",
            "  random `LATCH-CANARY-...` token, so this report is reproducible",
            "  byte for byte.",
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
    print("Adversarial self-red-team")
    print(
        f"  Hardened detections: {results['hardened_detected']}"
        f"/{results['caught_probe_count']}"
        f" ({results['hardened_detection_rate'] * 100:.1f}%)"
    )
    print(
        f"  Irreducible boundaries: {results['boundary_probe_count']}"
        f" ({results['boundaries_unflagged']} left unflagged by design)"
    )
    print(
        f"  Overall detection: {results['hardened_detected']}"
        f"/{results['probe_count']}"
        f" ({results['overall_detection_rate'] * 100:.1f}%)"
    )
    for family in results["families"]:
        print(
            f"  {family['family']:30}"
            f" caught {family['caught']}/{family['caught_total']}"
            f" boundaries {family['boundaries']}"
        )
    print(f"Wrote {RESULTS_JSON}")
    print(f"Wrote {REPORT_MD}")


def main() -> int:
    results = compute_results()
    write_results(results)
    print_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
