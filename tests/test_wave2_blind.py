"""Tests for the frozen Wave 2 pre-registered blind evaluation."""

from __future__ import annotations

import json
from pathlib import Path

from adversarial.run_wave2_blind import (
    BASELINE_JSON,
    REPORT_MD,
    _dump,
    compute_results,
    main,
    render_report,
)
from adversarial.wave2_blind import BLIND_PROBES

ROOT = Path(__file__).resolve().parents[1]


def test_corpus_shape() -> None:
    assert len(BLIND_PROBES) == 16
    ids = [probe.probe_id for probe in BLIND_PROBES]
    assert len(ids) == len(set(ids))
    assert sum(1 for probe in BLIND_PROBES if probe.expected_positive) == 12
    assert sum(1 for probe in BLIND_PROBES if not probe.expected_positive) == 4


def test_frozen_baseline_exists_and_matches_live_run() -> None:
    assert BASELINE_JSON.exists()
    frozen = json.loads(BASELINE_JSON.read_text(encoding="utf-8"))
    live = compute_results()

    assert frozen["wave"] == 2
    assert frozen["frozen"] is True
    assert frozen["metrics"] == live["metrics"]
    assert [row["probe_id"] for row in frozen["probes"]] == [
        row["probe_id"] for row in live["probes"]
    ]
    for before, after in zip(frozen["probes"], live["probes"], strict=True):
        assert before["latch_flagged"] == after["latch_flagged"]
        assert before["latch_signals"] == after["latch_signals"]
        assert before["live"] == after["live"]
    assert BASELINE_JSON.read_text(encoding="utf-8") == _dump(live)


def test_benign_controls_have_zero_false_positives() -> None:
    metrics = compute_results()["metrics"]
    assert metrics["benign_probe_count"] == 4
    assert metrics["false_positives"] == 0
    assert metrics["true_negatives"] == 4
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["benign_violations"] == []


def test_blind_catches_and_misses_are_both_recorded() -> None:
    results = compute_results()
    metrics = results["metrics"]

    assert metrics["blind_catches"], "expected at least one genuine blind catch"
    assert metrics["blind_misses"], "expected the blind misses to be reported"
    assert metrics["true_positives"] == len(metrics["blind_catches"])
    assert metrics["false_negatives"] == len(metrics["blind_misses"])
    assert (
        metrics["true_positives"] + metrics["false_negatives"]
        == metrics["hostile_probe_count"]
    )
    assert metrics["recall"] < 1.0

    # The honest miss list is pinned: a rule change would have to update this
    # test and the frozen baseline together, on purpose.
    assert metrics["blind_misses"] == [
        "w2_braille_blank_shadow",
        "w2_fullwidth_homoglyph_shadow",
        "w2_graph_compound_verb_ingest",
        "w2_graph_synonym_siphon",
        "w2_hangul_filler_shadow",
        "w2_passive_voice_hijack",
        "w2_stdio_cli_arg_secret",
    ]


def test_runner_verifies_instead_of_overwriting_the_baseline() -> None:
    before = BASELINE_JSON.read_bytes()
    before_report = REPORT_MD.read_bytes()

    assert main([]) == 0

    assert BASELINE_JSON.read_bytes() == before
    assert REPORT_MD.read_bytes() == before_report


def test_report_is_deterministic_and_honest() -> None:
    results = compute_results()
    report = REPORT_MD.read_text(encoding="utf-8")
    assert report == render_report(results)

    assert report.startswith(
        "# Wave 2: Author-Blind Upper Bound (Self-Authored, Frozen First Run)"
    )
    flat = " ".join(report.replace(">", " ").split())
    assert "Author-Blind Upper Bound" in flat
    assert "awaiting independent external 10-probe submission" in flat
    assert "EXTERNAL_REDTEAM_BRIEF.md" in report
    assert "## Blind catches" in report
    assert "## Blind misses" in report
    assert "## Benign hard negatives" in report
    assert "wave2_frozen_baseline.json" in report
    assert "--freeze-new-baseline" in report
    assert "post-tuning" in report
    for row in results["probes"]:
        assert f"`{row['probe_id']}`" in report
