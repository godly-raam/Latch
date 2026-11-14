"""Tests for the ground-truth benchmark suite."""

from __future__ import annotations

import json

from benchmark.corpus import BENIGN_CASES, CASES, HOSTILE_CASES
from benchmark.naive_baseline import naive_flags, scan_text
from benchmark.run_benchmark import (
    RESULTS_JSON,
    RESULTS_MD,
    compute_results,
    latch_verdict,
    render_markdown,
)
from mcpprobe.graph import analyze_capability_graph, classify_tool
from mcpprobe.models import ToolDefinition


def test_corpus_shape() -> None:
    assert len(CASES) == 24
    assert len(HOSTILE_CASES) == 12
    assert len(BENIGN_CASES) == 12
    assert len({case.case_id for case in CASES}) == 24
    for case in HOSTILE_CASES:
        assert case.expectation == "hostile"
        assert case.expected_positive is True
    for case in BENIGN_CASES:
        assert case.expectation == "benign"
        assert case.expected_positive is False


def test_latch_matches_ground_truth_on_every_case() -> None:
    mismatches = [
        case.case_id
        for case in CASES
        if latch_verdict(case)["flagged"] is not case.expected_positive
    ]

    assert mismatches == []


def test_latch_metrics_are_perfect() -> None:
    results = compute_results()
    latch = results["latch"]

    assert latch["tp"] == 12
    assert latch["fp"] == 0
    assert latch["tn"] == 12
    assert latch["fn"] == 0
    assert latch["precision"] == 1.0
    assert latch["recall"] == 1.0
    assert latch["f1"] == 1.0
    assert latch["fpr"] == 0.0


def test_naive_baseline_is_measurably_worse() -> None:
    results = compute_results()
    naive = results["naive"]
    latch = results["latch"]

    assert naive["fp"] > 0
    assert naive["fn"] > 0
    assert naive["fpr"] > latch["fpr"]
    assert naive["recall"] < latch["recall"]
    assert naive["precision"] < latch["precision"]


def test_naive_baseline_false_positives_are_the_expected_lookalikes() -> None:
    by_id = {case.case_id: case for case in CASES}

    for case_id in (
        "b02-passhash-verifier",
        "b03-tokenizer-stats",
        "b04-secret-santa",
        "b05-webhook-signature-validator",
        "b06-curl-syntax-linter",
        "b07-sql-query-formatter",
        "b08-correlation-header",
        "b12-trusted-egress",
    ):
        assert naive_flags(by_id[case_id]) is True, case_id


def test_naive_baseline_misses_keyword_free_attacks() -> None:
    by_id = {case.case_id: case for case in CASES}

    for case_id in (
        "h02-annotation-flip",
        "h03-hidden-parameter",
        "h04-tag-block-description",
        "h05-tag-block-nested-schema",
        "h06-bidi-override",
    ):
        assert naive_flags(by_id[case_id]) is False, case_id


def test_naive_scanner_is_plain_substring_matching() -> None:
    assert scan_text("asset_manager") == []
    assert scan_text("passhash_verifier") == ["ssh", "pass"]
    assert scan_text("x-mcp-header") == ["x-mcp-header"]


def test_results_json_matches_recomputation() -> None:
    payload = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))

    assert payload == compute_results()
    assert "generated_at" not in payload


def test_results_markdown_matches_recomputation() -> None:
    assert RESULTS_MD.read_text(encoding="utf-8") == render_markdown(compute_results())


def test_results_markdown_contains_the_summary_table() -> None:
    text = RESULTS_MD.read_text(encoding="utf-8")

    assert "| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |" in text
    assert "| **Latch** | 12 | 0 | 12 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |" in text
    assert "| Naive keyword/substring baseline | 7 | 8 | 4 | 5 | 0.47 | 0.58 | 0.52 | 0.67 |" in text


def test_benchmark_is_reproducible() -> None:
    assert compute_results() == compute_results()


# -- graph refinements covered by the benchmark corpus ---------------------


def test_self_loop_chains_are_suppressed() -> None:
    servers = {
        "slack": [
            ToolDefinition.model_validate(
                {
                    "name": "post_message",
                    "description": "Post.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": False, "openWorldHint": True},
                }
            )
        ],
        "db": [
            ToolDefinition.model_validate(
                {
                    "name": "query_ledger",
                    "description": "Query.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                    },
                }
            )
        ],
    }

    report = analyze_capability_graph(servers)

    assert report.trifecta_paths == []
    assert report.passed is True


def test_ledger_tools_classify_as_private_reads() -> None:
    for name, parameter in (("read_ledger", "ledger"), ("get_ledger", "ledgers")):
        tool = ToolDefinition.model_validate(
            {
                "name": name,
                "description": "Read the ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {parameter: {"type": "string"}},
                },
            }
        )
        assert classify_tool("wallet", tool).capabilities == ["PRIVATE_DATA_READ"], name
