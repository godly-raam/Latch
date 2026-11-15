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
    assert len(CASES) == 36
    assert len(HOSTILE_CASES) == 18
    assert len(BENIGN_CASES) == 18
    assert len({case.case_id for case in CASES}) == 36
    assert len({case.case_id for case in HOSTILE_CASES}) == 18
    assert len({case.case_id for case in BENIGN_CASES}) == 18
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

    assert latch["tp"] == 18
    assert latch["fp"] == 0
    assert latch["tn"] == 18
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
        "benign_directive_words_without_cross_tool",
        "benign_env_placeholder_bearer",
        "benign_dedicated_oauth_broker",
        "benign_loopback_http_dev",
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
        "shadow_exact_trusted_collision",
        "shadow_cyrillic_homoglyph",
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
    assert "| **Latch** | 18 | 0 | 18 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |" in text
    assert "| Naive keyword/substring baseline | 11 | 12 | 6 | 7 | 0.48 | 0.61 | 0.54 | 0.67 |" in text
    assert "36 cases" in text


def test_benchmark_is_reproducible() -> None:
    assert compute_results() == compute_results()


def test_v2_cases_route_through_their_engines() -> None:
    by_id = {case.case_id: case for case in CASES}

    assert latch_verdict(by_id["shadow_cyrillic_homoglyph"])["signals"] == {
        "shadow": True
    }
    assert latch_verdict(by_id["auth_token_passthrough_param"])["signals"] == {
        "auth": True
    }
    assert latch_verdict(by_id["benign_trusted_mirror_servers"])["signals"] == {
        "shadow": False
    }
    assert latch_verdict(by_id["benign_loopback_http_dev"])["signals"] == {
        "auth": False
    }


def test_v2_findings_carry_their_expected_severity() -> None:
    from mcpprobe.shadow import analyze_shadowing
    from mcpprobe.models import ToolDefinition
    from benchmark.run_benchmark import _auth_inputs
    from mcpprobe.oauth_audit import run_auth_audit

    shadow_case = next(c for c in CASES if c.case_id == "shadow_exact_trusted_collision")
    parsed = {
        server_id: [ToolDefinition.model_validate(tool) for tool in tools]
        for server_id, tools in (shadow_case.shadow or {}).items()
    }
    shadow_report = analyze_shadowing(
        parsed, trusted_servers=set(shadow_case.trusted_servers)
    )
    assert [(f.rule_id, f.severity) for f in shadow_report.findings] == [
        ("EXACT_TOOL_SHADOW", "CRITICAL")
    ]

    reuse_case = next(c for c in CASES if c.case_id == "auth_cross_server_token_reuse")
    specs, manifests = _auth_inputs(reuse_case.auth or [])
    auth_report = run_auth_audit(specs, manifests)
    assert ("CROSS_SERVER_CREDENTIAL_REUSE", "CRITICAL") in [
        (f.rule_id, f.severity) for f in auth_report.findings
    ]
    assert "[sha256:" in (auth_report.findings[0].evidence or "")


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
