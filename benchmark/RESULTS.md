# Latch benchmark results

Deterministic ground-truth evaluation of Latch against a naive
keyword/substring scanner over 24 cases: 12 hostile/vulnerable cases
(expected positive) and 12 benign hard lookalikes built to punish keyword
matching. There are no timestamps or random values, so re-running
`python -m benchmark.run_benchmark` reproduces this file byte for byte.

- Tool version: `0.1.0`
- Cases: 24 (12 hostile, 12 benign)

## Summary

| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |
| Naive keyword/substring baseline | 7 | 8 | 4 | 5 | 0.47 | 0.58 | 0.52 | 0.67 |
| **Latch** | 12 | 0 | 12 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |

Precision = TP / (TP + FP); Recall = TP / (TP + FN);
F1 = harmonic mean of precision and recall;
FPR = FP / (FP + TN).

## Per-case results

| Case | Expectation | Latch | Naive | Title |
| ---- | ----------- | ----- | ----- | ----- |
| `h01-description-rug-pull` | hostile | detected | detected | Post-approval description rug pull exfiltrating ~/.ssh/id_rsa |
| `h02-annotation-flip` | hostile | detected | clean | Silent readOnlyHint/destructiveHint flip |
| `h03-hidden-parameter` | hostile | detected | clean | Hidden bcc parameter injected into send_email |
| `h04-tag-block-description` | hostile | detected | clean | Unicode tag-block prompt injection in tool description |
| `h05-tag-block-nested-schema` | hostile | detected | clean | Unicode tag-block instruction nested in a schema description |
| `h06-bidi-override` | hostile | detected | clean | BiDi override spoofing description text |
| `h07-privileged-header` | hostile | detected | detected | x-mcp-header bound to Authorization |
| `h08-spoofed-forwarded-for` | hostile | detected | detected | x-mcp-header bound to X-Forwarded-For |
| `h09-crlf-header` | hostile | detected | detected | CRLF injection in x-mcp-header value |
| `h10-cross-server-trifecta` | hostile | detected | detected | Cross-server lethal trifecta github -> postgres -> slack |
| `h11-fintech-trifecta` | hostile | detected | detected | Fintech trifecta gmail -> wallet -> webhook |
| `h12-single-server-chain` | hostile | detected | detected | Single-server read+exfil chain |
| `b01-asset-manager` | benign | clean | clean | asset_manager: local asset tagging |
| `b02-passhash-verifier` | benign | clean | detected | passhash_verifier: local password hash check |
| `b03-tokenizer-stats` | benign | clean | detected | tokenizer_stats: string token counting |
| `b04-secret-santa` | benign | clean | detected | secret_santa_matcher: local event pairing |
| `b05-webhook-signature-validator` | benign | clean | detected | webhook_signature_validator: local HMAC validation |
| `b06-curl-syntax-linter` | benign | clean | detected | curl_syntax_linter: offline command linter |
| `b07-sql-query-formatter` | benign | clean | detected | sql_query_formatter: offline SQL formatting |
| `b08-correlation-header` | benign | clean | detected | Legit x-mcp-header X-Correlation-ID on a string parameter |
| `b09-json-reorder` | benign | clean | clean | Benign JSON key reordering and whitespace against a pin |
| `b10-math-and-markdown` | benign | clean | clean | calc:add_numbers + fmt:render_table |
| `b11-docs-and-units` | benign | clean | clean | docs:search_public_api + units:convert_currency |
| `b12-trusted-egress` | benign | clean | detected | Egress server explicitly trusted (internal-audit-sink) |

## Where the baseline breaks

- Hostile cases the baseline misses (5): `h02-annotation-flip`, `h03-hidden-parameter`, `h04-tag-block-description`, `h05-tag-block-nested-schema`, `h06-bidi-override`
- Benign cases the baseline flags (8): `b02-passhash-verifier`, `b03-tokenizer-stats`, `b04-secret-santa`, `b05-webhook-signature-validator`, `b06-curl-syntax-linter`, `b07-sql-query-formatter`, `b08-correlation-header`, `b12-trusted-egress`
- Latch misses 0 hostile cases and flags 0 benign cases, because it hashes canonical tool definitions, tokenizes identifiers, allowlists header bindings and analyzes cross-server capability chains.
