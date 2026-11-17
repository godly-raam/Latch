# External black-box red-team: status

> **TEMPLATE VALIDATION ONLY — this is not a red-team result.**
> The probes below are the two illustrative examples shipped in
> [`external_probes_template.json`](external_probes_template.json),
> run only to prove the schema and scorer work. No independent
> contributor has submitted a probe set yet, so this file makes no
> claim about detection quality.

## Method

`python -m adversarial.run_external_blind --input <path>` validates
the submission against the documented schema, then runs
`audit_manifest`, `analyze_capability_graph`, `analyze_shadowing`,
`run_auth_audit` and the lockfile verifier on each probe. A probe
counts as detected when any engine fires on it.

## Metrics

| TP | FP | TN | FN | Precision | Recall | FPR |
| -- | -- | -- | -- | --------- | ------ | --- |
| 1 | 0 | 1 | 0 | 1.00 | 1.00 | 0.00 |

- Probes: 2 (1 hostile, 1 benign)
- Caught: `template_unicode_tag_block`
- Missed: none
- Benign probes wrongly flagged: none
- Probe errors: none

## Per-probe results

| Probe | Surface | Expected | Verdict | Rules | Author description |
| ----- | ------- | -------- | ------- | ----- | ------------------ |
| `template_unicode_tag_block` | `audit` | positive | detected | audit:UNICODE_TAG_BLOCK | Invisible Unicode Tag-block characters encode an instruction inside an otherwise ordinary tool description. |
| `template_benign_echo` | `audit` | negative | clean | — | An ordinary echo tool with a plain description must stay clean: a benign control for the same engine. |

## How to submit a real probe set

Read [`EXTERNAL_REDTEAM_BRIEF.md`](EXTERNAL_REDTEAM_BRIEF.md), write
ten probes (7-8 hostile, 2-3 benign controls) in the documented JSON
shape, and run
`python -m adversarial.run_external_blind --input <your-file>`.
Do not read `mcpprobe/` source or the shipped keyword/regex tables
first: the point is an unbiased attempt.

Self-authored corpora in this repository (Wave 1 and Wave 2) are
upper bounds, not independent measurements. See
[`WAVE2_BLIND_REPORT.md`](WAVE2_BLIND_REPORT.md).
