# Holdout: a disjoint 100-package sample under frozen rules

The numbers in `FIELD_STUDY_REPORT.md` are **in-sample**. The detectors were
narrowed by hand triage of those same 31 captures, so going from 11 flagged
surfaces to 3 measures a regression suite, not generalization. This directory is
the out-of-sample measurement a reviewer should quote: a second registry pull
that shares no package with the first, scored with the rules frozen.

## Method

- **Split.** `python -m field_study.discover_targets --npm-limit 70
  --pypi-limit 30 --output field_study/holdout/targets.json --exclude-targets
  field_study/round1/targets.json` was run on 2026-11-24. Exclusions are
  explicit and audited: only the `package_eval` pins and the round-1 list,
  both named on the command line and recorded with their sha256 in
  `field_study/holdout/targets.split.json`. Overlap between the two samples:
  **0 of 100**. The second pull is the continuation of the same two registry
  queries (`mcp-server` search for npm, the `*mcp-server*` name set for PyPI),
  so it is the tail of that ranking rather than an independent random draw of
  the ecosystem.
- **Rounds.** Round 1 is `field_study/round1/targets.json` (sha256
  `f58d630a02879547861914711418a8de14f1859418d43eda71fe8fea0e8fc739`, unchanged
  when the file was moved under `round1/`); the holdout is
  `field_study/holdout/targets.json`. Each has a `*.split.json` beside it
  recording the exclusion sources, their sha256, the excluded-name count, the
  discovered count and the (empty) overlap. Round-1's other artifacts — the
  captures, `scan_results.json` and both reports — remain at the
  `field_study/` root, because `run_field_study` defaults to them.
- **Freeze.** Detector fingerprint
  `d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4` — identical
  to the post-hardening run. No rule, vocabulary entry or threshold was touched
  between the two samples.
- **Harvest.** Same harness, same isolation: a disposable `python:3.12-slim`
  container (node `20.19.2`, npm `9.2.0`, uv) with a `--memory=3g --cpus=2`
  limit, a scratch `HOME`/npm/uv cache per run, only `PATH` inherited, and a
  15-second timeout per package. No credentials were supplied.
- **Analyze.** Offline, from the recorded `tools/list` captures:
  `python -m field_study.run_field_study --analyze --captures
  field_study/holdout/captures --targets field_study/holdout/targets.json
  --output-dir field_study/holdout`.

## Result

| Metric | Value |
| ------ | ----- |
| Packages pulled | 100 (`70` npm, `30` PyPI) |
| Overlap with round 1 | 0 |
| `harvested` | 18 |
| `missing_required_env` | 13 |
| `startup_error` | 46 |
| `timeout` | 23 |
| Surface tools analyzed | 112 |
| Flagged surfaces | **0** |
| Findings | **0** |
| **False positives / analyzed surfaces** | **0 / 18** |

Every one of the 18 harvested surfaces is clean under the frozen rules, so the
out-of-sample false-positive count is **zero**. No triage was required: there was
nothing to triage.

**Read it as a bound, not a proof.** Eighteen surfaces is a small denominator.
With `0` failures in `18` trials, the rule of three puts the 95% upper bound on
the per-server false-positive rate at about `17%` (`3/18`). The holdout rules out
the pre-fix behaviour — where most SaaS surfaces in round 1 flagged — but it
cannot certify a rate near zero.

## Cross-server compositions on the holdout

| Metric | Value |
| ------ | ----- |
| Compositions | 207 |
| Flagged compositions | 37 |
| `LETHAL_TRIFECTA` paths | 1,401 (675 cross-server) |
| `shadow` findings | 21 |
| `auth-audit` findings | 0 |

Three of the 37 flagged sets are `EXACT_TOOL_SHADOW` and 13 are
`CROSS_TOOL_HIJACK`, both of which are structurally impossible in the
single-server pass. `auth-audit` is again unexercised: the corpus is stdio
manifests with no HTTP/OAuth transport, so its zero is an untested engine.

## Scope of what this shows

- **Shown:** the hardened rules produce no findings on a fresh, disjoint sample
  of ordinary npm/PyPI MCP servers, so the round-1 improvement is not just the
  triage set memorized.
- **Not shown:** recall. None of the 18 surfaces is a known hostile package, so
  this sample has no positives to catch; it measures the false-positive side
  only. The yield is also lower than round 1 (`18%` vs `31%`), and the analyzed
  surfaces are small (median `3` tools, largest `32`), so the harder SaaS
  surfaces that drove round 1's findings are under-represented.
- **Still untested:** runtime behaviour (responses and handlers), `auth-audit`
  on remote HTTP/OAuth servers, and any target that needs credentials. See the
  Limitations section of `FIELD_STUDY_REPORT.md` for the boundary this study
  does not cross.

## Artifacts

- `field_study/round1/targets.json` — the round-1 100 pinned packages
  (sha256 `f58d630a02879547861914711418a8de14f1859418d43eda71fe8fea0e8fc739`).
- `field_study/round1/targets.split.json` — round-1 exclusion audit (only the
  `package_eval` pins; no earlier round existed).
- `field_study/holdout/targets.json` — the 100 pinned packages.
- `field_study/holdout/targets.split.json` — holdout exclusion audit:
  `package_eval` pins plus round 1, 0 overlapping packages.
- `field_study/holdout/captures/*.json` — recorded `tools/list` surfaces.
- `field_study/holdout/scan_results.json` — full findings and aggregates.
- `field_study/holdout/FIELD_STUDY_REPORT.md` — the same renderer applied to
  this sample.
