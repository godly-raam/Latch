# Third sample: placeholder credentials

The holdout's `0/18` is a clean bound only for surfaces that start without
credentials. Thirteen packages in that sample exited asking for a token or URL
and never listed tools, so the credentialed SaaS servers behind round 1's noise
stayed under-represented. This sample is the yield lever for that class: a fresh
100-package pull, harvested with **fixed dummy credential values** so that
presence-only checks pass. No real secret is used, and `0/18` is not revised by
anything here.

## Method

- **Sample.** `python -m field_study.discover_targets --npm-limit 70
  --pypi-limit 30 --output field_study/placeholder/targets.json
  --exclude-targets field_study/round1/targets.json
  --exclude-targets field_study/holdout/targets.json`, run on 2026-11-26.
  100 targets (`70` npm, `30` PyPI), **0** in common with either earlier round.
  The split record is `field_study/placeholder/targets.split.json`: three
  exclusion sources (the `package_eval` pins plus both earlier rounds), 211
  excluded names, empty overlap.
- **Freeze.** Detector fingerprint
  `d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4`, the same
  one the holdout used. No rule, vocabulary entry or threshold was touched.
- **Harvest.** Same disposable `python3.12`/`node22` container, same scratch
  `HOME`/npm/uv caches, only `PATH` inherited, 15-second timeout per package.
  The one difference is `--placeholder-credentials`: the child environment gets
  the fixed values in `run_field_study.PLACEHOLDER_CREDENTIAL_ENV`
  (`GITHUB_TOKEN`, `SLACK_BOT_TOKEN`, `DATABASE_URL`, `OPENAI_API_KEY`, … all
  `latch-placeholder-…` or an unusable loopback URL). Host variables are still
  never copied, and the capture records `credential_mode: "placeholder"`; the
  report's header states the mode.
- **Analyze.** Offline, from the captures:
  `python -m field_study.run_field_study --analyze --captures
  field_study/placeholder/captures --targets field_study/placeholder/targets.json
  --output-dir field_study/placeholder`.

## Yield against the holdout

| Metric | Holdout (no credentials) | Placeholder credentials |
| ------ | ------------------------ | ----------------------- |
| Packages | 100 | 100 |
| `harvested` | 18 | **24** |
| `missing_required_env` | 13 | **8** |
| `startup_error` | 46 | 37 |
| `timeout` | 23 | 31 |
| Analyzed surfaces | 18 | 24 |
| Flagged surfaces | 0 | **3** |
| Findings | 0 | **199** |

The lever works, but only partly: on a fresh 100-package pull the
`missing_required_env` count falls from `13` to `8` and yield rises from `18%`
to `24%`. The eight that still exit are the ones where a placeholder is not
enough: the server validates the token against its service or needs a real
resource URL. (These are different packages, so the comparison is between two
pulls of the same budget, not the same 100 targets.)
Timeouts rise (`23` → `31`): a token that passes a presence check often sends
the server into a network call that does not finish in 15 seconds.

## Result

Three of the 24 analyzed surfaces flag:

| Target | Tools | Findings | Rule | Read |
| ------ | ----- | -------- | ---- | ---- |
| `npm-loopctl-mcp-server-3-47-0` | 298 | 197 | `LETHAL_TRIFECTA` | `true_positive_informational` class |
| `npm-godot-mcp-server-0-6-1` | 71 | 1 | `UNICODE_VARIATION_SELECTOR` | spec-level finding |
| `pypi-aimemory-mcp-server-1-7-0` | 13 | 1 | `UNICODE_VARIATION_SELECTOR` | spec-level finding |

`loopctl-mcp-server@3.47.0` is the large credentialed SaaS surface the holdout
could not reach:
298 tools, 22 ingest tools, 17 private-data readers (`api_key_list`,
`chg_ledger_summary`, …) and nine egress tools, including `webhook_create` with
a caller-supplied `url` and `knowledge_ingest` with a caller-supplied URL to
fetch. The 197 paths are that product's own capability, not a detector bug —
the same `true_positive_informational` class as `@doitintl/doit-mcp-server` in
round 1. It is **not** hand-triaged composition by composition; the target-level
read is stated above so the number is not left unexplained.

The two `UNICODE_VARIATION_SELECTOR` findings are manifest-level: a tool name
carries an invisible variation selector, so the rendered name need not be the
bytes the model reads (`call_method` in the godot server, `clear_all_memories`
in the memory server). Both are HIGH and neither needs credentials.

Credentialed SaaS is not uniformly noisy: `npm-tavily-mcp-0-2-22`,
`npm-bugsnag-mcp-server-1-1-0` and `npm-openapi-mcp-server-2-1-0` listed tools
under placeholder credentials and produced no findings.

## Composition sweep on this sample

**Unvalidated stress test on arbitrary server pairs — not findings,** exactly as
in the other two rounds. 24 harvested surfaces give **348** compositions, of
which **53** flag: `7,820` `LETHAL_TRIFECTA` paths (`4,927` cross-server), `41`
`shadow` findings, and `auth-audit` at `0` (still no HTTP/OAuth transport).
Of the 53, the fixed-seed triage record does not cover this round, so **53 of 53
are untriaged**; the report says so instead of implying a review.

## What this shows, and what it does not

- **Shown:** placeholder credentials are a real yield lever for presence-only
  checks (`+6` harvested surfaces, `-5` missing-env exits on the same 100-package
  budget), and the hardened rules are **not** quiet on a large credentialed SaaS
  surface: one 298-tool product produced 197 paths with caller-URL webhook
  sinks. Anyone quoting `0/18` as a per-server rate should read this first.
- **Not shown:** recall. No target here is a known hostile package. This sample
  measures yield and the false-positive side of a harder surface class, nothing
  more.
- **Not shown:** authenticated behaviour. A placeholder is not a credential: a
  server that validates its token still never lists tools, so the 24 analyzed
  surfaces are still biased toward servers with weak or absent startup checks.
- **Not shown:** any rate. 24 surfaces is a small denominator, and the sample is
  the next slice of the same two registry queries, not a random draw of the
  ecosystem.
- **Does not revise `0/18`.** The holdout remains the clean bound for small,
  credential-free surfaces. This is a separate sample with a different
  intervention, reported separately.

## Artifacts

- `field_study/placeholder/targets.json` — the 100 pinned packages.
- `field_study/placeholder/targets.split.json` — exclusion audit (pins plus both
  earlier rounds, 0 overlapping packages).
- `field_study/placeholder/captures/*.json` — recorded surfaces, each with
  `credential_mode: "placeholder"`.
- `field_study/placeholder/scan_results.json` — full findings and aggregates.
- `field_study/placeholder/FIELD_STUDY_REPORT.md` — the same renderer applied to
  this sample; its header states the credential mode and its reproduction block
  shows the placeholder harvest command.
- `field_study/placeholder/DISCLOSURE_LOG.md` — per-target inventory for this
  sample.
