# Third sample: placeholder credentials (separate sample)

The holdout's `0/18` is a clean bound only for surfaces that start without
credentials. Thirteen packages in that sample exited asking for a token or URL
and never listed tools, so the credentialed SaaS servers behind round 1's noise
stayed under-represented. This file keeps two different questions apart:

- **The lever.** Do fixed dummy credentials raise the number of servers that
  list tools? That is measured **in-sample**, on the same 100 holdout targets,
  in `field_study/holdout_placeholder/PAIRED.md`. The paired table is the only
  evidence for the lever.
- **This sample.** A fresh 100-package pull harvested with placeholders, used to
  see what a credentialed surface looks like to the hardened rules. It is a
  separate third sample from the next slice of the same registry queries, and it
  is **not** evidence for the lever: different packages, one arm.

An earlier version of this file compared this pull's yield against the holdout's
and reported `+6` harvested surfaces. That comparison mixed two different
100-package draws, so it measured package difficulty as much as the credential.
It is superseded by the paired table below.

## The lever, measured in-sample

Same 100 holdout targets (`field_study/holdout/targets.json`), harvested twice:
once with no credentials (`field_study/holdout/captures`, the original run) and
once with `run_field_study.PLACEHOLDER_CREDENTIAL_ENV`
(`field_study/holdout_placeholder/captures`). Same `python3.12`/`node22`
container, same memory and CPU limits, same 15-second timeout, same scratch
`HOME`/npm/uv caches, only `PATH` inherited, and the frozen detector fingerprint
`d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4`. Reproduce
with:

```
python -m field_study.paired_placeholder
```

| Status | none | placeholder |
| ------ | ---- | ----------- |
| `harvested` | 18 | **16** |
| `missing_required_env` | 13 | 9 |
| `timeout` | 23 | 28 |
| `startup_error` | 46 | 47 |

Transitions (none → placeholder):

| Transition | Packages |
| ---------- | -------- |
| `harvested` → `harvested` | 11 |
| `missing_required_env` → `harvested` | 2 |
| `timeout` → `harvested` | 2 |
| `startup_error` → `harvested` | 1 |
| `harvested` → `timeout` | 6 |
| `harvested` → `startup_error` | 1 |
| `missing_required_env` → `missing_required_env` | 8 |
| `missing_required_env` → `timeout` | 3 |
| `timeout` → `timeout` | 15 |
| `timeout` → `startup_error` | 5 |
| `timeout` → `missing_required_env` | 1 |
| `startup_error` → `startup_error` | 41 |
| `startup_error` → `timeout` | 4 |

**Newly harvested: 5.** `npm-contextstream-mcp-server-1-0-99` (2 tools) and
`npm-dbx-app-mcp-server-0-4-145` (3 tools) are small; the other three are the
credentialed SaaS class the holdout could not reach: `npm-replicate-mcp-0-9-0`
(35 tools), `npm-thirdstrandstudio-mcp-figma-0-7-0` (31) and
`npm-zereight-mcp-gitlab-3-0-0` (40).

**Newly lost: 7.** `npm-knip-mcp-0-0-39`, `npm-langsmith-mcp-server-0-1-7`,
`npm-mcp-searxng-2-12-0`, `npm-openbnb-mcp-server-airbnb-0-3-0`,
`npm-tacitai-mcp-server-0-15-1` and `npm-vizejs-musea-mcp-server-0-793-0` now
time out; `npm-transcend-io-mcp-server-docs-0-6-1` now exits with a startup
error. All seven listed tools without credentials.

**Net yield change: −2.** On this list the lever is a swap, not a gain: five
packages that never listed tools now do, seven that did no longer finish. A
dummy token that passes a presence check can push a server into a network call
that does not return inside 15 seconds, so part of the loss may be the
credential rather than the harness. One run per arm cannot separate that from
transient install or network state, and the seven were not retried.

**Findings from newly harvested packages only: 95**, all `LETHAL_TRIFECTA`
(10 `CRITICAL`, 85 `HIGH`), from three of the five: `gitlab` 80, `figma` 11,
`replicate` 4. The two small surfaces produced none. These are target-level
paths on surfaces that only existed under placeholder credentials; they are not
compositions and were not hand-triaged here.

## Yield of this sample (separate pull)

This is the third sample, not the lever. It was discovered on 2026-11-26 with
`python -m field_study.discover_targets --npm-limit 70 --pypi-limit 30
--output field_study/placeholder/targets.json --exclude-targets
field_study/round1/targets.json --exclude-targets
field_study/holdout/targets.json`: 100 targets (`70` npm, `30` PyPI), **0** in
common with either earlier round. The split record is
`field_study/placeholder/targets.split.json` (three exclusion sources, 211
excluded names, empty overlap). Harvest used the same container, limits, timeout
and frozen fingerprint as the paired arms; the one difference is
`--placeholder-credentials`.

| Metric | This sample |
| ------ | ----------- |
| Packages | 100 |
| `harvested` | 24 |
| `missing_required_env` | 8 |
| `startup_error` | 37 |
| `timeout` | 31 |
| Analyzed surfaces | 24 |
| Flagged surfaces | 3 |
| Findings | 199 |

Because these are different packages from the holdout, this table is not
comparable row-by-row with the paired arms above. It describes one credentialed
pull; it does not measure the credential's effect.

## Result

Three of the 24 analyzed surfaces flag:

| Target | Tools | Findings | Rule | Read |
| ------ | ----- | -------- | ---- | ---- |
| `npm-loopctl-mcp-server-3-47-0` | 298 | 197 | `LETHAL_TRIFECTA` | `true_positive_informational` class |
| `npm-godot-mcp-server-0-6-1` | 71 | 1 | `UNICODE_VARIATION_SELECTOR` | spec-level finding |
| `pypi-aimemory-mcp-server-1-7-0` | 13 | 1 | `UNICODE_VARIATION_SELECTOR` | spec-level finding |

`loopctl-mcp-server@3.47.0` is a large credentialed SaaS surface:
298 tools, 22 ingest tools, 17 private-data readers (`api_key_list`,
`chg_ledger_summary`, …) and nine egress tools, including `webhook_create` with
a caller-supplied `url` and `knowledge_ingest` with a caller-supplied URL to
fetch. The 197 paths are that product's own capability, not a detector bug — the
same `true_positive_informational` class as `@doitintl/doit-mcp-server` in round
1. It is **not** hand-triaged composition by composition; the target-level read
is stated so the number is not left unexplained.

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

- **Shown:** the hardened rules are **not** quiet on large credentialed SaaS
  surfaces. `loopctl` produced 197 paths with caller-URL webhook sinks in this
  sample, and the paired run's five newly harvested surfaces produced 95 more
  `LETHAL_TRIFECTA` paths across three packages. Anyone quoting `0/18` as a
  per-server rate should read these first.
- **Shown about the lever:** placeholder credentials change which servers list
  tools, but on the holdout list the net was `-2` harvested: five gained, seven
  lost to timeouts and one startup error. There is no yield gain to cite from
  this list, and the earlier cross-pull `+6` comparison is withdrawn.
- **Not shown:** authenticated behaviour. A placeholder is not a credential: a
  server that validates its token still never lists tools, so the analyzed
  surfaces are still biased toward servers with weak or absent startup checks.
- **Not shown:** recall. No target here is a known hostile package. This sample
  measures yield and the false-positive side of a harder surface class, nothing
  more.
- **Not shown:** any rate. 24 surfaces is a small denominator, and the sample is
  the next slice of the same two registry queries, not a random draw of the
  ecosystem.
- **Does not revise `0/18`.** The holdout remains the clean bound for small,
  credential-free surfaces. This is a separate sample with a different
  intervention, reported separately.

## Artifacts

Paired measurement (the lever):

- `field_study/holdout_placeholder/captures/*.json` — the holdout list
  re-harvested with placeholders, each recording `credential_mode:
  "placeholder"`.
- `field_study/holdout_placeholder/paired.json` — per-package statuses,
  transitions and the newly harvested findings.
- `field_study/holdout_placeholder/PAIRED.md` — the same as a report.
- `field_study/holdout_placeholder/harvest.log` — the run's output.

Separate third sample:

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
