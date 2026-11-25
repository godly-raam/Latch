# Field study: unseen npm & PyPI MCP servers

**Status: harvest + offline static scan; flagged surfaces await hand triage.**
Every number below comes from
`field_study/run_field_study.py --analyze` over recorded `tools/list`
captures; no package was executed during analysis. There are no
independent ground-truth labels: any verdict below is a self-assigned
hand triage whose criteria are stated in the worksheet.

- Detector fingerprint: `d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4`
- Credential mode: **placeholder** — every credential a harvested package received is a fixed dummy value (`latch-placeholder-…`); no real secret was used.
- Captured targets: **100**
- Analyzed surfaces: **24**
- Flagged surfaces: **3**
- Targets awaiting hand triage: **3**

## Harvester outcomes

| Status | Count | Meaning |
| ------ | ----- | ------- |
| `harvested` | 24 | `tools/list` returned with placeholder credentials. |
| `missing_required_env` | 8 | Exited asking for a token/key/URL; recorded, not retried with secrets. |
| `timeout` | 31 | Exceeded the per-package timeout. |
| `startup_error` | 37 | Install or startup failed for another reason. |

Presence-only checks pass under placeholder credentials, so this
share should fall. A package that still exits here validates the
credential against its service, which the study does not supply.

## Detector hardening (Week 2 hand triage → fix)

The Week-2 run flagged **11 of 31** analyzed surfaces with **21,249**
findings. Almost all of them were `LETHAL_TRIFECTA` paths produced by one
annotation rule: `openWorldHint=true` without `readOnlyHint` supplied both
`UNTRUSTED_INPUT` and `EXTERNAL_EGRESS` for every SaaS CRUD and analytics
tool, so an ingest × read × egress product exploded — one cost-analytics
server alone accounted for 20,664 paths. Hand triage separated eight
detector false positives from one genuine spec violation and one inherent
capability, then `mcpprobe/graph.py` was tightened and the same captures
were re-analyzed offline.

| Metric | Pre-fix | Post-fix |
| ------ | ------- | -------- |
| Detector fingerprint | `9f211077305c91b1026397f1402d170aed0297efc0efda872ab9256fc836ed4e` | `d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4` |
| Analyzed surfaces | 31 | 24 |
| Flagged surfaces | 11 | 3 |
| Findings | 21,249 | 199 |
| `LETHAL_TRIFECTA` paths | 21,248 | 197 |
| `manifest_error` | 1 | 0 |

Rules changed:

1. `annotation.openWorldHint` no longer asserts `UNTRUSTED_INPUT` unless
   the tool names external content (URL, message, log, page, feed, …).
2. `annotation.openWorldEgress` no longer asserts `EXTERNAL_EGRESS` on its
   own: it needs destination evidence — an external target, a schema
   sink, an `x-mcp-header` binding, or a caller-chosen URL/verb carrying
   a payload.
3. `to`, `external` and `comment` left `EXTERNAL_TARGETS`, and
   `recipients`/`webhook`/`callback`/`destination_url` stayed. `to`,
   `cc` and `bcc` are recipient fields: they count only on a
   messaging/mail/HTTP sender, not on a CRM record. Egress nouns come
   from the tool name or a destination-shaped parameter (`issue_key`,
   `channel_id` match by noun; `reportUrl`, `s3Bucket` are record
   fields), and egress verbs from the name or an action-shaped enum, so
   `type: enum["Url"]` and `entity: enum["run"]` stop counting.
4. Pagination and idempotency parameters (`pageToken`,
   `idempotency-key`, …) no longer supply content or secret nouns.
5. A tool whose name starts with a read verb (`list_*`, `get_*`,
   `search_*`) is not a sink, and a payload sender must be governed by a
   leading outbound verb (`send_payload`), not merely contain one
   (`create_text_send`).

Per-target before/after:

| Target | Pre-fix findings | Post-fix findings | Week-2 verdict |
| ------ | ---------------- | ----------------- | -------------- |
| `npm-godot-mcp-server-0-6-1` | — | 1 | `pending` |
| `npm-loopctl-mcp-server-3-47-0` | — | 197 | `pending` |
| `pypi-aimemory-mcp-server-1-7-0` | — | 1 | `pending` |

The residual `@doitintl/doit-mcp-server` paths are no longer
annotation-derived: readers of third-party ticket and status data feed
alert and subscription tools whose `recipients` parameter is a
caller-chosen notification destination. That sink is deliberately
kept — dropping it would also blind the analyzer to report and alert
exfiltration — so the target is labelled
`true_positive_informational`: a real capability of the product rather
than a detector bug.

## Cross-server compositions

A per-server scan cannot answer two of the four engines' questions:
`shadow` needs a second server before any tool name can collide with
anything, and the trifecta is a property of the tool set an agent mounts,
not of one server. The same pinned detectors were therefore re-run over
**348** compositions drawn from the
24 harvested surfaces with an
analyzable manifest — every pair of them, plus each one mounted beside
three kits taken from the pinned `package_eval` captures
(`filesystem+fetch`, `filesystem+git`, `fetch+github`). The duplicate-name
surface behind `CASE-01` is excluded — no capability analysis can run on
it.

**Unvalidated stress test on arbitrary server pairs — not findings.**
Nothing below was drawn from a real deployment: the grid is every pair of
harvested surfaces plus three first-party kits, so the counts are upper
bounds on what the frozen rules emit on that grid, not a prevalence
estimate.
No sample of this sweep has been hand-triaged yet, so the counts
below are untriaged rule output.

Anchors: `npm-server-filesystem`, `npm-server-github-2025-4-8`, `npm-server-memory`, `npm-server-slack-2025-4-25`, `pypi-mcp-server-fetch`, `pypi-mcp-server-git`.

| Metric | Value |
| ------ | ----- |
| Compositions scanned | 348 |
| Compositions with at least one finding | 53 |
| `LETHAL_TRIFECTA` paths | 7,820 (4,927 cross-server) |
| `shadow` findings | 41 |
| `auth-audit` findings | 0 |

| Rule | Compositions |
| ---- | ------------ |
| `CROSS_TOOL_HIJACK` | 6 |
| `EXACT_TOOL_SHADOW` | 5 |
| `LETHAL_TRIFECTA` | 49 |

Largest and quietest compositions in the sweep:

| Composition | Servers | Graph paths | Cross-server | Shadow |
| ----------- | ------- | ----------- | ------------ | ------ |
| `npm-loopctl-mcp-server-3-47-0+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | 3 | 517 | 517 | 4 |
| `npm-alchemy-mcp-server-0-3-0+npm-loopctl-mcp-server-3-47-0` | 2 | 368 | 368 | 0 |
| `npm-dialpad-dialtone-mcp-server-1-15-0+npm-loopctl-mcp-server-3-47-0` | 2 | 242 | 242 | 0 |
| `npm-alchemy-mcp-server-0-3-0+npm-bugsnag-mcp-server-1-1-0` | 2 | 0 | 0 | 0 |

This sweep is the measurement the per-server table cannot give: it
shows that the same frozen rules do produce cross-server paths and
`shadow` collisions once the corpus has more than one server in it.
It is not a prevalence estimate — the compositions are enumerated
from a fixed harvest, not sampled from real deployments.

`auth-audit` stays at zero here: Every capture is a stdio manifest, so auth-audit has no HTTP/OAuth transport to audit. Its zero is an untested engine, not a pass.

## Targets

| Target | Ecosystem | Version | Status | Tools | Findings |
| ------ | --------- | ------- | ------ | ----- | -------- |
| `@0xmonaco/mcp-server` | npm | 1.1.20 | `timeout` | 0 | 0 |
| `@aborruso/ckan-mcp-server` | npm | 0.4.146 | `timeout` | 0 | 0 |
| `@agent-infra/mcp-server-filesystem` | npm | 1.2.29 | `startup_error` | 0 | 0 |
| `@alchemy/mcp-server` | npm | 0.3.0 | `harvested` | 97 | 0 |
| `@azure/mcp-linux-x64` | npm | 4.0.0-beta.10 | `timeout` | 0 | 0 |
| `@azure/mcp-win32-x64` | npm | 4.0.0-beta.10 | `startup_error` | 0 | 0 |
| `bugsnag-mcp-server` | npm | 1.1.0 | `harvested` | 11 | 0 |
| `cclsp` | npm | 0.7.0 | `timeout` | 0 | 0 |
| `@clipwright/mcp-server` | npm | 0.80.0 | `missing_required_env` | 0 | 0 |
| `cls-mcp-server` | npm | 1.3.0 | `harvested` | 20 | 0 |
| `@codacy/codacy-mcp` | npm | 0.7.5 | `timeout` | 0 | 0 |
| `code-review-mcp-server` | npm | 1.5.3 | `timeout` | 0 | 0 |
| `codex-mcp-server` | npm | 1.4.10 | `harvested` | 6 | 0 |
| `deepl-mcp-server` | npm | 1.3.16 | `missing_required_env` | 0 | 0 |
| `@delorenj/mcp-server-trello` | npm | 1.8.1 | `missing_required_env` | 0 | 0 |
| `@dialpad/dialtone-mcp-server` | npm | 1.15.0 | `harvested` | 7 | 0 |
| `docusaurus-plugin-mcp-server` | npm | 2.7.2 | `timeout` | 0 | 0 |
| `@drawio/mcp` | npm | 1.13.1 | `harvested` | 8 | 0 |
| `duckduckgo-mcp-server` | npm | 0.1.2 | `harvested` | 1 | 0 |
| `electron-mcp-server` | npm | 1.5.1 | `timeout` | 0 | 0 |
| `@elgato/mcp-server` | npm | 0.1.8 | `timeout` | 0 | 0 |
| `@eventcatalog/mcp-server` | npm | 2.1.0 | `missing_required_env` | 0 | 0 |
| `@fanyangmeng/ghost-mcp` | npm | 0.2.0 | `missing_required_env` | 0 | 0 |
| `@flexprice/mcp-server` | npm | 2.1.51 | `startup_error` | 0 | 0 |
| `godot-mcp-server` | npm | 0.6.1 | `harvested` | 71 | 1 |
| `@google-cloud/gcloud-mcp` | npm | 0.5.3 | `startup_error` | 0 | 0 |
| `@google-cloud/observability-mcp` | npm | 0.2.3 | `timeout` | 0 | 0 |
| `@henkey/postgres-mcp-server` | npm | 1.0.7 | `harvested` | 18 | 0 |
| `@igniteui/mcp-server` | npm | 16.0.1 | `timeout` | 0 | 0 |
| `@line/line-bot-mcp-server` | npm | 0.5.0 | `timeout` | 0 | 0 |
| `loopctl-mcp-server` | npm | 3.47.0 | `harvested` | 298 | 197 |
| `@magicuidesign/mcp` | npm | 2.1.1 | `harvested` | 3 | 0 |
| `@matillion/mcp-server` | npm | 1.20.6 | `startup_error` | 0 | 0 |
| `mcp-echo-server` | npm | 1.0.0 | `harvested` | 1 | 0 |
| `mcp-server-commands` | npm | 0.8.2 | `harvested` | 1 | 0 |
| `mcp-server-sqlite-npx` | npm | 0.8.0 | `timeout` | 0 | 0 |
| `@milaboratories/pl-mcp-server` | npm | 48.0.0 | `startup_error` | 0 | 0 |
| `@negokaz/excel-mcp-server` | npm | 0.12.0 | `timeout` | 0 | 0 |
| `@nitrostack/cli` | npm | 1.1.3 | `timeout` | 0 | 0 |
| `@nocobase/plugin-mcp-server` | npm | 2.2.53 | `startup_error` | 0 | 0 |
| `@noves/noves-mcp-server` | npm | 0.1.3 | `harvested` | 9 | 0 |
| `openapi-mcp-generator` | npm | 5.0.1 | `startup_error` | 0 | 0 |
| `openapi-mcp-server` | npm | 2.1.0 | `harvested` | 2 | 0 |
| `plantuml-mcp-server` | npm | 0.2.4 | `harvested` | 3 | 0 |
| `playwright-mcp-server` | npm | 1.0.0 | `startup_error` | 0 | 0 |
| `podman-mcp-server` | npm | 0.0.15 | `startup_error` | 0 | 0 |
| `@professional-wiki/mediawiki-mcp-server` | npm | 0.21.0 | `timeout` | 0 | 0 |
| `puppeteer-mcp-server` | npm | 0.7.2 | `timeout` | 0 | 0 |
| `rea-agents` | npm | 6.10.1 | `timeout` | 0 | 0 |
| `@sbroenne/mcp-server-excel-win32-x64` | npm | 2.6.13 | `startup_error` | 0 | 0 |
| `serper-search-scrape-mcp-server` | npm | 0.1.2 | `missing_required_env` | 0 | 0 |
| `sharp-mcp` | npm | 0.2.6 | `timeout` | 0 | 0 |
| `@shopify/dev-mcp` | npm | 1.19.0 | `timeout` | 0 | 0 |
| `@siemens/element-mcp` | npm | 51.8.0-v.2.1.0 | `timeout` | 0 | 0 |
| `slack-mcp-server` | npm | 1.3.0 | `startup_error` | 0 | 0 |
| `@socketsecurity/mcp` | npm | 0.5.0 | `missing_required_env` | 0 | 0 |
| `@statelyai/mcp` | npm | 0.32.2 | `harvested` | 22 | 0 |
| `@suthio/redash-mcp` | npm | 0.1.2 | `timeout` | 0 | 0 |
| `tavily-mcp` | npm | 0.2.22 | `harvested` | 5 | 0 |
| `terraform-mcp-server` | npm | 0.13.0 | `harvested` | 10 | 0 |
| `@tinycloud/mcp` | npm | 0.11.0 | `startup_error` | 0 | 0 |
| `tlaplus-mcp` | npm | 1.0.3 | `harvested` | 3 | 0 |
| `@transcend-io/mcp-server-config` | npm | 0.2.2 | `timeout` | 0 | 0 |
| `@trycompai/mcp-server` | npm | 0.7.16 | `startup_error` | 0 | 0 |
| `twelvelabs-mcp` | npm | 1.0.0 | `timeout` | 0 | 0 |
| `@usegrade/mcp-server` | npm | 0.1.0 | `missing_required_env` | 0 | 0 |
| `vercel-mcp` | npm | 0.0.7 | `timeout` | 0 | 0 |
| `@withpica/mcp-server` | npm | 2.128.0 | `harvested` | 3 | 0 |
| `@zapier/zapier-sdk-mcp` | npm | 0.29.1 | `startup_error` | 0 | 0 |
| `@zeplin/mcp-server` | npm | 1.0.6 | `harvested` | 4 | 0 |
| `agentsyun-coupon-mcp-server` | pypi | 0.0.18 | `startup_error` | 0 | 0 |
| `agile-mcp-server` | pypi | 0.4.0 | `startup_error` | 0 | 0 |
| `agntcy-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `agriculture-mcp-server` | pypi | 0.1.2 | `startup_error` | 0 | 0 |
| `ags-mcp-server` | pypi | 1.2.0 | `startup_error` | 0 | 0 |
| `ai-cogence-mcp-server` | pypi | 1.0.0 | `timeout` | 0 | 0 |
| `ai-core-mcp-server` | pypi | 1.0.0 | `startup_error` | 0 | 0 |
| `ai-ecom-mcp-server` | pypi | 0.1.5 | `timeout` | 0 | 0 |
| `ai-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `ai4h-mcp-server` | pypi | 0.0.1 | `startup_error` | 0 | 0 |
| `aidlc-mcp-server` | pypi | 0.1.0 | `harvested` | 6 | 0 |
| `aimarket-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `aimemory-mcp-server` | pypi | 1.7.0 | `harvested` | 13 | 1 |
| `aiohttp-mcp-server` | pypi | 0.3.0 | `startup_error` | 0 | 0 |
| `aip-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `air-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `airbook-mcp-server` | pypi | 0.0.1 | `startup_error` | 0 | 0 |
| `airflow-mcp-server` | pypi | 0.9.1 | `startup_error` | 0 | 0 |
| `aitasker-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `akshare-mcp-server` | pypi | 0.1.1 | `timeout` | 0 | 0 |
| `alertmanager-mcp-server` | pypi | 1.3.1 | `startup_error` | 0 | 0 |
| `algochains-mcp-server` | pypi | 22.7.3 | `timeout` | 0 | 0 |
| `algogene-mcp-server` | pypi | 0.1.8 | `startup_error` | 0 | 0 |
| `alibaba-cloud-application-management-mcp-server` | pypi | 1.0.4 | `startup_error` | 0 | 0 |
| `alibaba-cloud-ops-mcp-server` | pypi | 0.9.27 | `timeout` | 0 | 0 |
| `alibabacloud-ack-mcp-server` | pypi | 1.0.2 | `timeout` | 0 | 0 |
| `alibabacloud-agentloop-memory-mcp-server` | pypi | 0.2.0 | `startup_error` | 0 | 0 |
| `alibabacloud-dms-mcp-server` | pypi | 0.1.23 | `startup_error` | 0 | 0 |
| `alibabacloud-dts-mcp-server` | pypi | 0.1.4 | `startup_error` | 0 | 0 |
| `alibabacloud-ims-editing-mcp-server` | pypi | 0.0.3 | `startup_error` | 0 | 0 |

## Findings by engine

| Engine | Findings |
| ------ | -------- |
| `audit` | 2 |
| `graph` | 197 |
| `shadow` | 0 |
| `auth-audit` | 0 |

### Rules seen

| Rule | Findings |
| ---- | -------- |
| `LETHAL_TRIFECTA` | 197 |
| `UNICODE_VARIATION_SELECTOR` | 2 |

## Findings

Caps at 20 findings per target; `field_study/scan_results.json` holds
the complete list.

### `godot-mcp-server` 0.6.1

| Engine | Rule | Severity | Tool |
| ------ | ---- | -------- | ---- |
| `audit` | `UNICODE_VARIATION_SELECTOR` | HIGH | `call_method` |

### `loopctl-mcp-server` 3.47.0

| Engine | Rule | Severity | Tool |
| ------ | ---- | -------- | ---- |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:artifact_list` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:artifact_list` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:artifact_list` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:corpus_search` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:corpus_search` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:corpus_search` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_cost_anomalies` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_cost_anomalies` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_cost_anomalies` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_ingestion_anomalies` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_ingestion_anomalies` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_ingestion_anomalies` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_story_token_usage` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_story_token_usage` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:get_story_token_usage` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:knowledge_analytics_top` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:knowledge_analytics_top` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:knowledge_analytics_top` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:knowledge_hybrid_search` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-loopctl-mcp-server-3-47-0:knowledge_hybrid_search` |
| … | (177 more) | | |

### `aimemory-mcp-server` 1.7.0

| Engine | Rule | Severity | Tool |
| ------ | ---- | -------- | ---- |
| `audit` | `UNICODE_VARIATION_SELECTOR` | HIGH | `clear_all_memories` |


## Hand-triage worksheet (Week 2)

Every flagged target is classified into exactly one bucket before any
number is quoted as a result:

| Bucket | Definition | Targets |
| ------ | ---------- | ------- |
| `true_positive_exploitable` | Concrete exploit: an unguarded ingest → private-read → egress chain at a caller-controlled sink. | 0 (none) |
| `true_positive_informational` | Real capability, expected by design: a networked server whose trifecta is inherent to the product. | 0 (none) |
| `manifest_error` | The captured `tools/list` surface is invalid (duplicate tool names), so no capability analysis can run. Reported upstream as a spec violation. | 0 (none) |
| `false_positive_detector_bug` | Over-broad heuristic on a benign manifest; fixed in `mcpprobe/graph.py` with a regression test, then the captures were re-analyzed. | 0 resolved (none) |
| `pending` | Not triaged yet. | 3 (`npm-godot-mcp-server-0-6-1`, `npm-loopctl-mcp-server-3-47-0`, `pypi-aimemory-mcp-server-1-7-0`) |

Triage protocol:

1. Read the captured tool definition in `field_study/captures/<slug>.json`.
2. Reproduce offline (`latch audit`, `latch graph`, `latch shadow`).
3. Quote the exact field and rule in the worksheet; do not guess intent.
4. For detector bugs, fix the rule and add a regression case in `tests/`,
   then regenerate this report so the before/after is visible.

## Limitations

- Targets are registry top-N for one query, not a random sample of the
  ecosystem; prevalence claims are out of scope.
- Capture is `tools/list` only. Handler-level bugs (path traversal,
  injection) are invisible to a manifest auditor and are not scored.
- Credentials are placeholders, not real ones, so a server that
  validates its token before listing tools still never lists them.
  The analyzed subset stays biased toward servers that start
  without a working credential.
- No independent second rater: every label in Week 2 is self-assigned.
- Detectors were frozen for the duration of the harvest. Week-2 triage
  then changed them; the pre-fix and post-fix fingerprints in the
  hardening section pin both rule sets.
- These post-fix numbers are in-sample: the rules were narrowed by
  hand triage of these same captures, so they are a regression suite,
  not validation. `field_study/HOLDOUT.md` repeats the run with the
  rules frozen on a disjoint 100-package sample and is the
  out-of-sample result.
- A `no_finding` verdict is a statement about `tools/list` only
  (names, schemas, annotations, descriptions). Responses, handler code
  and prompt behaviour are outside the scan, so a hostile server whose
  manifest looks benign is invisible here.
- `auth-audit` is not exercised by this corpus: every capture is a
  stdio manifest with no HTTP/OAuth transport to audit, so its zero
  is an untested engine rather than a clean result.

## Reproduction

```bash
# Round 1; each run writes <output stem>.split.json beside its list.
python -m field_study.discover_targets --npm-limit 70 --pypi-limit 30 \
    --output field_study/round1/targets.json
# Holdout, disjoint from round 1 by explicit exclusion.
python -m field_study.discover_targets --npm-limit 70 --pypi-limit 30 \
    --output field_study/holdout/targets.json \
    --exclude-targets field_study/round1/targets.json
# harvest inside the disposable container from run_field_study.SAFETY_BLOCK
python -m field_study.run_field_study --analyze
# Third sample: presence-only checks pass, tokens stay fake.
python -m field_study.run_field_study --harvest --placeholder-credentials \
    --targets field_study/placeholder/targets.json \
    --captures field_study/placeholder/captures
python -m field_study.run_field_study --analyze \
    --captures field_study/placeholder/captures \
    --targets field_study/placeholder/targets.json \
    --output-dir field_study/placeholder
pytest -q tests/test_field_study.py
```
