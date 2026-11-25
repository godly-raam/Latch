# Field study: unseen npm & PyPI MCP servers

**Status: harvest + offline static scan, hand-triaged in Week 2 and re-analyzed after the detector fix.**
Every number below comes from
`field_study/run_field_study.py --analyze` over recorded `tools/list`
captures; no package was executed during analysis. There are no
independent ground-truth labels: any verdict below is a self-assigned
hand triage whose criteria are stated in the worksheet.

- Detector fingerprint: `d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4`
- Captured targets: **100**
- Analyzed surfaces: **31**
- Flagged surfaces: **3**
- Targets awaiting hand triage: **0**

## Harvester outcomes

| Status | Count | Meaning |
| ------ | ----- | ------- |
| `harvested` | 31 | `tools/list` returned without credentials. |
| `missing_required_env` | 13 | Exited asking for a token/key/URL; recorded, not retried with secrets. |
| `timeout` | 21 | Exceeded the per-package timeout. |
| `startup_error` | 35 | Install or startup failed for another reason. |

A high `missing_required_env` share is expected and is not a
defect: most hosted-service MCP servers cannot list tools without
`GITHUB_TOKEN`-class credentials. The study never supplies them.

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
| Analyzed surfaces | 31 | 31 |
| Flagged surfaces | 11 | 3 |
| Findings | 21,249 | 71 |
| `LETHAL_TRIFECTA` paths | 21,248 | 70 |
| `manifest_error` | 1 | 1 |

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
| `npm-angelogiacco-elevenlabs-mcp-server-1-0-4` | 1 | 1 | `manifest_error` (spec violation) |
| `npm-bitwarden-mcp-server-2026-7-0` | 12 | 0 | `false_positive_detector_bug` (fixed) |
| `npm-chrome-devtools-mcp-1-13-0` | 9 | 4 | `true_positive_informational` |
| `npm-doitintl-doit-mcp-server-5-1-0` | 20,664 | 66 | `true_positive_informational` |
| `npm-heroku-mcp-server-1-2-15` | 1 | 0 | `false_positive_detector_bug` (fixed) |
| `npm-meshy-ai-meshy-mcp-server-0-6-12` | 530 | 0 | `false_positive_detector_bug` (fixed) |
| `npm-microsoft-clarity-mcp-server-3-0-0` | 10 | 0 | `false_positive_detector_bug` (fixed) |
| `npm-notionhq-notion-mcp-server-2-6-1` | 5 | 0 | `false_positive_detector_bug` (fixed) |
| `npm-qase-mcp-server-3-2-1` | 7 | 0 | `false_positive_detector_bug` (fixed) |
| `npm-sap-ux-fiori-mcp-server-1-17-0` | 5 | 0 | `false_positive_detector_bug` (fixed) |
| `npm-tsmztech-mcp-server-salesforce-0-0-8` | 5 | 0 | `false_positive_detector_bug` (fixed) |

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
**525** compositions drawn from the
30 harvested surfaces with an
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
A fixed-seed hand triage of a sample follows and finds that most
flags do not survive contact with the pair.

Anchors: `npm-server-filesystem`, `npm-server-github-2025-4-8`, `npm-server-memory`, `npm-server-slack-2025-4-25`, `pypi-mcp-server-fetch`, `pypi-mcp-server-git`.

| Metric | Value |
| ------ | ----- |
| Compositions scanned | 525 |
| Compositions with at least one finding | 136 |
| `LETHAL_TRIFECTA` paths | 5,113 (2,937 cross-server) |
| `shadow` findings | 186 |
| `auth-audit` findings | 0 |

| Rule | Compositions |
| ---- | ------------ |
| `CROSS_TOOL_HIJACK` | 53 |
| `EXACT_TOOL_SHADOW` | 4 |
| `LETHAL_TRIFECTA` | 91 |

### Hand triage of the sweep

20 of the 136 flagged compositions were drawn with `random.Random(20261125)` over the sorted composition ids and read individually
(`python -m field_study.triage_compositions`). Verdicts: **4 real, 2 plausible, 14 artifact**. The remaining 116 are untriaged.

| Composition | Verdict | Evidence |
| ----------- | ------- | -------- |
| `npm-bitwarden-mcp-server-2026-7-0+npm-doitintl-doit-mcp-server-5-1-0` | `real` | `create_folder` is genuinely mounted by both servers; the 53 hijacks are prose matches on `delete`/`status` and the 78 paths treat a vault read as untrusted ingest. |
| `npm-bitwarden-mcp-server-2026-7-0+npm-modelcontextprotocol-server-sequential-thinking-2-2-0` | `artifact` | `generate` is matched inside sequential-thinking prose; no tool routes to another server. |
| `npm-bitwarden-mcp-server-2026-7-0+npm-sap-ux-fiori-mcp-server-1-17-0` | `artifact` | `generate` is matched inside SAP build instructions; prose, not routing. |
| `npm-bitwarden-mcp-server-2026-7-0+npm-tsmztech-mcp-server-salesforce-0-0-8` | `artifact` | `status` is matched inside Salesforce prose; prose, not routing. |
| `npm-chelaile-mcp-server-1-1-0+npm-chrome-devtools-mcp-1-13-0` | `artifact` | public transit search is not attacker-controlled input, and the other paths are chrome-devtools alone. |
| `npm-chrome-devtools-mcp-1-13-0+npm-ericthered926-duckduckgo-mcp-server-0-6-0` | `real` | search snippets are attacker-influenced, chrome reads network traffic, and `navigate_page` accepts any URL. |
| `npm-chrome-devtools-mcp-1-13-0+npm-modelcontextprotocol-server-sequential-thinking-2-2-0` | `artifact` | all four paths are inside chrome-devtools; the partner adds no leg. |
| `npm-chrome-devtools-mcp-1-13-0+pypi-a2a-mcp-server-0-1-5` | `artifact` | all four paths are inside chrome-devtools; the partner adds no leg. |
| `npm-chrome-devtools-mcp-1-13-0+pypi-acp-mcp-server-0-0-5` | `artifact` | all four paths are inside chrome-devtools; the partner adds no leg. |
| `npm-doitintl-doit-mcp-server-5-1-0+npm-modelcontextprotocol-server-sequential-thinking-2-2-0` | `artifact` | all 66 paths are inside doit; the partner adds no leg. |
| `npm-doitintl-doit-mcp-server-5-1-0+npm-mui-mcp-0-1-10` | `artifact` | all 66 paths are inside doit; the partner adds no leg. |
| `npm-doitintl-doit-mcp-server-5-1-0+npm-server-filesystem+pypi-mcp-server-git` | `real` | third-party ticket and diagram text, local file reads, then alert email and Slack recipients. |
| `npm-doitintl-doit-mcp-server-5-1-0+npm-touchdesigner-mcp-server-2-2-0` | `real` | ticket text, TouchDesigner node reads, then alert recipients. |
| `npm-doitintl-doit-mcp-server-5-1-0+pypi-acp-mcp-server-0-0-5` | `artifact` | cross-server paths are 0; every path is inside doit. |
| `npm-ericthered926-duckduckgo-mcp-server-0-6-0+npm-hostinger-api-mcp-4-20-0` | `artifact` | `search` is matched inside hostinger prose; no routing. |
| `npm-ericthered926-duckduckgo-mcp-server-0-6-0+npm-hostinger-mcp-4-20-0` | `artifact` | `search` is matched inside hostinger prose; no routing. |
| `npm-hostinger-mcp-4-20-0+npm-server-filesystem+pypi-mcp-server-fetch` | `artifact` | `search` is matched inside hostinger prose; filesystem and fetch add no hijack. |
| `npm-meshy-ai-meshy-mcp-server-0-6-12+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | the ingest leg is a caller-supplied Meshy model analysis, and the egress repository is fixed. |
| `npm-next-devtools-mcp-0-4-0+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `plausible` | fetch, then a private repository read, then an issue or PR is a real chain; the destination repository is fixed, not caller-chosen. |
| `npm-upstash-context7-mcp-4-7-3+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `plausible` | fetch, then a private repository read, then an issue or PR is a real chain; the destination repository is fixed, not caller-chosen. |

The artifacts come from three mechanisms, each visible in the
notes above:

1. **A leg the detector misclassified.** `create_pull_request` is
   read as untrusted input, a local `read_file`/`search_files` as
   ingest, and a fixed product API as an egress. A path built from
   one of those is not a chain, whatever its shape.
2. **A single-server chain the partner does not touch.** Several
   sampled compositions flag only because one mounted server has an
   inherent trifecta of its own; the second server adds no leg, so
   the flag is a property of the harness, not of the pair.
3. **Prose matched against a generic tool name.** `search`,
   `status`, `delete`, `generate`, `browser` and `fetch` occur in
   ordinary descriptions, and `CROSS_TOOL_HIJACK` then claims
   routing that the text does not contain.

No detector was changed for this triage: the sweep is labelled,
not fixed, so the frozen fingerprint above still covers it and the
remaining compositions stay untriaged.

Largest and quietest compositions in the sweep:

| Composition | Servers | Graph paths | Cross-server | Shadow |
| ----------- | ------- | ----------- | ------------ | ------ |
| `npm-doitintl-doit-mcp-server-5-1-0+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | 3 | 288 | 288 | 1 |
| `npm-doitintl-doit-mcp-server-5-1-0+npm-meshy-ai-meshy-mcp-server-0-6-12` | 2 | 156 | 156 | 0 |
| `npm-meshy-ai-meshy-mcp-server-0-6-12+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | 3 | 130 | 130 | 0 |
| `npm-bitwarden-mcp-server-2026-7-0+npm-coinbase-cds-mcp-server-9-30-1` | 2 | 0 | 0 | 0 |

This sweep is the measurement the per-server table cannot give: it
shows that the same frozen rules do produce cross-server paths and
`shadow` collisions once the corpus has more than one server in it.
It is not a prevalence estimate — the compositions are enumerated
from a fixed harvest, not sampled from real deployments.

`auth-audit` stays at zero here: Every capture is a stdio manifest, so auth-audit has no HTTP/OAuth transport to audit. Its zero is an untested engine, not a pass.

## Targets

| Target | Ecosystem | Version | Status | Tools | Findings |
| ------ | --------- | ------- | ------ | ----- | -------- |
| `@aikidosec/mcp` | npm | 1.0.35 | `timeout` | 0 | 0 |
| `@angelogiacco/elevenlabs-mcp-server` | npm | 1.0.4 | `harvested` | 546 | 1 |
| `@apify/actors-mcp-server` | npm | 0.22.0 | `timeout` | 0 | 0 |
| `axe-mcp-server` | npm | 1.9.1 | `startup_error` | 0 | 0 |
| `@azure-devops/mcp` | npm | 2.11.0 | `timeout` | 0 | 0 |
| `@azure/mcp` | npm | 4.0.0-beta.10 | `timeout` | 0 | 0 |
| `bailian-mcp-server` | npm | 0.0.4 | `missing_required_env` | 0 | 0 |
| `@benborla29/mcp-server-mysql` | npm | 2.0.9 | `timeout` | 0 | 0 |
| `@bitwarden/mcp-server` | npm | 2026.7.0 | `harvested` | 59 | 0 |
| `@brave/brave-search-mcp-server` | npm | 2.2.0 | `missing_required_env` | 0 | 0 |
| `@browserstack/mcp-server` | npm | 2.6.11 | `timeout` | 0 | 0 |
| `@cap-js/mcp-server` | npm | 0.1.0 | `timeout` | 0 | 0 |
| `chelaile-mcp-server` | npm | 1.1.0 | `harvested` | 15 | 0 |
| `chrome-devtools-mcp` | npm | 1.13.0 | `harvested` | 33 | 4 |
| `@coinbase/cds-mcp-server` | npm | 9.30.1 | `harvested` | 2 | 0 |
| `@contentful/mcp-server` | npm | 1.24.9 | `timeout` | 0 | 0 |
| `@currents/mcp` | npm | 2.8.0 | `missing_required_env` | 0 | 0 |
| `@doitintl/doit-mcp-server` | npm | 5.1.0 | `harvested` | 285 | 66 |
| `@ehrocks/fe-mcp-server` | npm | 1.0.10 | `harvested` | 1 | 0 |
| `@ericthered926/duckduckgo-mcp-server` | npm | 0.6.0 | `harvested` | 2 | 0 |
| `@eslint/mcp` | npm | 0.3.17 | `harvested` | 1 | 0 |
| `@heroku/mcp-server` | npm | 1.2.15 | `harvested` | 33 | 0 |
| `hostinger-api-mcp` | npm | 4.20.0 | `harvested` | 3 | 0 |
| `@hostinger/mcp` | npm | 4.20.0 | `harvested` | 3 | 0 |
| `@hubspot/mcp-server` | npm | 0.4.0 | `missing_required_env` | 0 | 0 |
| `@iobroker/mcp-server` | npm | 1.10.0 | `startup_error` | 0 | 0 |
| `@ivotoby/openapi-mcp-server` | npm | 1.18.0 | `startup_error` | 0 | 0 |
| `jira-mcp-server` | npm | 0.0.1 | `startup_error` | 0 | 0 |
| `kubernetes-mcp-server` | npm | 0.1.3 | `startup_error` | 0 | 0 |
| `malicious-mcp-server` | npm | 1.5.0 | `harvested` | 7 | 0 |
| `@mantine/mcp-server` | npm | 9.8.2 | `harvested` | 5 | 0 |
| `@mapbox/mcp-server` | npm | 0.18.1 | `timeout` | 0 | 0 |
| `mcp-hello-world` | npm | 1.1.2 | `harvested` | 3 | 0 |
| `mcp-server` | npm | 0.0.9 | `timeout` | 0 | 0 |
| `mcp-server-kubernetes` | npm | 4.2.3 | `timeout` | 0 | 0 |
| `mcp-server-whisper` | npm | 0.0.1 | `startup_error` | 0 | 0 |
| `@meshy-ai/meshy-mcp-server` | npm | 0.6.12 | `harvested` | 28 | 0 |
| `@microsoft/clarity-mcp-server` | npm | 3.0.0 | `harvested` | 30 | 0 |
| `@modelcontextprotocol/server-sequential-thinking` | npm | 2.2.0 | `harvested` | 1 | 0 |
| `@mui/mcp` | npm | 0.1.10 | `harvested` | 2 | 0 |
| `next-devtools-mcp` | npm | 0.4.0 | `harvested` | 4 | 0 |
| `@notionhq/notion-mcp-server` | npm | 2.6.1 | `harvested` | 24 | 0 |
| `@pandacss/mcp` | npm | 2.6.0 | `timeout` | 0 | 0 |
| `@phantom/mcp-server` | npm | 1.2.12 | `timeout` | 0 | 0 |
| `@processon/mcp-server-processon-node` | npm | 1.0.10 | `harvested` | 2 | 0 |
| `@qase/mcp-server` | npm | 3.2.1 | `harvested` | 42 | 0 |
| `@roychri/mcp-server-asana` | npm | 1.8.0 | `timeout` | 0 | 0 |
| `@runpod/mcp-server` | npm | 5.0.0 | `missing_required_env` | 0 | 0 |
| `@sap-ux/fiori-mcp-server` | npm | 1.17.0 | `harvested` | 9 | 0 |
| `scryfall-mcp-server` | npm | 0.1.1 | `harvested` | 7 | 0 |
| `@sentry/mcp-server` | npm | 0.50.0 | `startup_error` | 0 | 0 |
| `@sigmacomputing/slack-mcp-server` | npm | 0.1.1 | `missing_required_env` | 0 | 0 |
| `@softeria/ms-365-mcp-server` | npm | 0.190.5 | `timeout` | 0 | 0 |
| `@supabase/mcp-server-supabase` | npm | 0.19.0 | `missing_required_env` | 0 | 0 |
| `@superblocksteam/mcp-server` | npm | 2.0.183 | `timeout` | 0 | 0 |
| `@theia/ai-mcp-server` | npm | 1.77.0 | `startup_error` | 0 | 0 |
| `tiny-http-mcp-server` | npm | 0.1.132 | `timeout` | 0 | 0 |
| `@tocharianou/mcp-server-kibana` | npm | 0.12.1 | `harvested` | 17 | 0 |
| `touchdesigner-mcp-server` | npm | 2.2.0 | `harvested` | 14 | 0 |
| `@transloadit/mcp-server` | npm | 0.9.0 | `timeout` | 0 | 0 |
| `@tsmztech/mcp-server-salesforce` | npm | 0.0.8 | `harvested` | 15 | 0 |
| `@ui5/mcp-server` | npm | 0.3.3 | `timeout` | 0 | 0 |
| `@unthread-io/mcp-server` | npm | 1.3.1 | `startup_error` | 0 | 0 |
| `@upstash/context7-mcp` | npm | 4.7.3 | `harvested` | 2 | 0 |
| `@upstash/mcp-server` | npm | 0.4.1 | `missing_required_env` | 0 | 0 |
| `@winor30/mcp-server-datadog` | npm | 1.8.0 | `missing_required_env` | 0 | 0 |
| `@wonderwhy-er/desktop-commander` | npm | 0.3.4 | `timeout` | 0 | 0 |
| `@xeroapi/xero-mcp-server` | npm | 0.0.18 | `startup_error` | 0 | 0 |
| `@z_ai/mcp-server` | npm | 0.1.6 | `missing_required_env` | 0 | 0 |
| `@zencoderai/slack-mcp-server` | npm | 0.0.1 | `missing_required_env` | 0 | 0 |
| `3dcitydb-mcp-server` | pypi | 1.2.2 | `startup_error` | 0 | 0 |
| `a-stock-mcp-server` | pypi | 1.1.1 | `timeout` | 0 | 0 |
| `a2a-mcp-server` | pypi | 0.1.5 | `harvested` | 7 | 0 |
| `a2a-protocol-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `a3m-mcp-server` | pypi | 1.0.0 | `startup_error` | 0 | 0 |
| `aa-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `aapt-mcp-server` | pypi | 1.0.0 | `startup_error` | 0 | 0 |
| `aas-mcp-server` | pypi | 0.3.0 | `missing_required_env` | 0 | 0 |
| `abacum-mcp-server` | pypi | 0.1.7.post1 | `missing_required_env` | 0 | 0 |
| `ableton-live-mcp-server` | pypi | 0.2.1 | `startup_error` | 0 | 0 |
| `ableton-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `abraflexi-mcp-server` | pypi | 1.2.4 | `startup_error` | 0 | 0 |
| `ac-mcp-server` | pypi | 0.12.0 | `startup_error` | 0 | 0 |
| `accessibility-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `accounting-subject-analysis-mcp-server` | pypi | 0.1.4 | `startup_error` | 0 | 0 |
| `aceflow-mcp-server` | pypi | 3.0.2 | `startup_error` | 0 | 0 |
| `acex-mcp-server` | pypi | 1.1.1 | `startup_error` | 0 | 0 |
| `acli-mcp-server` | pypi | 0.1.4 | `startup_error` | 0 | 0 |
| `acp-mcp-server` | pypi | 0.0.5 | `harvested` | 16 | 0 |
| `action1-mcp-server` | pypi | 1.0.0 | `startup_error` | 0 | 0 |
| `actvalue.lambda-mcp-server` | pypi | 2.0.0 | `startup_error` | 0 | 0 |
| `adb-mcp-server` | pypi | 1.0.0 | `startup_error` | 0 | 0 |
| `adb-mysql-mcp-server` | pypi | 2.0.0 | `startup_error` | 0 | 0 |
| `adbpg-mcp-server` | pypi | 2.0.3 | `startup_error` | 0 | 0 |
| `add-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `add-stdio-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `Ai_Indeed_mcp_server` | pypi | 1.0.0 | `startup_error` | 0 | 0 |
| `BigGo-MCP-Server` | pypi | 0.2.0 | `startup_error` | 0 | 0 |
| `ELF-mcp-server` | pypi | 1.61.0 | `startup_error` | 0 | 0 |
| `Things3-MCP-server` | pypi | 2.0.7 | `startup_error` | 0 | 0 |

## Findings by engine

| Engine | Findings |
| ------ | -------- |
| `audit` | 1 |
| `graph` | 70 |
| `shadow` | 0 |
| `auth-audit` | 0 |

### Rules seen

| Rule | Findings |
| ---- | -------- |
| `LETHAL_TRIFECTA` | 70 |
| `manifest_error` | 1 |

## Findings

Caps at 20 findings per target; `field_study/scan_results.json` holds
the complete list.

### `@angelogiacco/elevenlabs-mcp-server` 1.0.4

| Engine | Rule | Severity | Tool |
| ------ | ---- | -------- | ---- |
| `audit` | `manifest_error` | MEDIUM | `(manifest)` |

### `chrome-devtools-mcp` 1.13.0

| Engine | Rule | Severity | Tool |
| ------ | ---- | -------- | ---- |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-chrome-devtools-mcp-1-13-0:get_console_message` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-chrome-devtools-mcp-1-13-0:get_css_styles` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-chrome-devtools-mcp-1-13-0:list_console_messages` |
| `graph` | `LETHAL_TRIFECTA` | CRITICAL | `npm-chrome-devtools-mcp-1-13-0:list_network_requests` |

### `@doitintl/doit-mcp-server` 5.1.0

| Engine | Rule | Severity | Tool |
| ------ | ---- | -------- | ---- |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_statussheet_components` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_statussheet_components` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_statussheet_components` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_statussheet_components` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_statussheet_components` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_statussheet_components` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_ticket` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_ticket` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_ticket` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_ticket` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_ticket` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:get_ticket` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_alert_slack_channels` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_alert_slack_channels` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_alert_slack_channels` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_alert_slack_channels` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_alert_slack_channels` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_alert_slack_channels` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_attribute_workloads_filter_values` |
| `graph` | `LETHAL_TRIFECTA` | HIGH | `npm-doitintl-doit-mcp-server-5-1-0:list_attribute_workloads_filter_values` |
| … | (46 more) | | |


## Hand-triage worksheet (Week 2)

Every flagged target is classified into exactly one bucket before any
number is quoted as a result:

| Bucket | Definition | Targets |
| ------ | ---------- | ------- |
| `true_positive_exploitable` | Concrete exploit: an unguarded ingest → private-read → egress chain at a caller-controlled sink. | 0 (none) |
| `true_positive_informational` | Real capability, expected by design: a networked server whose trifecta is inherent to the product. | 2 (`npm-chrome-devtools-mcp-1-13-0`, `npm-doitintl-doit-mcp-server-5-1-0`) |
| `manifest_error` | The captured `tools/list` surface is invalid (duplicate tool names), so no capability analysis can run. Reported upstream as a spec violation. | 1 (`npm-angelogiacco-elevenlabs-mcp-server-1-0-4`) |
| `false_positive_detector_bug` | Over-broad heuristic on a benign manifest; fixed in `mcpprobe/graph.py` with a regression test, then the captures were re-analyzed. | 8 resolved (`npm-bitwarden-mcp-server-2026-7-0`, `npm-heroku-mcp-server-1-2-15`, `npm-meshy-ai-meshy-mcp-server-0-6-12`, `npm-microsoft-clarity-mcp-server-3-0-0`, `npm-notionhq-notion-mcp-server-2-6-1`, `npm-qase-mcp-server-3-2-1`, `npm-sap-ux-fiori-mcp-server-1-17-0`, `npm-tsmztech-mcp-server-salesforce-0-0-8`) |
| `pending` | Not triaged yet. | 0 (none) |

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
- Packages needing credentials never list tools here, so the
  analyzed subset is biased toward servers that start without
  secrets.
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
- **Known out-of-scope miss: `malicious-mcp-server@1.5.0`.** The package describes itself as "A deliberately malicious MCP server for E2E testing purposes". Its surface is hostile by intent (`tokenInputReceiver` collects API keys, database passwords and JWT secrets; `customerDataProvider` is PII-shaped; `promptGuardTriggerer` wraps untrusted content), but none of that is expressed in annotations or capability names, and the malicious behaviour is in runtime responses and handlers, which `tools/list` does not carry. The pinned detectors therefore return zero findings. It is recorded as `known_out_of_scope_miss` in `DISCLOSURE_LOG.md`, never as `no_finding`: a static `tools/list` scan reporting this server clean would be a false negative, not a true one.

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
pytest -q tests/test_field_study.py
```
