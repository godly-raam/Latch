# Field study: unseen npm & PyPI MCP servers

**Status: harvest + offline static scan; no surface flagged.**
Every number below comes from
`field_study/run_field_study.py --analyze` over recorded `tools/list`
captures; no package was executed during analysis. There are no
independent ground-truth labels: any verdict below is a self-assigned
hand triage whose criteria are stated in the worksheet.

- Detector fingerprint: `d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4`
- Captured targets: **100**
- Analyzed surfaces: **18**
- Flagged surfaces: **0**
- Targets awaiting hand triage: **0**

## Harvester outcomes

| Status | Count | Meaning |
| ------ | ----- | ------- |
| `harvested` | 18 | `tools/list` returned without credentials. |
| `missing_required_env` | 13 | Exited asking for a token/key/URL; recorded, not retried with secrets. |
| `timeout` | 23 | Exceeded the per-package timeout. |
| `startup_error` | 46 | Install or startup failed for another reason. |

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
| Analyzed surfaces | 31 | 18 |
| Flagged surfaces | 11 | 0 |
| Findings | 21,249 | 0 |
| `LETHAL_TRIFECTA` paths | 21,248 | 0 |
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
**207** compositions drawn from the
18 harvested surfaces with an
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
| Compositions scanned | 207 |
| Compositions with at least one finding | 37 |
| `LETHAL_TRIFECTA` paths | 1,401 (675 cross-server) |
| `shadow` findings | 21 |
| `auth-audit` findings | 0 |

| Rule | Compositions |
| ---- | ------------ |
| `CROSS_TOOL_HIJACK` | 13 |
| `EXACT_TOOL_SHADOW` | 3 |
| `LETHAL_TRIFECTA` | 24 |

### Hand triage of the sweep

20 of the 37 flagged compositions were drawn with `random.Random(20261125)` over the sorted composition ids and read individually
(`python -m field_study.triage_compositions`). Verdicts: **3 real, 3 plausible, 14 artifact**. The remaining 17 are untriaged.

| Composition | Verdict | Evidence |
| ----------- | ------- | -------- |
| `npm-browsermcp-mcp-2-5-0+npm-mcp-searxng-2-12-0` | `artifact` | `browser` is matched inside searxng prose; no routing. |
| `npm-browsermcp-mcp-2-5-0+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `plausible` | fetch, then a private repository read, then an issue or PR; the destination repository is fixed. |
| `npm-clipform-mcp-server-5-17-0+npm-wikipedia-mcp-1-0-3` | `artifact` | `search` is matched inside clipform prose; no routing. |
| `npm-clipform-mcp-server-5-17-0+pypi-agent-tasker-mcp-server-1-0-1` | `real` | news text, then private form responses, then `execute`, which takes a caller-chosen URL and command. |
| `npm-hourei-mcp-server-1-0-6+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | `search_law` reads a fixed legal database, not attacker-controlled content. |
| `npm-hugeicons-mcp-server-0-4-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | icon install snippets are not untrusted input. |
| `npm-mcp-searxng-2-12-0+npm-server-filesystem+pypi-mcp-server-fetch` | `artifact` | `fetch` is matched inside searxng prose; no routing. |
| `npm-mcp-searxng-2-12-0+npm-wikipedia-mcp-1-0-3` | `artifact` | `search` is matched inside searxng prose; no routing. |
| `npm-square-mcp-server-0-1-2+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `plausible` | fetch, then a private repository read, then an issue or PR; the destination repository is fixed. |
| `npm-tacitai-mcp-server-0-15-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `plausible` | fetch, then a private repository read, then an issue or PR; the destination repository is fixed. |
| `npm-tailwindcss-mcp-server-0-1-1+pypi-agent-tasker-mcp-server-1-0-1` | `artifact` | Tailwind docs are a fixed first-party source; the chain starts from documentation prose. |
| `npm-tailwindcss-mcp-server-0-1-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | the ingest leg is `create_pull_request`, a write tool, not an ingest. |
| `npm-transcend-io-mcp-server-docs-0-6-1+npm-wikipedia-mcp-1-0-3` | `artifact` | `search` is matched inside Transcend docs prose; no routing. |
| `npm-transcend-io-mcp-server-docs-0-6-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | `docs_fetch` reads a fixed docs site, not attacker-controlled content. |
| `npm-vizejs-musea-mcp-server-0-793-0+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | the ingest leg is `create_pull_request`, a write tool, not an ingest. |
| `npm-wikipedia-mcp-1-0-3+npm-server-filesystem+pypi-mcp-server-fetch` | `artifact` | `search` is matched inside wikipedia prose; no routing. |
| `pypi-agent-tasker-mcp-server-1-0-1+npm-server-filesystem+pypi-mcp-server-fetch` | `real` | fetch, then local file reads, then `execute`, which takes a caller-chosen URL and command. |
| `pypi-agent-tasker-mcp-server-1-0-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | the ingest leg is `create_pull_request`, a write tool, not an ingest. |
| `pypi-agentic-mcp-server-0-1-1+npm-server-filesystem+pypi-mcp-server-git` | `real` | `read_file` and `write_file` are mounted by two servers; dispatch is genuinely ambiguous. |
| `pypi-agentic-mcp-server-0-1-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | `artifact` | the ingest leg is `create_pull_request`, a write tool, not an ingest. |

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
| `npm-clipform-mcp-server-5-17-0+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | 3 | 94 | 94 | 0 |
| `pypi-agent-tasker-mcp-server-1-0-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | 3 | 92 | 92 | 0 |
| `npm-hugeicons-mcp-server-0-4-1+pypi-mcp-server-fetch+npm-server-github-2025-4-8` | 3 | 82 | 82 | 0 |
| `npm-browsermcp-mcp-2-5-0+npm-clipform-mcp-server-5-17-0` | 2 | 0 | 0 | 0 |

This sweep is the measurement the per-server table cannot give: it
shows that the same frozen rules do produce cross-server paths and
`shadow` collisions once the corpus has more than one server in it.
It is not a prevalence estimate — the compositions are enumerated
from a fixed harvest, not sampled from real deployments.

`auth-audit` stays at zero here: Every capture is a stdio manifest, so auth-audit has no HTTP/OAuth transport to audit. Its zero is an untested engine, not a pass.

## Targets

| Target | Ecosystem | Version | Status | Tools | Findings |
| ------ | --------- | ------- | ------ | ----- | -------- |
| `@abhaybabbar/retellai-mcp-server` | npm | 1.0.4 | `missing_required_env` | 0 | 0 |
| `agentation-mcp` | npm | 1.3.2 | `startup_error` | 0 | 0 |
| `@amap/amap-maps-mcp-server` | npm | 0.0.8 | `missing_required_env` | 0 | 0 |
| `@anyproto/anytype-mcp` | npm | 2.0.3 | `startup_error` | 0 | 0 |
| `@arabold/docs-mcp-server` | npm | 3.5.0 | `timeout` | 0 | 0 |
| `argocd-mcp` | npm | 0.9.0 | `startup_error` | 0 | 0 |
| `@auth0/auth0-mcp-server` | npm | 0.1.0-beta.19 | `startup_error` | 0 | 0 |
| `@aventurevc/mcp-server` | npm | 0.8.498 | `missing_required_env` | 0 | 0 |
| `aws-s3-mcp` | npm | 0.4.0 | `timeout` | 0 | 0 |
| `@battlegrid/mcp-server` | npm | 32.0.115 | `missing_required_env` | 0 | 0 |
| `@bit2me/mcp-server` | npm | 4.5.2 | `startup_error` | 0 | 0 |
| `@browsermcp/mcp` | npm | 2.5.0 | `harvested` | 1 | 0 |
| `@clipform/mcp-server` | npm | 5.17.0 | `harvested` | 32 | 0 |
| `@cloudflare/mcp-server-cloudflare` | npm | 0.2.0 | `startup_error` | 0 | 0 |
| `@cnbcool/mcp-server` | npm | 0.6.7 | `startup_error` | 0 | 0 |
| `@contextstream/mcp-server` | npm | 1.0.99 | `timeout` | 0 | 0 |
| `datadog-mcp-server` | npm | 1.0.9 | `missing_required_env` | 0 | 0 |
| `dataforseo-mcp-server` | npm | 3.1.3 | `timeout` | 0 | 0 |
| `@dbx-app/mcp-server` | npm | 0.4.145 | `timeout` | 0 | 0 |
| `@decodo/mcp-server` | npm | 1.9.0 | `missing_required_env` | 0 | 0 |
| `@dopplerhq/mcp-server` | npm | 1.0.5 | `timeout` | 0 | 0 |
| `@esaio/esa-mcp-server` | npm | 0.15.2 | `missing_required_env` | 0 | 0 |
| `@gongrzhe/server-gmail-autoauth-mcp` | npm | 1.1.11 | `timeout` | 0 | 0 |
| `graphlit-mcp-server` | npm | 1.0.20260112001 | `timeout` | 0 | 0 |
| `hourei-mcp-server` | npm | 1.0.6 | `harvested` | 3 | 0 |
| `@hugeicons/mcp-server` | npm | 0.4.1 | `harvested` | 6 | 0 |
| `@kintone/mcp-server` | npm | 1.11.4 | `missing_required_env` | 0 | 0 |
| `@knip/mcp` | npm | 0.0.39 | `harvested` | 2 | 0 |
| `kubernetes-mcp-server-linux-amd64` | npm | 0.1.3 | `startup_error` | 0 | 0 |
| `langsmith-mcp-server` | npm | 0.1.7 | `harvested` | 15 | 0 |
| `@mastra/mcp-docs-server` | npm | 1.3.15 | `timeout` | 0 | 0 |
| `mcp-searxng` | npm | 2.12.0 | `harvested` | 4 | 0 |
| `mcp-server-code-runner` | npm | 0.1.8 | `harvested` | 1 | 0 |
| `@modelcontextprotocol/server-pdf` | npm | 2.0.4 | `timeout` | 0 | 0 |
| `@mongodb-js/mcp-tools-atlas` | npm | 3.4.0 | `startup_error` | 0 | 0 |
| `mongodb-mcp-server` | npm | 3.4.0 | `timeout` | 0 | 0 |
| `@near-mcp/aitp-mcp-server` | npm | 0.1.34 | `timeout` | 0 | 0 |
| `@nexus2520/bitbucket-mcp-server` | npm | 4.0.0 | `missing_required_env` | 0 | 0 |
| `@onozaty/redmine-mcp-server` | npm | 1.4.0 | `missing_required_env` | 0 | 0 |
| `@openbnb/mcp-server-airbnb` | npm | 0.3.0 | `harvested` | 2 | 0 |
| `replicate-mcp` | npm | 0.9.0 | `startup_error` | 0 | 0 |
| `@sap/mdk-mcp-server` | npm | 0.4.4 | `timeout` | 0 | 0 |
| `@shortcut/mcp` | npm | 0.25.0 | `startup_error` | 0 | 0 |
| `slite-mcp-server` | npm | 1.3.0 | `missing_required_env` | 0 | 0 |
| `@smartbear/mcp` | npm | 0.45.0 | `timeout` | 0 | 0 |
| `square-mcp-server` | npm | 0.1.2 | `harvested` | 3 | 0 |
| `@storybook/mcp` | npm | 10.6.8 | `startup_error` | 0 | 0 |
| `@structured-world/gitlab-mcp` | npm | 13.5.0 | `timeout` | 0 | 0 |
| `@tacitai/mcp-server` | npm | 0.15.1 | `harvested` | 1 | 0 |
| `tailwindcss-mcp-server` | npm | 0.1.1 | `harvested` | 8 | 0 |
| `@thesvg/mcp-server` | npm | 0.9.2 | `harvested` | 5 | 0 |
| `@thirdstrandstudio/mcp-figma` | npm | 0.7.0 | `missing_required_env` | 0 | 0 |
| `tiny-stdio-mcp-server` | npm | 0.1.32 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-admin` | npm | 2.1.0 | `timeout` | 0 | 0 |
| `@transcend-io/mcp-server-assessment` | npm | 2.1.18 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-base` | npm | 3.2.0 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-consent` | npm | 1.6.0 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-custom-functions` | npm | 0.3.5 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-discovery` | npm | 1.1.0 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-docs` | npm | 0.6.1 | `harvested` | 3 | 0 |
| `@transcend-io/mcp-server-dsr` | npm | 2.2.0 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-inventory` | npm | 1.2.0 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-policy` | npm | 0.2.10 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-preferences` | npm | 0.9.0 | `startup_error` | 0 | 0 |
| `@transcend-io/mcp-server-workflows` | npm | 1.2.0 | `startup_error` | 0 | 0 |
| `@vizejs/musea-mcp-server` | npm | 0.793.0 | `harvested` | 13 | 0 |
| `@voltagent/mcp-server` | npm | 2.2.0 | `startup_error` | 0 | 0 |
| `@vouchington/mcp-server` | npm | 0.2.0 | `startup_error` | 0 | 0 |
| `wikipedia-mcp` | npm | 1.0.3 | `harvested` | 2 | 0 |
| `@zereight/mcp-gitlab` | npm | 3.0.0 | `missing_required_env` | 0 | 0 |
| `adls2-mcp-server` | pypi | 0.1.4 | `timeout` | 0 | 0 |
| `ado-mcp-server` | pypi | 0.1.0 | `timeout` | 0 | 0 |
| `adversary-mcp-server` | pypi | 1.11.1 | `timeout` | 0 | 0 |
| `adx-mcp-server` | pypi | 1.1.0 | `startup_error` | 0 | 0 |
| `age_mcp_server` | pypi | 0.3.0 | `timeout` | 0 | 0 |
| `agent-analytics-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agent-commerce-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `agent-coordination-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `agent-cost-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agent-directory-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agent-feedback-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `agent-identity-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `agent-insurance-mcp-server` | pypi | 0.2.0 | `startup_error` | 0 | 0 |
| `agent-mcp-server` | pypi | 0.1.1 | `timeout` | 0 | 0 |
| `agent-memory-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agent-reputation-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agent-staking-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `agent-tasker-mcp-server` | pypi | 1.0.1 | `harvested` | 2 | 0 |
| `agent-toolkit-mcp-server` | pypi | 0.4.0 | `startup_error` | 0 | 0 |
| `agent-validator-mcp-server` | pypi | 0.1.0 | `startup_error` | 0 | 0 |
| `agent-workflow-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agentauth-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agentbridge-mcp-server` | pypi | 0.1.1 | `startup_error` | 0 | 0 |
| `agentfactory-mcp-server` | pypi | 0.1.0 | `timeout` | 0 | 0 |
| `agentic_mcp_server` | pypi | 0.1.1 | `harvested` | 9 | 0 |
| `agentmesh-mcp-server` | pypi | 3.7.0 | `startup_error` | 0 | 0 |
| `agentoath-mcp-server` | pypi | 0.2.0 | `startup_error` | 0 | 0 |
| `agentops-mcp-server` | pypi | 0.5.4 | `timeout` | 0 | 0 |
| `agentskills-mcp-server` | pypi | 0.7.0 | `startup_error` | 0 | 0 |
| `agentsphere-mcp-server` | pypi | 1.9.1 | `startup_error` | 0 | 0 |

## Findings by engine

| Engine | Findings |
| ------ | -------- |
| `audit` | 0 |
| `graph` | 0 |
| `shadow` | 0 |
| `auth-audit` | 0 |

### Rules seen

No findings were produced by any engine.

## Findings

Caps at 20 findings per target; `field_study/scan_results.json` holds
the complete list.

No engine flagged any recorded surface.

## Hand-triage worksheet (Week 2)

Every flagged target is classified into exactly one bucket before any
number is quoted as a result:

| Bucket | Definition | Targets |
| ------ | ---------- | ------- |
| `true_positive_exploitable` | Concrete exploit: an unguarded ingest → private-read → egress chain at a caller-controlled sink. | 0 (none) |
| `true_positive_informational` | Real capability, expected by design: a networked server whose trifecta is inherent to the product. | 0 (none) |
| `manifest_error` | The captured `tools/list` surface is invalid (duplicate tool names), so no capability analysis can run. Reported upstream as a spec violation. | 0 (none) |
| `false_positive_detector_bug` | Over-broad heuristic on a benign manifest; fixed in `mcpprobe/graph.py` with a regression test, then the captures were re-analyzed. | 0 resolved (none) |
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
