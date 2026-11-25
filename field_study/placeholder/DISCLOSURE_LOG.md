# Responsible-disclosure log

**Status: one case closed without a ticket, none open.** No advisory and
no security ticket has been filed. Every entry below is generated from
artifacts already on disk, and Latch never contacts a maintainer on its
own. `CASE-01` is closed because upstream is archived and unmaintained
(`closed_upstream_archived`), not because a fix shipped: it is a
recorded result, not a disclosure.

## Coordinated Disclosure & Upstream Bug Log

| Case ID | Package & Version | Ecosystem | Finding | Upstream Status | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CASE-01` | `@angelogiacco/elevenlabs-mcp-server@1.0.4` | npm | `manifest_error`: `tools/list` returns 546 entries with 6 duplicate tool names (`Add_A_Pronunciation_Dictionary`, `List_Phone_Numbers`, `Get_Dependent_Agents_List`, `List_Procedures`, `Get_Asset`, `Delete_Asset`) and conflicting schemas, violating MCP's unique tool-name invariant. | `closed_upstream_archived` (2026-11-24) | Upstream `elevenlabs/elevenlabs-mcp` is deprecated and no longer maintained in favor of the hosted server (`https://api.elevenlabs.io/v1/mcp`). The npm package links to an unmaintained fork (`AngeloGiacco/elevenlabs-mcp`, 18 commits behind upstream, Issues disabled), so no upstream ticket was filed. |

## Per-target harvest inventory

| Target | Version | Repository | Status | Notes |
| ------ | ------- | ---------- | ------ | ----- |
| `@0xmonaco/mcp-server` | 1.1.20 | https://github.com/Monaco-Research/monaco-sdk | `not_applicable` | No tool surface captured. |
| `@aborruso/ckan-mcp-server` | 0.4.146 | https://github.com/ondata/ckan-mcp-server | `not_applicable` | No tool surface captured. |
| `@agent-infra/mcp-server-filesystem` | 1.2.29 | https://github.com/bytedance/UI-TARS-desktop | `not_applicable` | No tool surface captured. |
| `@alchemy/mcp-server` | 0.3.0 | https://github.com/alchemyplatform/alchemy-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@azure/mcp-linux-x64` | 4.0.0-beta.10 | https://github.com/microsoft/mcp | `not_applicable` | No tool surface captured. |
| `@azure/mcp-win32-x64` | 4.0.0-beta.10 | https://github.com/microsoft/mcp | `not_applicable` | No tool surface captured. |
| `bugsnag-mcp-server` | 1.1.0 | https://github.com/yourusername/bugsnag-mcp | `no_finding` | Clean under the pinned detectors. |
| `cclsp` | 0.7.0 | https://github.com/ktnyt/cclsp | `not_applicable` | No tool surface captured. |
| `@clipwright/mcp-server` | 0.80.0 | https://github.com/seocombat/clipwright-mcp | `not_applicable` | No tool surface captured. |
| `cls-mcp-server` | 1.3.0 | https://github.com/Tencent/cls-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@codacy/codacy-mcp` | 0.7.5 | https://github.com/codacy/codacy-mcp-server | `not_applicable` | No tool surface captured. |
| `code-review-mcp-server` | 1.5.3 | https://github.com/Orcus2021/code-review-mcp-server | `not_applicable` | No tool surface captured. |
| `codex-mcp-server` | 1.4.10 | https://github.com/tuannvm/codex-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `deepl-mcp-server` | 1.3.16 | https://github.com/DeepL/deepl-mcp-server | `not_applicable` | No tool surface captured. |
| `@delorenj/mcp-server-trello` | 1.8.1 | https://github.com/delorenj/mcp-server-trello | `not_applicable` | No tool surface captured. |
| `@dialpad/dialtone-mcp-server` | 1.15.0 | https://github.com/dialpad/dialtone | `no_finding` | Clean under the pinned detectors. |
| `docusaurus-plugin-mcp-server` | 2.7.2 | https://github.com/scalvert/docusaurus-plugin-mcp-server | `not_applicable` | No tool surface captured. |
| `@drawio/mcp` | 1.13.1 | https://github.com/jgraph/drawio-mcp | `no_finding` | Clean under the pinned detectors. |
| `duckduckgo-mcp-server` | 0.1.2 | https://github.com/zhsama/duckduckgo-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `electron-mcp-server` | 1.5.1 | https://github.com/halilural/electron-mcp-server | `not_applicable` | No tool surface captured. |
| `@elgato/mcp-server` | 0.1.8 | https://github.com/elgatosf/elgato-mcp-server | `not_applicable` | No tool surface captured. |
| `@eventcatalog/mcp-server` | 2.1.0 | https://github.com/event-catalog/mcp-server | `not_applicable` | No tool surface captured. |
| `@fanyangmeng/ghost-mcp` | 0.2.0 | — | `not_applicable` | No tool surface captured. |
| `@flexprice/mcp-server` | 2.1.51 | — | `not_applicable` | No tool surface captured. |
| `godot-mcp-server` | 0.6.1 | https://github.com/tomyud1/godot-mcp | `not_contacted` | Awaiting hand triage before any advisory. |
| `@google-cloud/gcloud-mcp` | 0.5.3 | https://github.com/googleapis/gcloud-mcp | `not_applicable` | No tool surface captured. |
| `@google-cloud/observability-mcp` | 0.2.3 | https://github.com/googleapis/gcloud-mcp | `not_applicable` | No tool surface captured. |
| `@henkey/postgres-mcp-server` | 1.0.7 | https://github.com/HenkDz/postgresql-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@igniteui/mcp-server` | 16.0.1 | https://github.com/IgniteUI/igniteui-cli | `not_applicable` | No tool surface captured. |
| `@line/line-bot-mcp-server` | 0.5.0 | ssh://git@github.com/line/line-bot-mcp-server | `not_applicable` | No tool surface captured. |
| `loopctl-mcp-server` | 3.47.0 | https://github.com/mkreyman/loopctl | `not_contacted` | Awaiting hand triage before any advisory. |
| `@magicuidesign/mcp` | 2.1.1 | https://github.com/magicuidesign/mcp | `no_finding` | Clean under the pinned detectors. |
| `@matillion/mcp-server` | 1.20.6 | — | `not_applicable` | No tool surface captured. |
| `mcp-echo-server` | 1.0.0 | — | `no_finding` | Clean under the pinned detectors. |
| `mcp-server-commands` | 0.8.2 | — | `no_finding` | Clean under the pinned detectors. |
| `mcp-server-sqlite-npx` | 0.8.0 | — | `not_applicable` | No tool surface captured. |
| `@milaboratories/pl-mcp-server` | 48.0.0 | https://github.com/milaboratory/platforma | `not_applicable` | No tool surface captured. |
| `@negokaz/excel-mcp-server` | 0.12.0 | — | `not_applicable` | No tool surface captured. |
| `@nitrostack/cli` | 1.1.3 | https://github.com/nitrocloudofficial/nitrostack | `not_applicable` | No tool surface captured. |
| `@nocobase/plugin-mcp-server` | 2.2.53 | — | `not_applicable` | No tool surface captured. |
| `@noves/noves-mcp-server` | 0.1.3 | — | `no_finding` | Clean under the pinned detectors. |
| `openapi-mcp-generator` | 5.0.1 | https://github.com/harsha-iiiv/openapi-mcp-generator | `not_applicable` | No tool surface captured. |
| `openapi-mcp-server` | 2.1.0 | — | `no_finding` | Clean under the pinned detectors. |
| `plantuml-mcp-server` | 0.2.4 | https://github.com/infobip/plantuml-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `playwright-mcp-server` | 1.0.0 | — | `not_applicable` | No tool surface captured. |
| `podman-mcp-server` | 0.0.15 | https://github.com/manusa/podman-mcp-server | `not_applicable` | No tool surface captured. |
| `@professional-wiki/mediawiki-mcp-server` | 0.21.0 | https://github.com/ProfessionalWiki/MediaWiki-MCP-Server | `not_applicable` | No tool surface captured. |
| `puppeteer-mcp-server` | 0.7.2 | https://github.com/merajmehrabi/puppeteer-mcp-server | `not_applicable` | No tool surface captured. |
| `rea-agents` | 6.10.1 | https://github.com/morluto/rea | `not_applicable` | No tool surface captured. |
| `@sbroenne/mcp-server-excel-win32-x64` | 2.6.13 | https://github.com/sbroenne/mcp-server-excel | `not_applicable` | No tool surface captured. |
| `serper-search-scrape-mcp-server` | 0.1.2 | https://github.com/marcopesani/mcp-server-serper | `not_applicable` | No tool surface captured. |
| `sharp-mcp` | 0.2.6 | https://github.com/choesumin/sharp-mcp | `not_applicable` | No tool surface captured. |
| `@shopify/dev-mcp` | 1.19.0 | — | `not_applicable` | No tool surface captured. |
| `@siemens/element-mcp` | 51.8.0-v.2.1.0 | https://code.siemens.com/ux/sdl-mcp | `not_applicable` | No tool surface captured. |
| `slack-mcp-server` | 1.3.0 | https://github.com/korotovsky/slack-mcp-server | `not_applicable` | No tool surface captured. |
| `@socketsecurity/mcp` | 0.5.0 | https://github.com/SocketDev/socket-mcp | `not_applicable` | No tool surface captured. |
| `@statelyai/mcp` | 0.32.2 | — | `no_finding` | Clean under the pinned detectors. |
| `@suthio/redash-mcp` | 0.1.2 | https://github.com/suthio/redash-mcp | `not_applicable` | No tool surface captured. |
| `tavily-mcp` | 0.2.22 | https://github.com/tavily-ai/tavily-mcp | `no_finding` | Clean under the pinned detectors. |
| `terraform-mcp-server` | 0.13.0 | — | `no_finding` | Clean under the pinned detectors. |
| `@tinycloud/mcp` | 0.11.0 | https://github.com/TinyCloudLabs/js-sdk | `not_applicable` | No tool surface captured. |
| `tlaplus-mcp` | 1.0.3 | https://github.com/sonoisa/tlaplus-mcp | `no_finding` | Clean under the pinned detectors. |
| `@transcend-io/mcp-server-config` | 0.2.2 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@trycompai/mcp-server` | 0.7.16 | https://github.com/trycompai/comp-v2 | `not_applicable` | No tool surface captured. |
| `twelvelabs-mcp` | 1.0.0 | — | `not_applicable` | No tool surface captured. |
| `@usegrade/mcp-server` | 0.1.0 | https://github.com/creatorcheck/creatorcheck | `not_applicable` | No tool surface captured. |
| `vercel-mcp` | 0.0.7 | https://github.com/zueai/vercel-api-mcp | `not_applicable` | No tool surface captured. |
| `@withpica/mcp-server` | 2.128.0 | — | `no_finding` | Clean under the pinned detectors. |
| `@zapier/zapier-sdk-mcp` | 0.29.1 | https://gitlab.com/zapier/zapier-sdk/zapier-sdk | `not_applicable` | No tool surface captured. |
| `@zeplin/mcp-server` | 1.0.6 | https://github.com/zeplin/mcp-server | `no_finding` | Clean under the pinned detectors. |
| `agentsyun-coupon-mcp-server` | 0.0.18 | — | `not_applicable` | No tool surface captured. |
| `agile-mcp-server` | 0.4.0 | https://github.com/agile-mcp/agile-mcp-server | `not_applicable` | No tool surface captured. |
| `agntcy-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/agntcy-mcp-server | `not_applicable` | No tool surface captured. |
| `agriculture-mcp-server` | 0.1.2 | https://github.com/AiAgentKarl/agriculture-mcp-server | `not_applicable` | No tool surface captured. |
| `ags-mcp-server` | 1.2.0 | https://pypi.org/project/ags-mcp-server/ | `not_applicable` | No tool surface captured. |
| `ai-cogence-mcp-server` | 1.0.0 | https://github.com/ai-cogence/mcp-server | `not_applicable` | No tool surface captured. |
| `ai-core-mcp-server` | 1.0.0 | — | `not_applicable` | No tool surface captured. |
| `ai-ecom-mcp-server` | 0.1.5 | — | `not_applicable` | No tool surface captured. |
| `ai-mcp-server` | 0.1.1 | https://github.com/brianMacao/ai-mcp-server | `not_applicable` | No tool surface captured. |
| `ai4h-mcp-server` | 0.0.1 | https://github.com/AIH-Infra | `not_applicable` | No tool surface captured. |
| `aidlc-mcp-server` | 0.1.0 | https://github.com/awslabs/aidlc-workflows | `no_finding` | Clean under the pinned detectors. |
| `aimarket-mcp-server` | 0.1.0 | — | `not_applicable` | No tool surface captured. |
| `aimemory-mcp-server` | 1.7.0 | https://github.com/jingchang0623-crypto/aimemory | `not_contacted` | Awaiting hand triage before any advisory. |
| `aiohttp-mcp-server` | 0.3.0 | https://github.com/aio-libs/aiohttp-mcp-server | `not_applicable` | No tool surface captured. |
| `aip-mcp-server` | 0.1.1 | https://github.com/The-Nexus-Guard/aip | `not_applicable` | No tool surface captured. |
| `air-mcp-server` | 0.1.0 | https://github.com/AgentIdentityRegistry/air-site | `not_applicable` | No tool surface captured. |
| `airbook-mcp-server` | 0.0.1 | https://github.com/pypa/sampleproject | `not_applicable` | No tool surface captured. |
| `airflow-mcp-server` | 0.9.1 | — | `not_applicable` | No tool surface captured. |
| `aitasker-mcp-server` | 0.1.1 | https://github.com/bleshinsky/aitasker-app/tree/master/backend/mcp_server | `not_applicable` | No tool surface captured. |
| `akshare-mcp-server` | 0.1.1 | — | `not_applicable` | No tool surface captured. |
| `alertmanager-mcp-server` | 1.3.1 | — | `not_applicable` | No tool surface captured. |
| `algochains-mcp-server` | 22.7.3 | — | `not_applicable` | No tool surface captured. |
| `algogene-mcp-server` | 0.1.8 | — | `not_applicable` | No tool surface captured. |
| `alibaba-cloud-application-management-mcp-server` | 1.0.4 | — | `not_applicable` | No tool surface captured. |
| `alibaba-cloud-ops-mcp-server` | 0.9.27 | — | `not_applicable` | No tool surface captured. |
| `alibabacloud-ack-mcp-server` | 1.0.2 | https://github.com/aliyun/alibabacloud-ack-mcp-server | `not_applicable` | No tool surface captured. |
| `alibabacloud-agentloop-memory-mcp-server` | 0.2.0 | — | `not_applicable` | No tool surface captured. |
| `alibabacloud-dms-mcp-server` | 0.1.23 | — | `not_applicable` | No tool surface captured. |
| `alibabacloud-dts-mcp-server` | 0.1.4 | — | `not_applicable` | No tool surface captured. |
| `alibabacloud-ims-editing-mcp-server` | 0.0.3 | — | `not_applicable` | No tool surface captured. |

## Protocol

1. Triage the finding offline and reproduce it with a minimal probe.
2. Prefer the repository's private security policy (SECURITY.md or a
   private advisory) over a public issue.
3. Report the exact tool definition, rule, and impact; include the
   capture digest so the maintainer can reproduce the surface.
4. Allow a 90-day coordinated window before publishing; disclose
   earlier only if the issue is actively exploited.
5. Update this file with the contact date, channel, and resolution.

No raw secrets, host paths, or environment values belong here.
