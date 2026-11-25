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
| `@aikidosec/mcp` | 1.0.35 | — | `not_applicable` | No tool surface captured. |
| `@apify/actors-mcp-server` | 0.22.0 | https://github.com/apify/apify-mcp-server | `not_applicable` | No tool surface captured. |
| `axe-mcp-server` | 1.9.1 | https://github.com/dequelabs/axe-mcp-server-public | `not_applicable` | No tool surface captured. |
| `@azure-devops/mcp` | 2.11.0 | https://github.com/microsoft/azure-devops-mcp | `not_applicable` | No tool surface captured. |
| `@azure/mcp` | 4.0.0-beta.10 | https://github.com/microsoft/mcp | `not_applicable` | No tool surface captured. |
| `bailian-mcp-server` | 0.0.4 | — | `not_applicable` | No tool surface captured. |
| `@benborla29/mcp-server-mysql` | 2.0.9 | https://github.com/benborla/mcp-server-mysql | `not_applicable` | No tool surface captured. |
| `@bitwarden/mcp-server` | 2026.7.0 | https://github.com/bitwarden/mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@brave/brave-search-mcp-server` | 2.2.0 | https://github.com/brave/brave-search-mcp-server | `not_applicable` | No tool surface captured. |
| `@browserstack/mcp-server` | 2.6.11 | https://github.com/browserstack/mcp-server | `not_applicable` | No tool surface captured. |
| `@cap-js/mcp-server` | 0.1.0 | https://github.com/cap-js/mcp-server | `not_applicable` | No tool surface captured. |
| `chelaile-mcp-server` | 1.1.0 | — | `no_finding` | Clean under the pinned detectors. |
| `chrome-devtools-mcp` | 1.13.0 | https://github.com/ChromeDevTools/chrome-devtools-mcp | `not_contacted` | Awaiting hand triage before any advisory. |
| `@coinbase/cds-mcp-server` | 9.30.1 | ssh://git@github.com/coinbase/cds | `no_finding` | Clean under the pinned detectors. |
| `@contentful/mcp-server` | 1.24.9 | https://github.com/contentful/contentful-mcp-server | `not_applicable` | No tool surface captured. |
| `@currents/mcp` | 2.8.0 | https://github.com/currents-dev/currents-mcp | `not_applicable` | No tool surface captured. |
| `@doitintl/doit-mcp-server` | 5.1.0 | https://github.com/doitintl/doit-mcp-server | `not_contacted` | Awaiting hand triage before any advisory. |
| `@ehrocks/fe-mcp-server` | 1.0.10 | https://github.com/thinkei/fe-mcp-service | `no_finding` | Clean under the pinned detectors. |
| `@ericthered926/duckduckgo-mcp-server` | 0.6.0 | https://github.com/ericthered926/duckduckgo-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@eslint/mcp` | 0.3.17 | https://github.com/eslint/rewrite | `no_finding` | Clean under the pinned detectors. |
| `@heroku/mcp-server` | 1.2.15 | https://github.com/heroku/heroku-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `hostinger-api-mcp` | 4.20.0 | https://github.com/hostinger/api-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@hostinger/mcp` | 4.20.0 | https://github.com/hostinger/api-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@hubspot/mcp-server` | 0.4.0 | — | `not_applicable` | No tool surface captured. |
| `@iobroker/mcp-server` | 1.10.0 | https://github.com/ioBroker/mcp-package | `not_applicable` | No tool surface captured. |
| `@ivotoby/openapi-mcp-server` | 1.18.0 | https://github.com/ivo-toby/mcp-openapi-server | `not_applicable` | No tool surface captured. |
| `jira-mcp-server` | 0.0.1 | — | `not_applicable` | No tool surface captured. |
| `kubernetes-mcp-server` | 0.1.3 | https://github.com/containers/kubernetes-mcp-server | `not_applicable` | No tool surface captured. |
| `malicious-mcp-server` | 1.5.0 | https://github.com/anysource-AI/malicious-mcp-server | `known_out_of_scope_miss` | Malice is in runtime responses, not in `tools/list`: the pinned detectors return nothing. Recorded as a boundary, not clean. |
| `@mantine/mcp-server` | 9.8.2 | https://github.com/mantinedev/mantine | `no_finding` | Clean under the pinned detectors. |
| `@mapbox/mcp-server` | 0.18.1 | https://github.com/mapbox/mcp-server | `not_applicable` | No tool surface captured. |
| `mcp-hello-world` | 1.1.2 | https://github.com/lobehub/mcp-hello-world | `no_finding` | Clean under the pinned detectors. |
| `mcp-server` | 0.0.9 | https://github.com/sandy-mount/mcp-server | `not_applicable` | No tool surface captured. |
| `mcp-server-kubernetes` | 4.2.3 | https://github.com/Flux159/mcp-server-kubernetes | `not_applicable` | No tool surface captured. |
| `mcp-server-whisper` | 0.0.1 | https://github.com/hlos-ai/mcp-servers | `not_applicable` | No tool surface captured. |
| `@meshy-ai/meshy-mcp-server` | 0.6.12 | https://github.com/meshy-dev/meshy-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@microsoft/clarity-mcp-server` | 3.0.0 | https://github.com/microsoft/clarity-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@modelcontextprotocol/server-sequential-thinking` | 2.2.0 | https://github.com/modelcontextprotocol/servers | `no_finding` | Clean under the pinned detectors. |
| `@mui/mcp` | 0.1.10 | https://github.com/mui/mui-x | `no_finding` | Clean under the pinned detectors. |
| `next-devtools-mcp` | 0.4.0 | https://github.com/vercel/next-devtools-mcp | `no_finding` | Clean under the pinned detectors. |
| `@notionhq/notion-mcp-server` | 2.6.1 | ssh://git@github.com/makenotion/notion-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@pandacss/mcp` | 2.6.0 | https://github.com/chakra-ui/panda | `not_applicable` | No tool surface captured. |
| `@phantom/mcp-server` | 1.2.12 | https://github.com/phantom/phantom-connect-sdk | `not_applicable` | No tool surface captured. |
| `@processon/mcp-server-processon-node` | 1.0.10 | — | `no_finding` | Clean under the pinned detectors. |
| `@qase/mcp-server` | 3.2.1 | https://github.com/qase-tms/qase-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@roychri/mcp-server-asana` | 1.8.0 | https://github.com/roychri/mcp-server-asana | `not_applicable` | No tool surface captured. |
| `@runpod/mcp-server` | 5.0.0 | https://github.com/runpod/runpod-mcp | `not_applicable` | No tool surface captured. |
| `@sap-ux/fiori-mcp-server` | 1.17.0 | https://github.com/SAP/open-ux-tools | `no_finding` | Clean under the pinned detectors. |
| `scryfall-mcp-server` | 0.1.1 | — | `no_finding` | Clean under the pinned detectors. |
| `@sentry/mcp-server` | 0.50.0 | https://github.com/getsentry/toolkit | `not_applicable` | No tool surface captured. |
| `@sigmacomputing/slack-mcp-server` | 0.1.1 | https://github.com/sigmacomputing/slack-mcp-server | `not_applicable` | No tool surface captured. |
| `@softeria/ms-365-mcp-server` | 0.190.5 | https://github.com/Softeria/ms-365-mcp-server | `not_applicable` | No tool surface captured. |
| `@supabase/mcp-server-supabase` | 0.19.0 | https://github.com/supabase/mcp | `not_applicable` | No tool surface captured. |
| `@superblocksteam/mcp-server` | 2.0.183 | https://github.com/superblocksteam/superblocks | `not_applicable` | No tool surface captured. |
| `@theia/ai-mcp-server` | 1.77.0 | https://github.com/eclipse-theia/theia | `not_applicable` | No tool surface captured. |
| `tiny-http-mcp-server` | 0.1.132 | https://github.com/poe-platform/poe-code | `not_applicable` | No tool surface captured. |
| `@tocharianou/mcp-server-kibana` | 0.12.1 | https://github.com/TocharianOU/mcp-server-kibana | `no_finding` | Clean under the pinned detectors. |
| `touchdesigner-mcp-server` | 2.2.0 | https://github.com/8beeeaaat/touchdesigner-mcp | `no_finding` | Clean under the pinned detectors. |
| `@transloadit/mcp-server` | 0.9.0 | https://github.com/transloadit/node-sdk | `not_applicable` | No tool surface captured. |
| `@tsmztech/mcp-server-salesforce` | 0.0.8 | https://github.com/tsmztech/mcp-server-salesforce | `no_finding` | Clean under the pinned detectors. |
| `@ui5/mcp-server` | 0.3.3 | https://github.com/UI5/mcp-server | `not_applicable` | No tool surface captured. |
| `@unthread-io/mcp-server` | 1.3.1 | https://github.com/unthread-io/mcp-server | `not_applicable` | No tool surface captured. |
| `@upstash/context7-mcp` | 4.7.3 | https://github.com/upstash/context7 | `no_finding` | Clean under the pinned detectors. |
| `@upstash/mcp-server` | 0.4.1 | https://github.com/upstash/mcp-server | `not_applicable` | No tool surface captured. |
| `@winor30/mcp-server-datadog` | 1.8.0 | https://github.com/winor30/mcp-server-datadog | `not_applicable` | No tool surface captured. |
| `@wonderwhy-er/desktop-commander` | 0.3.4 | https://github.com/wonderwhy-er/DesktopCommanderMCP | `not_applicable` | No tool surface captured. |
| `@xeroapi/xero-mcp-server` | 0.0.18 | git://github.com/XeroAPI/xero-mcp-server | `not_applicable` | No tool surface captured. |
| `@z_ai/mcp-server` | 0.1.6 | — | `not_applicable` | No tool surface captured. |
| `@zencoderai/slack-mcp-server` | 0.0.1 | https://github.com/zencoderai/slack-mcp-server | `not_applicable` | No tool surface captured. |
| `3dcitydb-mcp-server` | 1.2.2 | https://github.com/tum-gis/3dcitydb-mcp-server | `not_applicable` | No tool surface captured. |
| `a-stock-mcp-server` | 1.1.1 | https://github.com/Llldmiao/a-stock-mcp-server | `not_applicable` | No tool surface captured. |
| `a2a-mcp-server` | 0.1.5 | https://github.com/GongRzhe/A2A-MCP-Server | `no_finding` | Clean under the pinned detectors. |
| `a2a-protocol-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/a2a-protocol-mcp-server | `not_applicable` | No tool surface captured. |
| `a3m-mcp-server` | 1.0.0 | https://github.com/Das-rebel/a3m-router | `not_applicable` | No tool surface captured. |
| `aa-mcp-server` | 0.1.0 | https://github.com/thehesiod/aa-mcp | `not_applicable` | No tool surface captured. |
| `aapt-mcp-server` | 1.0.0 | — | `not_applicable` | No tool surface captured. |
| `aas-mcp-server` | 0.3.0 | https://github.com/SAP/aas-mcp-server | `not_applicable` | No tool surface captured. |
| `abacum-mcp-server` | 0.1.7.post1 | https://abacum.ai | `not_applicable` | No tool surface captured. |
| `ableton-live-mcp-server` | 0.2.1 | https://github.com/mrmos/ableton-live-mcp-server | `not_applicable` | No tool surface captured. |
| `ableton-mcp-server` | 0.1.0 | https://github.com/ldraney/ableton-mcp | `not_applicable` | No tool surface captured. |
| `abraflexi-mcp-server` | 1.2.4 | https://github.com/VitexSoftware/abraflexi-mcp-server | `not_applicable` | No tool surface captured. |
| `ac-mcp-server` | 0.12.0 | https://activecampaign.com | `not_applicable` | No tool surface captured. |
| `accessibility-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/accessibility-mcp-server | `not_applicable` | No tool surface captured. |
| `accounting-subject-analysis-mcp-server` | 0.1.4 | — | `not_applicable` | No tool surface captured. |
| `aceflow-mcp-server` | 3.0.2 | https://github.com/aceflow-pateoas/aceflow-ai | `not_applicable` | No tool surface captured. |
| `acex-mcp-server` | 1.1.1 | — | `not_applicable` | No tool surface captured. |
| `acli-mcp-server` | 0.1.4 | — | `not_applicable` | No tool surface captured. |
| `acp-mcp-server` | 0.0.5 | https://github.com/GongRzhe/ACP-MCP-Server | `no_finding` | Clean under the pinned detectors. |
| `action1-mcp-server` | 1.0.0 | — | `not_applicable` | No tool surface captured. |
| `actvalue.lambda-mcp-server` | 2.0.0 | https://github.com/yourusername/lambda-mcp-server | `not_applicable` | No tool surface captured. |
| `adb-mcp-server` | 1.0.0 | — | `not_applicable` | No tool surface captured. |
| `adb-mysql-mcp-server` | 2.0.0 | https://github.com/aliyun/alibabacloud-adb-mysql-mcp-server | `not_applicable` | No tool surface captured. |
| `adbpg-mcp-server` | 2.0.3 | — | `not_applicable` | No tool surface captured. |
| `add-mcp-server` | 0.1.0 | — | `not_applicable` | No tool surface captured. |
| `add-stdio-mcp-server` | 0.1.0 | — | `not_applicable` | No tool surface captured. |
| `Ai_Indeed_mcp_server` | 1.0.0 | — | `not_applicable` | No tool surface captured. |
| `BigGo-MCP-Server` | 0.2.0 | https://github.com/Funmula-Corp/BigGo-MCP-Server | `not_applicable` | No tool surface captured. |
| `ELF-mcp-server` | 1.61.0 | https://github.com/ksugahar/ELF-mcp-server | `not_applicable` | No tool surface captured. |
| `Things3-MCP-server` | 2.0.7 | https://github.com/rossshannon/things-fastmcp | `not_applicable` | No tool surface captured. |

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
