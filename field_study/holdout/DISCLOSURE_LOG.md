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
| `@abhaybabbar/retellai-mcp-server` | 1.0.4 | https://github.com/abhaybabbar/retellai-mcp-server | `not_applicable` | No tool surface captured. |
| `agentation-mcp` | 1.3.2 | — | `not_applicable` | No tool surface captured. |
| `@amap/amap-maps-mcp-server` | 0.0.8 | — | `not_applicable` | No tool surface captured. |
| `@anyproto/anytype-mcp` | 2.0.3 | https://github.com/anyproto/anytype-mcp | `not_applicable` | No tool surface captured. |
| `@arabold/docs-mcp-server` | 3.5.0 | https://github.com/arabold/docs-mcp-server | `not_applicable` | No tool surface captured. |
| `argocd-mcp` | 0.9.0 | https://github.com/argoproj-labs/mcp-for-argocd | `not_applicable` | No tool surface captured. |
| `@auth0/auth0-mcp-server` | 0.1.0-beta.19 | https://github.com/auth0/auth0-mcp-server | `not_applicable` | No tool surface captured. |
| `@aventurevc/mcp-server` | 0.8.498 | https://github.com/aventurevc/aventure-mcp | `not_applicable` | No tool surface captured. |
| `aws-s3-mcp` | 0.4.0 | https://github.com/samuraikun/aws-s3-mcp | `not_applicable` | No tool surface captured. |
| `@battlegrid/mcp-server` | 32.0.115 | https://github.com/playbattlegrid/battlegrid-mcp | `not_applicable` | No tool surface captured. |
| `@bit2me/mcp-server` | 4.5.2 | https://github.com/bit2me-devs/bit2me-mcp | `not_applicable` | No tool surface captured. |
| `@browsermcp/mcp` | 2.5.0 | https://github.com/BrowserMCP/mcp | `no_finding` | Clean under the pinned detectors. |
| `@clipform/mcp-server` | 5.17.0 | https://github.com/clipform/mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@cloudflare/mcp-server-cloudflare` | 0.2.0 | — | `not_applicable` | No tool surface captured. |
| `@cnbcool/mcp-server` | 0.6.7 | https://cnb.cool/cnb/tools/cnb-mcp-server | `not_applicable` | No tool surface captured. |
| `@contextstream/mcp-server` | 1.0.99 | https://github.com/contextstream/mcp-server | `not_applicable` | No tool surface captured. |
| `datadog-mcp-server` | 1.0.9 | https://github.com/GeLi2001/datadog-mcp-server | `not_applicable` | No tool surface captured. |
| `dataforseo-mcp-server` | 3.1.3 | https://github.com/dataforseo/mcp-server-typescript | `not_applicable` | No tool surface captured. |
| `@dbx-app/mcp-server` | 0.4.145 | https://github.com/t8y2/dbx | `not_applicable` | No tool surface captured. |
| `@decodo/mcp-server` | 1.9.0 | https://github.com/Decodo/mcp-server | `not_applicable` | No tool surface captured. |
| `@dopplerhq/mcp-server` | 1.0.5 | https://github.com/DopplerHQ/mcp-server | `not_applicable` | No tool surface captured. |
| `@esaio/esa-mcp-server` | 0.15.2 | https://github.com/esaio/esa-mcp-server | `not_applicable` | No tool surface captured. |
| `@gongrzhe/server-gmail-autoauth-mcp` | 1.1.11 | https://github.com/gongrzhe/server-gmail-autoauth-mcp | `not_applicable` | No tool surface captured. |
| `graphlit-mcp-server` | 1.0.20260112001 | https://github.com/graphlit/graphlit-mcp-server | `not_applicable` | No tool surface captured. |
| `hourei-mcp-server` | 1.0.6 | https://github.com/groundcobra009/hourei-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@hugeicons/mcp-server` | 0.4.1 | https://github.com/hugeicons/hugeicons | `no_finding` | Clean under the pinned detectors. |
| `@kintone/mcp-server` | 1.11.4 | https://github.com/kintone/mcp-server | `not_applicable` | No tool surface captured. |
| `@knip/mcp` | 0.0.39 | https://github.com/webpro-nl/knip | `no_finding` | Clean under the pinned detectors. |
| `kubernetes-mcp-server-linux-amd64` | 0.1.3 | https://github.com/containers/kubernetes-mcp-server | `not_applicable` | No tool surface captured. |
| `langsmith-mcp-server` | 0.1.7 | — | `no_finding` | Clean under the pinned detectors. |
| `@mastra/mcp-docs-server` | 1.3.15 | https://github.com/mastra-ai/mastra | `not_applicable` | No tool surface captured. |
| `mcp-searxng` | 2.12.0 | https://github.com/ihor-sokoliuk/mcp-searxng | `no_finding` | Clean under the pinned detectors. |
| `mcp-server-code-runner` | 0.1.8 | https://github.com/formulahendry/mcp-server-code-runner | `no_finding` | Clean under the pinned detectors. |
| `@modelcontextprotocol/server-pdf` | 2.0.4 | https://github.com/modelcontextprotocol/ext-apps | `not_applicable` | No tool surface captured. |
| `@mongodb-js/mcp-tools-atlas` | 3.4.0 | https://github.com/mongodb-js/mongodb-mcp-server | `not_applicable` | No tool surface captured. |
| `mongodb-mcp-server` | 3.4.0 | https://github.com/mongodb-js/mongodb-mcp-server | `not_applicable` | No tool surface captured. |
| `@near-mcp/aitp-mcp-server` | 0.1.34 | — | `not_applicable` | No tool surface captured. |
| `@nexus2520/bitbucket-mcp-server` | 4.0.0 | https://github.com/pdogra1299/bitbucket-mcp-server | `not_applicable` | No tool surface captured. |
| `@onozaty/redmine-mcp-server` | 1.4.0 | https://github.com/onozaty/redmine-mcp-server | `not_applicable` | No tool surface captured. |
| `@openbnb/mcp-server-airbnb` | 0.3.0 | — | `no_finding` | Clean under the pinned detectors. |
| `replicate-mcp` | 0.9.0 | https://github.com/replicate/replicate-typescript-stainless | `not_applicable` | No tool surface captured. |
| `@sap/mdk-mcp-server` | 0.4.4 | https://github.com/SAP/mdk-mcp-server | `not_applicable` | No tool surface captured. |
| `@shortcut/mcp` | 0.25.0 | https://github.com/useshortcut/mcp-server-shortcut | `not_applicable` | No tool surface captured. |
| `slite-mcp-server` | 1.3.0 | — | `not_applicable` | No tool surface captured. |
| `@smartbear/mcp` | 0.45.0 | https://github.com/SmartBear/smartbear-mcp | `not_applicable` | No tool surface captured. |
| `square-mcp-server` | 0.1.2 | — | `no_finding` | Clean under the pinned detectors. |
| `@storybook/mcp` | 10.6.8 | https://github.com/storybookjs/storybook | `not_applicable` | No tool surface captured. |
| `@structured-world/gitlab-mcp` | 13.5.0 | https://github.com/structured-world/gitlab-mcp | `not_applicable` | No tool surface captured. |
| `@tacitai/mcp-server` | 0.15.1 | https://github.com/scottkmcmillan/tacit | `no_finding` | Clean under the pinned detectors. |
| `tailwindcss-mcp-server` | 0.1.1 | https://github.com/CarbonoDev/tailwindcss-mcp-server | `no_finding` | Clean under the pinned detectors. |
| `@thesvg/mcp-server` | 0.9.2 | https://github.com/glincker/thesvg | `no_finding` | Clean under the pinned detectors. |
| `@thirdstrandstudio/mcp-figma` | 0.7.0 | — | `not_applicable` | No tool surface captured. |
| `tiny-stdio-mcp-server` | 0.1.32 | https://github.com/poe-platform/poe-code | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-admin` | 2.1.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-assessment` | 2.1.18 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-base` | 3.2.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-consent` | 1.6.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-custom-functions` | 0.3.5 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-discovery` | 1.1.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-docs` | 0.6.1 | https://github.com/transcend-io/tools | `no_finding` | Clean under the pinned detectors. |
| `@transcend-io/mcp-server-dsr` | 2.2.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-inventory` | 1.2.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-policy` | 0.2.10 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-preferences` | 0.9.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@transcend-io/mcp-server-workflows` | 1.2.0 | https://github.com/transcend-io/tools | `not_applicable` | No tool surface captured. |
| `@vizejs/musea-mcp-server` | 0.793.0 | https://github.com/ubugeeei-prod/vize | `no_finding` | Clean under the pinned detectors. |
| `@voltagent/mcp-server` | 2.2.0 | https://github.com/VoltAgent/voltagent | `not_applicable` | No tool surface captured. |
| `@vouchington/mcp-server` | 0.2.0 | https://github.com/vouchington/vouchington-platform | `not_applicable` | No tool surface captured. |
| `wikipedia-mcp` | 1.0.3 | — | `no_finding` | Clean under the pinned detectors. |
| `@zereight/mcp-gitlab` | 3.0.0 | https://github.com/zereight/gitlab-mcp | `not_applicable` | No tool surface captured. |
| `adls2-mcp-server` | 0.1.4 | https://github.com/erikhoward/adls-mcp-server | `not_applicable` | No tool surface captured. |
| `ado-mcp-server` | 0.1.0 | https://github.com/viseshrp/ado-mcp | `not_applicable` | No tool surface captured. |
| `adversary-mcp-server` | 1.11.1 | https://github.com/brettbergin/adversary-mcp-server | `not_applicable` | No tool surface captured. |
| `adx-mcp-server` | 1.1.0 | — | `not_applicable` | No tool surface captured. |
| `age_mcp_server` | 0.3.0 | https://github.com/rioriost/age_mcp_server | `not_applicable` | No tool surface captured. |
| `agent-analytics-mcp-server` | 0.1.1 | https://github.com/AiAgentKarl/agent-analytics-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-commerce-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/agent-commerce-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-coordination-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/agent-coordination-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-cost-mcp-server` | 0.1.1 | — | `not_applicable` | No tool surface captured. |
| `agent-directory-mcp-server` | 0.1.1 | https://github.com/AiAgentKarl/agent-directory-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-feedback-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/agent-feedback-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-identity-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/agent-identity-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-insurance-mcp-server` | 0.2.0 | https://github.com/AiAgentKarl/agent-insurance-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-mcp-server` | 0.1.1 | https://codeup.aliyun.com/64650c96168f0a5963451dec/lib/agent-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-memory-mcp-server` | 0.1.1 | https://github.com/AiAgentKarl/agent-memory-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-reputation-mcp-server` | 0.1.1 | https://github.com/AiAgentKarl/agent-reputation-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-staking-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/agent-staking-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-tasker-mcp-server` | 1.0.1 | https://github.com/S3bRR/agent-tasker-mcp | `no_finding` | Clean under the pinned detectors. |
| `agent-toolkit-mcp-server` | 0.4.0 | https://github.com/PaperBackPear3/awesome-agent-toolkits | `not_applicable` | No tool surface captured. |
| `agent-validator-mcp-server` | 0.1.0 | https://github.com/AiAgentKarl/agent-validator-mcp-server | `not_applicable` | No tool surface captured. |
| `agent-workflow-mcp-server` | 0.1.1 | https://github.com/AiAgentKarl/agent-workflow-mcp-server | `not_applicable` | No tool surface captured. |
| `agentauth-mcp-server` | 0.1.1 | https://github.com/radi-totev/agent-auth | `not_applicable` | No tool surface captured. |
| `agentbridge-mcp-server` | 0.1.1 | — | `not_applicable` | No tool surface captured. |
| `agentfactory-mcp-server` | 0.1.0 | — | `not_applicable` | No tool surface captured. |
| `agentic_mcp_server` | 0.1.1 | — | `no_finding` | Clean under the pinned detectors. |
| `agentmesh-mcp-server` | 3.7.0 | https://github.com/microsoft/agent-governance-toolkit | `not_applicable` | No tool surface captured. |
| `agentoath-mcp-server` | 0.2.0 | https://github.com/AgentOath/agentoath | `not_applicable` | No tool surface captured. |
| `agentops-mcp-server` | 0.5.4 | https://github.com/rioriost/agentops_mcp_server | `not_applicable` | No tool surface captured. |
| `agentskills-mcp-server` | 0.7.0 | https://github.com/pratikxpanda/agentskills-sdk | `not_applicable` | No tool surface captured. |
| `agentsphere-mcp-server` | 1.9.1 | https://www.agentsphere.run/home | `not_applicable` | No tool surface captured. |

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
