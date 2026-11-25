# Paired sample: placeholder credentials on the holdout list

The lever measured **in-sample**: the same 100 holdout targets harvested
twice, once with no credentials and once with the fixed dummy values in
`run_field_study.PLACEHOLDER_CREDENTIAL_ENV`. Same container, memory and CPU
limits, 15-second timeout, and detector fingerprint
`d7c7ff0ce5adc621958074d0afa5bf886b33bedbae79b9a6e9c5fa933acc02a4`. The target list is held fixed,
so a status change is the credential intervention, not a different pull.

The earlier `field_study/placeholder` pull is a **separate third sample**;
it is not used as evidence for the lever and its yield table does not
belong to this comparison.

## Status by arm

| Status | none | placeholder |
| ------ | ---- | ----------- |
| `harvested` | 18 | 16 |
| `missing_required_env` | 13 | 9 |
| `timeout` | 23 | 28 |
| `startup_error` | 46 | 47 |

Analyzed surfaces: 18 -> 16 (net **-2**).

## Transitions

| none \ placeholder | `harvested` | `missing_required_env` | `timeout` | `startup_error` |
| --- | --- | --- | --- | --- |
| `harvested` | 11 | 0 | 6 | 1 |
| `missing_required_env` | 2 | 8 | 3 | 0 |
| `timeout` | 2 | 1 | 15 | 5 |
| `startup_error` | 1 | 0 | 4 | 41 |

- **Newly harvested:** 5
  - `npm-contextstream-mcp-server-1-0-99` (2 tools)
  - `npm-dbx-app-mcp-server-0-4-145` (3 tools)
  - `npm-replicate-mcp-0-9-0` (35 tools)
  - `npm-thirdstrandstudio-mcp-figma-0-7-0` (31 tools)
  - `npm-zereight-mcp-gitlab-3-0-0` (40 tools)
- **Newly lost:** 7
  - `npm-knip-mcp-0-0-39` (harvested -> timeout)
  - `npm-langsmith-mcp-server-0-1-7` (harvested -> timeout)
  - `npm-mcp-searxng-2-12-0` (harvested -> timeout)
  - `npm-openbnb-mcp-server-airbnb-0-3-0` (harvested -> timeout)
  - `npm-tacitai-mcp-server-0-15-1` (harvested -> timeout)
  - `npm-transcend-io-mcp-server-docs-0-6-1` (harvested -> startup_error)
  - `npm-vizejs-musea-mcp-server-0-793-0` (harvested -> timeout)
- **Other changes:** 13
  - `npm-abhaybabbar-retellai-mcp-server-1-0-4` (missing_required_env -> timeout)
  - `npm-anyproto-anytype-mcp-2-0-3` (startup_error -> timeout)
  - `npm-aventurevc-mcp-server-0-8-498` (missing_required_env -> timeout)
  - `npm-decodo-mcp-server-1-9-0` (missing_required_env -> timeout)
  - `npm-shortcut-mcp-0-25-0` (startup_error -> timeout)
  - `npm-transcend-io-mcp-server-assessment-2-1-18` (startup_error -> timeout)
  - `npm-transcend-io-mcp-server-policy-0-2-10` (startup_error -> timeout)
  - `pypi-adls2-mcp-server-0-1-4` (timeout -> startup_error)
  - `pypi-ado-mcp-server-0-1-0` (timeout -> missing_required_env)
  - `pypi-age-mcp-server-0-3-0` (timeout -> startup_error)
  - `pypi-agent-mcp-server-0-1-1` (timeout -> startup_error)
  - `pypi-agentfactory-mcp-server-0-1-0` (timeout -> startup_error)
  - `pypi-agentops-mcp-server-0-5-4` (timeout -> startup_error)

**Net yield change: -2.** 5 package(s) that never listed tools now do; 7 that did no longer finish. A placeholder that passes a presence check can send a server into a network call that does not return inside the timeout, so part of the loss may be the credential as well, not a harness regression. One run per arm cannot separate the two.

## Findings from newly harvested packages only

95 finding(s) across 5 newly harvested package(s). Packages already harvested without credentials are excluded here; their findings are unchanged from the holdout.

| Package | Tools | Findings | Rules |
| ------- | ----- | -------- | ----- |
| `npm-contextstream-mcp-server-1-0-99` | 2 | 0 | — |
| `npm-dbx-app-mcp-server-0-4-145` | 3 | 0 | — |
| `npm-replicate-mcp-0-9-0` | 35 | 4 | `LETHAL_TRIFECTA` ×4 |
| `npm-thirdstrandstudio-mcp-figma-0-7-0` | 31 | 11 | `LETHAL_TRIFECTA` ×11 |
| `npm-zereight-mcp-gitlab-3-0-0` | 40 | 80 | `LETHAL_TRIFECTA` ×80 |

Severity: `CRITICAL` 10, `HIGH` 85.

These are target-level findings on surfaces that only existed under
placeholder credentials. They are not compositions and were not
hand-triaged here.

## Per-package status

| Package | Ecosystem | none | placeholder | Tools |
| ------- | --------- | ---- | ----------- | ----- |
| `npm-abhaybabbar-retellai-mcp-server-1-0-4` | npm | `missing_required_env` | `timeout` | — |
| `npm-agentation-mcp-1-3-2` | npm | `startup_error` | `startup_error` | — |
| `npm-amap-amap-maps-mcp-server-0-0-8` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-anyproto-anytype-mcp-2-0-3` | npm | `startup_error` | `timeout` | — |
| `npm-arabold-docs-mcp-server-3-5-0` | npm | `timeout` | `timeout` | — |
| `npm-argocd-mcp-0-9-0` | npm | `startup_error` | `startup_error` | — |
| `npm-auth0-auth0-mcp-server-0-1-0-beta-19` | npm | `startup_error` | `startup_error` | — |
| `npm-aventurevc-mcp-server-0-8-498` | npm | `missing_required_env` | `timeout` | — |
| `npm-aws-s3-mcp-0-4-0` | npm | `timeout` | `timeout` | — |
| `npm-battlegrid-mcp-server-32-0-115` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-bit2me-mcp-server-4-5-2` | npm | `startup_error` | `startup_error` | — |
| `npm-browsermcp-mcp-2-5-0` | npm | `harvested` | `harvested` | 1 -> 1 |
| `npm-clipform-mcp-server-5-17-0` | npm | `harvested` | `harvested` | 32 -> 32 |
| `npm-cloudflare-mcp-server-cloudflare-0-2-0` | npm | `startup_error` | `startup_error` | — |
| `npm-cnbcool-mcp-server-0-6-7` | npm | `startup_error` | `startup_error` | — |
| `npm-contextstream-mcp-server-1-0-99` | npm | `timeout` | `harvested` | — |
| `npm-datadog-mcp-server-1-0-9` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-dataforseo-mcp-server-3-1-3` | npm | `timeout` | `timeout` | — |
| `npm-dbx-app-mcp-server-0-4-145` | npm | `timeout` | `harvested` | — |
| `npm-decodo-mcp-server-1-9-0` | npm | `missing_required_env` | `timeout` | — |
| `npm-dopplerhq-mcp-server-1-0-5` | npm | `timeout` | `timeout` | — |
| `npm-esaio-esa-mcp-server-0-15-2` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-gongrzhe-server-gmail-autoauth-mcp-1-1-11` | npm | `timeout` | `timeout` | — |
| `npm-graphlit-mcp-server-1-0-20260112001` | npm | `timeout` | `timeout` | — |
| `npm-hourei-mcp-server-1-0-6` | npm | `harvested` | `harvested` | 3 -> 3 |
| `npm-hugeicons-mcp-server-0-4-1` | npm | `harvested` | `harvested` | 6 -> 6 |
| `npm-kintone-mcp-server-1-11-4` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-knip-mcp-0-0-39` | npm | `harvested` | `timeout` | — |
| `npm-kubernetes-mcp-server-linux-amd64-0-1-3` | npm | `startup_error` | `startup_error` | — |
| `npm-langsmith-mcp-server-0-1-7` | npm | `harvested` | `timeout` | — |
| `npm-mastra-mcp-docs-server-1-3-15` | npm | `timeout` | `timeout` | — |
| `npm-mcp-searxng-2-12-0` | npm | `harvested` | `timeout` | — |
| `npm-mcp-server-code-runner-0-1-8` | npm | `harvested` | `harvested` | 1 -> 1 |
| `npm-modelcontextprotocol-server-pdf-2-0-4` | npm | `timeout` | `timeout` | — |
| `npm-mongodb-js-mcp-tools-atlas-3-4-0` | npm | `startup_error` | `startup_error` | — |
| `npm-mongodb-mcp-server-3-4-0` | npm | `timeout` | `timeout` | — |
| `npm-near-mcp-aitp-mcp-server-0-1-34` | npm | `timeout` | `timeout` | — |
| `npm-nexus2520-bitbucket-mcp-server-4-0-0` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-onozaty-redmine-mcp-server-1-4-0` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-openbnb-mcp-server-airbnb-0-3-0` | npm | `harvested` | `timeout` | — |
| `npm-replicate-mcp-0-9-0` | npm | `startup_error` | `harvested` | — |
| `npm-sap-mdk-mcp-server-0-4-4` | npm | `timeout` | `timeout` | — |
| `npm-shortcut-mcp-0-25-0` | npm | `startup_error` | `timeout` | — |
| `npm-slite-mcp-server-1-3-0` | npm | `missing_required_env` | `missing_required_env` | — |
| `npm-smartbear-mcp-0-45-0` | npm | `timeout` | `timeout` | — |
| `npm-square-mcp-server-0-1-2` | npm | `harvested` | `harvested` | 3 -> 3 |
| `npm-storybook-mcp-10-6-8` | npm | `startup_error` | `startup_error` | — |
| `npm-structured-world-gitlab-mcp-13-5-0` | npm | `timeout` | `timeout` | — |
| `npm-tacitai-mcp-server-0-15-1` | npm | `harvested` | `timeout` | — |
| `npm-tailwindcss-mcp-server-0-1-1` | npm | `harvested` | `harvested` | 8 -> 8 |
| `npm-thesvg-mcp-server-0-9-2` | npm | `harvested` | `harvested` | 5 -> 5 |
| `npm-thirdstrandstudio-mcp-figma-0-7-0` | npm | `missing_required_env` | `harvested` | — |
| `npm-tiny-stdio-mcp-server-0-1-32` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-admin-2-1-0` | npm | `timeout` | `timeout` | — |
| `npm-transcend-io-mcp-server-assessment-2-1-18` | npm | `startup_error` | `timeout` | — |
| `npm-transcend-io-mcp-server-base-3-2-0` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-consent-1-6-0` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-custom-functions-0-3-5` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-discovery-1-1-0` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-docs-0-6-1` | npm | `harvested` | `startup_error` | — |
| `npm-transcend-io-mcp-server-dsr-2-2-0` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-inventory-1-2-0` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-policy-0-2-10` | npm | `startup_error` | `timeout` | — |
| `npm-transcend-io-mcp-server-preferences-0-9-0` | npm | `startup_error` | `startup_error` | — |
| `npm-transcend-io-mcp-server-workflows-1-2-0` | npm | `startup_error` | `startup_error` | — |
| `npm-vizejs-musea-mcp-server-0-793-0` | npm | `harvested` | `timeout` | — |
| `npm-voltagent-mcp-server-2-2-0` | npm | `startup_error` | `startup_error` | — |
| `npm-vouchington-mcp-server-0-2-0` | npm | `startup_error` | `startup_error` | — |
| `npm-wikipedia-mcp-1-0-3` | npm | `harvested` | `harvested` | 2 -> 2 |
| `npm-zereight-mcp-gitlab-3-0-0` | npm | `missing_required_env` | `harvested` | — |
| `pypi-adls2-mcp-server-0-1-4` | pypi | `timeout` | `startup_error` | — |
| `pypi-ado-mcp-server-0-1-0` | pypi | `timeout` | `missing_required_env` | — |
| `pypi-adversary-mcp-server-1-11-1` | pypi | `timeout` | `timeout` | — |
| `pypi-adx-mcp-server-1-1-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-age-mcp-server-0-3-0` | pypi | `timeout` | `startup_error` | — |
| `pypi-agent-analytics-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-commerce-mcp-server-0-1-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-coordination-mcp-server-0-1-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-cost-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-directory-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-feedback-mcp-server-0-1-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-identity-mcp-server-0-1-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-insurance-mcp-server-0-2-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-mcp-server-0-1-1` | pypi | `timeout` | `startup_error` | — |
| `pypi-agent-memory-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-reputation-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-staking-mcp-server-0-1-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-tasker-mcp-server-1-0-1` | pypi | `harvested` | `harvested` | 2 -> 2 |
| `pypi-agent-toolkit-mcp-server-0-4-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-validator-mcp-server-0-1-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agent-workflow-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agentauth-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agentbridge-mcp-server-0-1-1` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agentfactory-mcp-server-0-1-0` | pypi | `timeout` | `startup_error` | — |
| `pypi-agentic-mcp-server-0-1-1` | pypi | `harvested` | `harvested` | 9 -> 9 |
| `pypi-agentmesh-mcp-server-3-7-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agentoath-mcp-server-0-2-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agentops-mcp-server-0-5-4` | pypi | `timeout` | `startup_error` | — |
| `pypi-agentskills-mcp-server-0-7-0` | pypi | `startup_error` | `startup_error` | — |
| `pypi-agentsphere-mcp-server-1-9-1` | pypi | `startup_error` | `startup_error` | — |

## Limits

- **In-sample, one run per arm.** The comparison holds the target list
  fixed but not the network or the registry state; a package that times
  out can be a transient install or a server waiting on a placeholder
  token to reach a service that never answers.
- **Placeholder is not authentication.** A server that validates its
  token still never lists tools, so the treatment arm stays biased
  toward presence-only startup checks.
- **Not a rate and not recall.** 100 packages from one discovery query,
  no known hostile target.
- **Baseline captures predate the `credential_mode` field.** They were
  harvested with no credentials and are treated as `none` here.
