# mcpprobe (Latch): measured real-package comparison

**`mcpprobe` is the project and CLI name; `Latch` is its subtitle.**
It is unrelated to `AgentLatch` (`AgentLatch/agent-latch`), a Python
source scanner, and to unrelated `latch` packages on PyPI/npm.

The headline is the measured comparison below: every scanner was run
against the same real upstream `tools/list` captures in
[`package_eval/captured_manifests/`](../package_eval/captured_manifests/).
The self-authored protocol scenarios are demoted to an appendix, because
they demonstrate rule coverage rather than generalization.

## Two evaluation stages, side by side

The corpus grew and the vocabulary changed in the same commit
(`4a089e1`), so the two stages are reported separately instead of being
blended into one headline.

| Stage | Corpus | Clean-package FPR | In-scope real-target recall | Overall real-target recall |
| ----- | ------ | ----------------- | --------------------------- | -------------------------- |
| **First-Run Blind Baseline** (pre-`4a089e1` rules) | 9 packages (5 clean) | 0.20 (1/5) | 0.67 (2/3) | 0.40 (2/5) |
| **Post-Tuning Corpus** (post-`4a089e1` vocabulary) | 14 packages (6 clean) | 0.17 (1/6) | 0.88 (7/8) | 0.70 (7/10) |

- **`0.20` / `0.67` is the only blind row.** The nine-package run was
  scored on an untouched engine before `4a089e1`; it is recorded, not
  recomputed, because the pre-tuning classifier no longer exists.
- **`0.17` / `0.88` is regression evidence, not blind evidence.**
  `4a089e1` added five packages and the `navigate` egress verb, which is
  what makes target D (`@modelcontextprotocol/server-puppeteer@2025.5.12
  + `@modelcontextprotocol/server-filesystem@2.3.0`) visible:
  **Detected (post-tuning: "navigate" added to egress vocabulary in
  `4a089e1`; would have missed on first run)**.
- **GitHub and Slack are known-class manifest checks, not
  generalization proof.**
  `@modelcontextprotocol/server-github@2025.4.8` and
  `@modelcontextprotocol/server-slack@2025.4.25` were chosen from
  capability classes the engine was already built to detect
  (`get_issue` / `get_file_contents` / `create_issue` and
  `get_channel_history` / `post_message`). Detecting them confirms the
  rules fire on real upstream manifests; it says nothing about servers
  nobody inspected.
- **Unseen-server recall is unmeasured.** Only the
  **First-Run Blind Baseline (9 packages)** and the **Wave 2
  Author-Blind Suite (`0.42` recall)** are pre-tuning runs, and both were
  authored by this project.

## Headline: measured on real captured packages

The headline row below is the **Post-Tuning Corpus** stage; the
nine-package blind baseline is the row above.

| Scanner | Stage | Clean-package FPR | In-scope real targets | Evidence |
| ------- | ----- | ----------------- | --------------------- | -------- |
| **mcpprobe (Latch)** | Post-tuning | 0.17 (1/6) | 0.88 (7/8) | measured |
| Naive keyword/substring baseline | Post-tuning | 0.83 (5/6) | not applicable | measured |
| `mcp-scan` (`snyk-agent-scan`) | Post-tuning | n/a (429 public API daily limit reached) | n/a | ran (v0.6.11), 429 public API daily limit reached |
| `AgentLatch` (`agent-latch`) | Post-tuning | n/a | n/a | architecture comparison only (not installed) |

The `0.88` (`7/8`) denominator is every in-scope target: the six single-capture package targets above plus the two cross-server compositions (`D` detected, `B` missed). Narrowed to package manifests only, the same run is `6/6`. The first-run blind row for that denominator is `0.67` (`2/3`): `mcp-remote` and `mcp-proxy` were caught, `B` was missed then too.

## Real captured packages

All 14 upstream captures from
[`package_eval/captured_manifests/`](../package_eval/captured_manifests/),
unmodified. The `mcp-scan` column is only filled when that scanner
produced a parseable live verdict.

| Package | Version | Tools | mcpprobe (Latch) | Latch rules | Naive | mcp-scan |
| ------- | ------- | ----- | ---------------- | ----------- | ----- | -------- |
| `mcp-remote` | 0.14.3 | 0 | flagged | HARDCODED_STATIC_CREDENTIAL | flagged | — |
| `mcp-remote` | 0.14.3 | 0 | flagged | INSECURE_HTTP_AUTH_TRANSPORT | flagged | — |
| `@modelcontextprotocol/server-everything` | 2.3.0 | 22 | flagged | ANNOTATION_CONTRADICTION, LETHAL_TRIFECTA | flagged | — |
| `@modelcontextprotocol/server-filesystem` | 0.6.2 | 9 | clean | — | flagged | — |
| `@modelcontextprotocol/server-filesystem` | 2.3.0 | 16 | clean | — | flagged | — |
| `@modelcontextprotocol/server-github` | 2025.4.8 | 26 | flagged | LETHAL_TRIFECTA | flagged | — |
| `@modelcontextprotocol/server-memory` | 2.1.1 | 9 | clean | — | clean | — |
| `@modelcontextprotocol/server-puppeteer` | 2025.5.12 | 7 | clean | — | flagged | — |
| `@modelcontextprotocol/server-slack` | 2025.4.25 | 8 | flagged | LETHAL_TRIFECTA | clean | — |
| `supergateway` | 3.1.0 | 0 | flagged | INSECURE_HTTP_AUTH_TRANSPORT | flagged | — |
| `mcp-proxy` | 0.8.2 | 0 | flagged | INSECURE_HTTP_AUTH_TRANSPORT | flagged | — |
| `mcp-server-fetch` | 2026.11.11 | 1 | clean | — | flagged | — |
| `mcp-server-git` | 2025.9.25 | 12 | clean | — | flagged | — |
| `mcp-server-git` | 2026.11.11 | 14 | clean | — | flagged | — |

On the 6 clean packages, mcpprobe (Latch) flags 1 (FPR 0.17); the naive baseline flags 5 (FPR 0.83). The Latch flag is the SDK diagnostics server, whose generic read/egress heuristics produce a documented static over-approximation.

In-model package targets detected (the `6/6` subset): `npm-mcp-remote-0-14-3`, `npm-mcp-remote-0-14-3-static-header`, `npm-server-github-2025-4-8`, `npm-server-slack-2025-4-25`, `npm-supergateway-3-1-0`, `pypi-mcp-proxy-0-8-2`. Handler-level CVEs in the corpus are outside a `tools/list` threat model and are scored as misses in [`package_eval/PACKAGE_EVAL_REPORT.md`](../package_eval/PACKAGE_EVAL_REPORT.md).

## Peer scanner: `mcp-scan` (`snyk-agent-scan`)

- Installed distribution: `snyk-agent-scan` `0.6.11`
- Exit status: `rate_limited` (`429 Daily usage limit reached on Snyk public analysis-machine API`)
- Exit code: `0`
- Remote analysis required: `True` -> `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10`
- Exact invocation:

```console
snyk-agent-scan scan <temp>/mcp-scan-config.json --json --no-skills --dangerously-run-mcp-servers --suppress-mcpserver-io true --storage-file <temp>/scan-state.json
```

The peer CLI ran and Snyk's public `analysis-machine` API answered **`429 Too Many Requests`**: the free daily quota is exhausted, so this run produced no per-package verdict. The peer has no local fallback -- `snyk-agent-scan 0.6.11` classifies every package on that remote API, which needs an account and applies a public daily limit, whereas `mcpprobe` (Latch) runs locally with neither credentials nor rate limits. No peer false-positive rate is claimed here. Re-run `python -m head_to_head.run_comparison --force-refresh` once the quota resets to replace this row with measured output.

## Architectural and detection matrix

Capabilities are taken from each project's current public
documentation. Where a project does not document a capability, the row
says so instead of assuming absence of the code.

| Capability | mcpprobe (Latch) | Invariant / Snyk mcp-scan | AgentLatch |
| ---------- | ---------------- | ------------------------- | ---------- |
| Role | Local deterministic CLI and CI verifier | CLI scanner with an optional monitoring proxy | Local-first Python AST scanner plus passive monitor-only MCP proxy |
| Schema lockfiles / pinning | Canonical SHA-256 tool lockfiles (pin/verify) | Tool pinning by description hash (rug-pull detection) | Not applicable: scans agent source, not MCP tool schemas |
| Live drift detection | list_changed watcher over stdio and Streamable HTTP | Rescan-based change detection; no persistent list_changed watcher documented | Passive proxy logs calls; no schema pinning or drift verifier |
| MCP manifest audit | MCP 2026-07-28 x-mcp-header plus Unicode Tag, bidi, variation-selector and zero-width checks | Tool-poisoning and prompt-injection checks in descriptions | Python source analysis (ast), not MCP manifest auditing |
| Cross-server chains | Capability graph with ingest -> read -> egress trifectas | Cross-origin escalation (tool shadowing) checks | No cross-server capability graph synthesis |
| Active canary probing | Execution-aware canary sink and SSRF-guard classification | Proxy observes live traffic; no canary exfiltration proof documented | Monitor-only proxy; no active canary probing |
| Tool shadowing | Exact, normalized, NFKC/homoglyph and cross-tool hijack detection | Tool shadowing and description poisoning | Not a documented MCP shadowing detector |
| OAuth 2.1 / RFC 9728 | OAuth 2.1 / RFC 9728 audit, credential reuse and token passthrough | Not documented as an RFC 9728 / OAuth metadata auditor | Masks secrets in passive call logs; no RFC 9728 probing |
| CI output | SARIF 2.1.0 plus text/JSON, exit codes for CI | CLI output; experimental and subject to change | Local reports and logs |
| Runtime dependency | Zero LLM or cloud dependency; offline and deterministic | Sends tool names/descriptions to the Snyk/Invariant API for deep classification; requires an account token in current releases | Local-first; no cloud classification service |

Sources: mcpprobe (Latch) — this repository; Invariant / Snyk mcp-scan — https://github.com/snyk/agent-scan (formerly github.com/invariantlabs-ai/mcp-scan); AgentLatch (agent-latch) — AgentLatch/agent-latch (project README)

## Honest limits of this comparison

- `mcp-scan` is measured only through its own remote classifier:
  the CLI sends the manifests to Snyk's `analysis-machine` API
  (account token required, public daily quota) and this report parses
  that response. A row that says `measured` is the peer's verdict;
  any other status means no peer verdict exists at all, which is
  neither a clean scan nor a detection.
- `agent-latch` was **not exercised at all**: its row is an
  `architectural_comparison_only` documentation comparison, and a
  documentation comparison cannot prove a detection either way.
- The fourteen-package row is not blind: `4a089e1` added five
  packages and the `navigate` egress verb, and target D would have
  been missed before it. Only the nine-package First-Run Blind
  Baseline and the Wave 2 author-blind suite (`0.42` recall) predate
  the tuning.
- GitHub and Slack were selected from capability classes the engine
  already models, so their detection is a known-class manifest check
  rather than evidence that recall generalizes. Recall on unseen
  third-party servers remains unmeasured.
- The ten scenarios are canonical shapes written alongside the rules,
  not a random sample: they verify rule wiring (see the appendix) and
  say nothing about generalization. The measurement this project is
  still missing is an independent 10-probe submission through
  [`adversarial/EXTERNAL_REDTEAM_BRIEF.md`](../adversarial/EXTERNAL_REDTEAM_BRIEF.md).
- `mcpprobe` (Latch) is measured on the same frozen captures as
  [`package_eval`](../package_eval/PACKAGE_EVAL_REPORT.md), including the
  diagnostics-server false positive, which is not excused here.

## Appendix: Self-Authored Protocol Feature Coverage Demo (10/10)

> **Self-Authored Protocol Feature Demo (10/10 — Feature Coverage
> Check, Not a Generalization Benchmark).** These ten scenarios were
> written by this project alongside the engines they exercise. A
> `10/10` here verifies that each shipped rule is wired and fires; it
> is not a random sample of real-world attacks and must not be read
> as a detection rate. The measured evidence is the real-package
> comparison above and
> [`package_eval/PACKAGE_EVAL_REPORT.md`](../package_eval/PACKAGE_EVAL_REPORT.md).

| Scenario | Category | Latch | Rules | Naive |
| -------- | -------- | ----- | ----- | ----- |
| Post-approval schema rug pull (`post_approval_schema_rug_pull`) | `drift` | detected | verify:MODIFIED_TOOL | detected |
| notifications/tools/list_changed mid-session drift (`live_list_changed_drift`) | `drift` | detected | watch:MODIFIED_TOOL | missed |
| Unicode Tag-block instruction smuggling (`unicode_tag_smuggling`) | `manifest_text` | detected | audit:UNICODE_TAG_BLOCK | detected |
| MCP 2026-07-28 x-mcp-header bound to Authorization (`x_mcp_header_authorization`) | `manifest_text` | detected | audit:HEADER_PRIVILEGED_INJECTION | detected |
| Cyrillic homoglyph tool shadowing (`cyrillic_homoglyph_shadow`) | `shadowing` | detected | shadow:CONFUSABLE_UNICODE_SHADOW | missed |
| Cross-tool routing hijack (`cross_tool_hijack`) | `shadowing` | detected | shadow:CROSS_TOOL_HIJACK | detected |
| Cross-server lethal trifecta (`cross_server_lethal_trifecta`) | `capability_graph` | detected | graph:LETHAL_TRIFECTA | detected |
| Runtime SSRF-guarded vs confirmed canary exfiltration (`runtime_ssrf_guard_vs_confirmed_exfil`) | `runtime` | detected | probe-chain:CONFIRMED_EXPLOITABLE, probe-chain:UNCONFIRMED_SSRF_GUARD | missed |
| RFC 9728 protected-resource metadata mismatch (`rfc9728_prm_resource_mismatch`) | `auth` | detected | auth-audit:CROSS_ORIGIN_RESOURCE_METADATA, auth-audit:MISSING_PROTECTED_RESOURCE_METADATA | detected |
| Cross-server Bearer token reuse (`cross_server_bearer_reuse`) | `auth` | detected | auth-audit:CROSS_SERVER_CREDENTIAL_REUSE, auth-audit:HARDCODED_STATIC_CREDENTIAL | detected |

Feature coverage: Latch fires on 10/10 self-authored scenarios (1.00); the naive baseline fires on 7/10 (0.70).
