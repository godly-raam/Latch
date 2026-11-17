# Head-to-head: Latch vs naive baseline vs documented peers

Two scanners ran **live** on this machine: `Latch (mcpprobe)` and the
naive keyword/substring baseline. `mcp-scan` and `agent-latch` were
not installed, so their columns below are the **documented architecture**
of each tool (with sources), not measured detections.

| Tool | Live in this environment? |
| ---- | ------------------------ |
| `mcp-scan` | not installed (`shutil.which` returned nothing) |
| `agent-latch` | not installed (`shutil.which` returned nothing) |

## Real captured packages

All 9 upstream captures from
[`package_eval/captured_manifests/`](../package_eval/captured_manifests/),
unmodified.

| Package | Version | Tools | Latch | Latch rules | Naive | Naive hits |
| ------- | ------- | ----- | ----- | ----------- | ----- | ---------- |
| `mcp-remote` | 0.14.3 | 0 | flagged | INSECURE_HTTP_AUTH_TRANSPORT | flagged | http:// |
| `@modelcontextprotocol/server-everything` | 2.3.0 | 22 | flagged | ANNOTATION_CONTRADICTION, LETHAL_TRIFECTA | flagged | secret, token, pass, ignore, instead, before, x-mcp-header |
| `@modelcontextprotocol/server-filesystem` | 0.6.2 | 9 | clean | — | flagged | before, http:// |
| `@modelcontextprotocol/server-filesystem` | 2.3.0 | 16 | clean | — | flagged | ignore, instead, before |
| `@modelcontextprotocol/server-memory` | 2.1.1 | 9 | clean | — | clean | — |
| `mcp-proxy` | 0.8.2 | 0 | flagged | INSECURE_HTTP_AUTH_TRANSPORT | flagged | http:// |
| `mcp-server-fetch` | 2026.11.11 | 1 | clean | — | flagged | before |
| `mcp-server-git` | 2025.9.25 | 12 | clean | — | flagged | pass |
| `mcp-server-git` | 2026.11.11 | 14 | clean | — | flagged | pass |

On the 5 clean packages, Latch flags 1 (FPR 0.20); the naive baseline flags 4 (FPR 0.80). The Latch flag is the SDK diagnostics server, whose generic read/egress heuristics produce a documented static over-approximation.

In-model real targets detected: `npm-mcp-remote-0-14-3`, `pypi-mcp-proxy-0-8-2`. Handler-level CVEs in the corpus are outside a `tools/list` threat model and are scored as misses in [`package_eval/PACKAGE_EVAL_REPORT.md`](../package_eval/PACKAGE_EVAL_REPORT.md).

## Ten canonical protocol and agentic-risk scenarios

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
| RFC 9728 protected-resource metadata mismatch (`rfc9728_prm_resource_mismatch`) | `auth` | detected | auth-audit:PRM_RESOURCE_MISMATCH | detected |
| Cross-server Bearer token reuse (`cross_server_bearer_reuse`) | `auth` | detected | auth-audit:CROSS_SERVER_CREDENTIAL_REUSE, auth-audit:HARDCODED_STATIC_CREDENTIAL | detected |

Latch detects 10/10 scenarios (1.00 recall); the naive baseline detects 7/10 (0.70).

## Architectural and detection matrix

Capabilities are taken from each project's current public
documentation. Where a project does not document a capability, the row
says so instead of assuming absence of the code.

| Capability | Latch (mcpprobe) | Invariant / Snyk mcp-scan | AgentLatch |
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

Sources: Latch (mcpprobe) — this repository; Invariant / Snyk mcp-scan — https://github.com/snyk/agent-scan (formerly github.com/invariantlabs-ai/mcp-scan); AgentLatch (agent-latch) — AgentLatch/agent-latch (project README)

## Honest limits of this comparison

- Two of the three peers were **not exercised**. Their rows are a
  documentation comparison, and a documentation comparison cannot
  prove a detection either way.
- The ten scenarios are canonical shapes, not a random sample. They
  exercise the engines Latch ships, so the recall number describes
  those shapes.
- `Latch` is measured on the same frozen captures as
  [`package_eval`](../package_eval/PACKAGE_EVAL_REPORT.md), including the
  diagnostics-server false positive, which is not excused here.

To make the peer columns measured rather than documented, install the CLIs and re-run: `python -m head_to_head.run_comparison` will record live output for any binary it finds on `PATH`.
