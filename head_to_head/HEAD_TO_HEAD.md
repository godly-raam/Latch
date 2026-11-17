# mcpprobe (Latch): measured real-package comparison

**`mcpprobe` is the project and CLI name; `Latch` is its subtitle.**
It is unrelated to `AgentLatch` (`AgentLatch/agent-latch`), a Python
source scanner, and to unrelated `latch` packages on PyPI/npm.

The headline is the measured comparison below: every scanner was run
against the same real upstream `tools/list` captures in
[`package_eval/captured_manifests/`](../package_eval/captured_manifests/).
The self-authored protocol scenarios are demoted to an appendix, because
they demonstrate rule coverage rather than generalization.

## Headline: measured on real captured packages

| Scanner | Clean-package FPR | In-model real targets | Evidence |
| ------- | ----------------- | --------------------- | -------- |
| **mcpprobe (Latch)** | 0.20 (1/5) | 2/2 | measured |
| Naive keyword/substring baseline | 0.80 (4/5) | not applicable | measured |
| `mcp-scan` (`snyk-agent-scan`) | n/a | n/a | installed (v0.6.11), requires `SNYK_TOKEN` |
| `AgentLatch` (`agent-latch`) | n/a | n/a | architecture comparison only (not installed) |

## Real captured packages

All 9 upstream captures from
[`package_eval/captured_manifests/`](../package_eval/captured_manifests/),
unmodified. The `mcp-scan` column is only filled when that scanner
produced a parseable live verdict.

| Package | Version | Tools | mcpprobe (Latch) | Latch rules | Naive | mcp-scan |
| ------- | ------- | ----- | ---------------- | ----------- | ----- | -------- |
| `mcp-remote` | 0.14.3 | 0 | flagged | INSECURE_HTTP_AUTH_TRANSPORT | flagged | — |
| `@modelcontextprotocol/server-everything` | 2.3.0 | 22 | flagged | ANNOTATION_CONTRADICTION, LETHAL_TRIFECTA | flagged | — |
| `@modelcontextprotocol/server-filesystem` | 0.6.2 | 9 | clean | — | flagged | — |
| `@modelcontextprotocol/server-filesystem` | 2.3.0 | 16 | clean | — | flagged | — |
| `@modelcontextprotocol/server-memory` | 2.1.1 | 9 | clean | — | clean | — |
| `mcp-proxy` | 0.8.2 | 0 | flagged | INSECURE_HTTP_AUTH_TRANSPORT | flagged | — |
| `mcp-server-fetch` | 2026.11.11 | 1 | clean | — | flagged | — |
| `mcp-server-git` | 2025.9.25 | 12 | clean | — | flagged | — |
| `mcp-server-git` | 2026.11.11 | 14 | clean | — | flagged | — |

On the 5 clean packages, mcpprobe (Latch) flags 1 (FPR 0.20); the naive baseline flags 4 (FPR 0.80). The Latch flag is the SDK diagnostics server, whose generic read/egress heuristics produce a documented static over-approximation.

In-model real targets detected: `npm-mcp-remote-0-14-3`, `pypi-mcp-proxy-0-8-2`. Handler-level CVEs in the corpus are outside a `tools/list` threat model and are scored as misses in [`package_eval/PACKAGE_EVAL_REPORT.md`](../package_eval/PACKAGE_EVAL_REPORT.md).

## Peer scanner: `mcp-scan` (`snyk-agent-scan`)

- Installed distribution: `snyk-agent-scan` `0.6.11`
- Exit status: `credentials_required` (`snyk-agent-scan requires SNYK_TOKEN; no token is present`)
- Exit code: `1`
- Remote analysis required: `True` -> `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10`
- Exact invocation:

```console
snyk-agent-scan scan <temp>/mcp-scan-config.json --json --no-skills --dangerously-run-mcp-servers --suppress-mcpserver-io true --storage-file <temp>/scan-state.json
```

This environment could not obtain a **measured** peer verdict. Current `snyk-agent-scan` releases require a `SNYK_TOKEN` account credential and perform deep analysis on Snyk's endpoint, so with no token the CLI stops before scanning and emits no findings. That is recorded exactly as observed instead of being reported as a clean scan or a detection. Set `SNYK_TOKEN` and re-run `python -m head_to_head.run_comparison` to replace this row with measured output; the runner caches the result keyed by scanner version, capture digests and token presence.

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

- `mcp-scan` was **invoked, not measured**. Its CLI requires an
  account token and performs deep analysis on a Snyk endpoint, so the
  recorded row proves the installation, the version and the exact
  invocation -- not a false-positive rate. It is neither a clean scan
  nor a detection.
- `agent-latch` was **not exercised at all**: its row is an
  `architectural_comparison_only` documentation comparison, and a
  documentation comparison cannot prove a detection either way.
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
| RFC 9728 protected-resource metadata mismatch (`rfc9728_prm_resource_mismatch`) | `auth` | detected | auth-audit:PRM_RESOURCE_MISMATCH | detected |
| Cross-server Bearer token reuse (`cross_server_bearer_reuse`) | `auth` | detected | auth-audit:CROSS_SERVER_CREDENTIAL_REUSE, auth-audit:HARDCODED_STATIC_CREDENTIAL | detected |

Feature coverage: Latch fires on 10/10 self-authored scenarios (1.00); the naive baseline fires on 7/10 (0.70).
