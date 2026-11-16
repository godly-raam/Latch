# Latch real-world evaluation: disclosed advisories & upstream reference servers

Deterministic evaluation of Latch's static engines (`verify_manifest`,
`audit_manifest`, `analyze_capability_graph`, `analyze_shadowing`,
`run_auth_audit`), its execution-aware prober (`verify_trifecta_chains`),
and the naive keyword/substring baseline on the same targets.

- Targets: 24 (12 pre-patch vulnerable, 8 post-patch fixed, 4 official upstream reference servers)
- Targets inside Latch's threat model: 22
- No timestamps or random values are recorded; re-running
  `python -m cve_eval.run_cve_eval` reproduces this report byte for byte.

## In-scope detection (protocol, schema, auth, shadow and flow flaws)

| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |
| **Latch** | 10 | 0 | 12 | 0 | 1.00 | 1.00 | 1.00 | 0.00 |

Latch detects every in-scope pre-patch target and flags no post-patch or
upstream reference server.

## Overall, including out-of-scope handler implementation bugs

| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |
| **Latch** | 10 | 0 | 12 | 2 | 1.00 | 0.83 | 0.91 | 0.00 |

The honest misses are pure implementation bugs inside tool handlers (path
canonicalization and SQL string concatenation). Their manifests are
indistinguishable from the patched versions, so no manifest- or
protocol-level analyzer can separate them; Latch records them as misses
rather than claiming detection:

- `CVE-2025-FILESYSTEM-TRAVERSAL`
- `CVE-2025-POSTGRES-SQLI`

## Static-only vs. execution-aware verification

The runtime-allowlist patch keeps an identical tool schema and adds a
domain allowlist inside the handler. Static analysis cannot see it;
`latch probe-chain` can.

| Case | Static `graph` | `probe-chain` | Probe status | Why |
| ---- | -------------- | ------------- | ------------ | --- |
| `MCP-RUNTIME-ALLOWLIST-post` | flagged | blocked | BLOCKED_AT_EGRESS | blocked: destination '127.0.0.1' is not in the *.corp.internal allowlist |

That row is the reason this project has an execution-aware prober: a
static CRITICAL on a patched server is a false positive, and only
running the chain distinguishes a real exploit from a guarded one.

## Naive keyword/substring baseline on the same targets

| Scanner | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
| ------- | -- | -- | -- | -- | --------- | ------ | -- | --- |
| Naive keyword/substring baseline | 7 | 7 | 5 | 5 | 0.50 | 0.58 | 0.54 | 0.58 |

The baseline cannot see graph structure, Unicode folding, credential
identity or placeholder semantics, so it both misses real flaws and
flags official reference servers. Benign targets it flags here:

- `CVE-2026-30623-post`
- `CVE-2026-27825-post`
- `MCP-2026-07-28-HEADER-post`
- `MCP-RUNTIME-ALLOWLIST-post`
- `UPSTREAM-FS`
- `UPSTREAM-GIT`
- `UPSTREAM-POSTGRES`

## Per-case results

| Case | Advisory | Status | In model | Expected | Latch | Engines | Naive |
| ---- | -------- | ------ | -------- | -------- | ----- | ------- | ----- |
| `CVE-2026-30623-pre` | CVE-2026-30623 | pre_patch_vulnerable | yes | positive | detected | auth-audit | detected |
| `CVE-2026-27825-pre` | CVE-2026-27825 | pre_patch_vulnerable | yes | positive | detected | auth-audit, graph | detected |
| `GHSA-MCP-2025-WHATSAPP-pre` | GHSA-MCP-2025-WHATSAPP | pre_patch_vulnerable | yes | positive | detected | verify, graph | clean |
| `GHSA-MCP-2025-GITHUB-TRIFECTA-pre` | GHSA-MCP-2025-GITHUB-TRIFECTA | pre_patch_vulnerable | yes | positive | detected | graph | clean |
| `MCP-2026-07-28-HEADER-pre` | MCP-2026-07-28-HEADER | pre_patch_vulnerable | yes | positive | detected | audit | detected |
| `MCP-REGISTRY-HOMOGLYPH-pre` | MCP-REGISTRY-HOMOGLYPH | pre_patch_vulnerable | yes | positive | detected | shadow | detected |
| `MCP-RUNTIME-ALLOWLIST-pre` | MCP-RUNTIME-ALLOWLIST | pre_patch_vulnerable | yes | positive | detected | graph, probe-chain | detected |
| `CVE-2025-FILESYSTEM-TRAVERSAL-pre` | CVE-2025-FILESYSTEM-TRAVERSAL | pre_patch_vulnerable | no | positive | clean | audit | clean |
| `MCP-2026-07-28-PRM-401-pre` | MCP-2026-07-28-PRM-401 | pre_patch_vulnerable | yes | positive | detected | auth-audit | clean |
| `MCP-2026-07-28-HEADER-CRLF-pre` | MCP-2026-07-28-HEADER-CRLF | pre_patch_vulnerable | yes | positive | detected | audit | detected |
| `MCP-DUPLICATE-TOOL-SHADOW-pre` | MCP-DUPLICATE-TOOL-SHADOW | pre_patch_vulnerable | yes | positive | detected | shadow | clean |
| `CVE-2025-POSTGRES-SQLI-pre` | CVE-2025-POSTGRES-SQLI | pre_patch_vulnerable | no | positive | clean | audit | detected |
| `CVE-2026-30623-post` | CVE-2026-30623 | post_patch_fixed | yes | negative | clean | auth-audit | detected |
| `CVE-2026-27825-post` | CVE-2026-27825 | post_patch_fixed | yes | negative | clean | auth-audit, graph | detected |
| `GHSA-MCP-2025-WHATSAPP-post` | GHSA-MCP-2025-WHATSAPP | post_patch_fixed | yes | negative | clean | verify, graph | clean |
| `GHSA-MCP-2025-GITHUB-TRIFECTA-post` | GHSA-MCP-2025-GITHUB-TRIFECTA | post_patch_fixed | yes | negative | clean | graph | clean |
| `MCP-2026-07-28-HEADER-post` | MCP-2026-07-28-HEADER | post_patch_fixed | yes | negative | clean | audit | detected |
| `MCP-REGISTRY-HOMOGLYPH-post` | MCP-REGISTRY-HOMOGLYPH | post_patch_fixed | yes | negative | clean | shadow | clean |
| `MCP-RUNTIME-ALLOWLIST-post` | MCP-RUNTIME-ALLOWLIST | post_patch_fixed | yes | negative | clean | graph, probe-chain | detected |
| `CVE-2025-FILESYSTEM-TRAVERSAL-post` | CVE-2025-FILESYSTEM-TRAVERSAL | post_patch_fixed | yes | negative | clean | audit | clean |
| `UPSTREAM-FS` | UPSTREAM-FS | upstream_reference | yes | negative | clean | audit, graph | detected |
| `UPSTREAM-GIT` | UPSTREAM-GIT | upstream_reference | yes | negative | clean | audit, graph | detected |
| `UPSTREAM-MEMORY` | UPSTREAM-MEMORY | upstream_reference | yes | negative | clean | audit, graph | clean |
| `UPSTREAM-POSTGRES` | UPSTREAM-POSTGRES | upstream_reference | yes | negative | clean | audit, graph | detected |

## Threat Model Boundaries & Honest Limitations

- **Scope.** Latch analyzes what a client can observe: tool metadata,
  JSON Schemas, annotations, headers, cross-server wiring, credentials,
  and live tool behaviour for the two calls in a trifecta. It does not
  read handler source code, so pure implementation bugs are out of scope.
- **Out-of-scope misses recorded:** counted as false negatives in the
  overall table, never quietly excluded, and marked
  `in_latch_threat_model: false` in `cve_results.json`:

  - `CVE-2025-FILESYSTEM-TRAVERSAL`
  - `CVE-2025-POSTGRES-SQLI`
- **Runtime guards are treated as ground truth.** When `probe-chain`
  runs, its verdict overrides the static graph, because a guard that
  blocks the live canary means the path is not exploitable as served.
  Probing is non-destructive: benign read arguments, a loopback-only
  sink, and a random canary.
- **Coverage is bounded by the probe's schema synthesis.** A chain whose
  egress tool accepts no URL or string payload cannot be parameterized
  and is reported `INCONCLUSIVE_SCHEMA`, never as confirmed.
- **Advisory identifiers are labels for bug classes.** The payloads are
  reconstructed from public 2025-2026 disclosures against MCP gateways,
  vendor servers and registries; they are not byte-for-byte copies of
  the vendors' test fixtures.
