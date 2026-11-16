# Synthetic Regression Suite Modeled on Disclosed MCP Bug Classes

**These 24 fixtures are synthetic models, not raw upstream captures.** Each
one is written for this repository to reproduce the *shape* of a bug class
disclosed in 2025-2026 MCP advisories, or the clean tool surface of a
reference server. They are not the vendors' own test fixtures, they quote
no advisory text, and `bug_class` labels are mechanism names rather than
CVE/GHSA identifiers. Real `tools/list` captures of pinned npm and PyPI
packages are evaluated separately in `package_eval/`.

Deterministic evaluation of Latch's static engines (`verify_manifest`,
`audit_manifest`, `analyze_capability_graph`, `analyze_shadowing`,
`run_auth_audit`), its execution-aware prober (`verify_trifecta_chains`),
and the naive keyword/substring baseline on the same targets.

- Targets: 24 (12 pre-patch models, 8 post-patch models, 4 reference-server models)
- Targets inside Latch's threat model: 22
- No timestamps or random values are recorded; re-running
  `python -m synthetic_regression.run_regression` reproduces this report
  byte for byte.

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

- `OOB-HANDLER-PATH-TRAVERSAL`
- `OOB-HANDLER-SQLI`

## Static-only vs. execution-aware verification

The runtime-allowlist patch keeps an identical tool schema and adds a
domain allowlist inside the handler. Static analysis cannot see it;
`latch probe-chain` can.

| Case | Static `graph` | `probe-chain` | Probe status | Why |
| ---- | -------------- | ------------- | ------------ | --- |
| `runtime-allowlist-patch-post` | flagged | blocked | BLOCKED_AT_EGRESS | blocked: destination '127.0.0.1' is not in the *.corp.internal allowlist |

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

- `auth-token-passthrough-post`
- `cleartext-http-trifecta-post`
- `header-unicode-poison-post`
- `runtime-allowlist-patch-post`
- `clean-filesystem-model`
- `clean-git-model`
- `clean-postgres-model`

## Per-case results

| Case | Bug class | Status | In model | Expected | Latch | Engines | Naive |
| ---- | -------- | ------ | -------- | -------- | ----- | ------- | ----- |
| `auth-token-passthrough-pre` | AUTH-TOKEN-PASSTHROUGH | pre_patch_vulnerable | yes | positive | detected | auth-audit | detected |
| `cleartext-http-trifecta-pre` | CLEARTEXT-HTTP-TRIFECTA | pre_patch_vulnerable | yes | positive | detected | auth-audit, graph | detected |
| `rugpull-post-approval-pre` | RUGPULL-POST-APPROVAL | pre_patch_vulnerable | yes | positive | detected | verify, graph | clean |
| `github-trifecta-exfil-pre` | GITHUB-TRIFECTA-EXFIL | pre_patch_vulnerable | yes | positive | detected | graph | clean |
| `header-unicode-poison-pre` | HEADER-UNICODE-POISON | pre_patch_vulnerable | yes | positive | detected | audit | detected |
| `homoglyph-shadow-pre` | HOMOGLYPH-SHADOW | pre_patch_vulnerable | yes | positive | detected | shadow | detected |
| `runtime-allowlist-patch-pre` | RUNTIME-ALLOWLIST-PATCH | pre_patch_vulnerable | yes | positive | detected | graph, probe-chain | detected |
| `oob-handler-path-traversal-pre` | OOB-HANDLER-PATH-TRAVERSAL | pre_patch_vulnerable | no | positive | clean | audit | clean |
| `prm-401-challenge-pre` | PRM-401-CHALLENGE | pre_patch_vulnerable | yes | positive | detected | auth-audit | clean |
| `HEADER-UNICODE-POISON-CRLF-pre` | HEADER-UNICODE-POISON-CRLF | pre_patch_vulnerable | yes | positive | detected | audit | detected |
| `duplicate-tool-shadow-pre` | DUPLICATE-TOOL-SHADOW | pre_patch_vulnerable | yes | positive | detected | shadow | clean |
| `oob-handler-sqli-pre` | OOB-HANDLER-SQLI | pre_patch_vulnerable | no | positive | clean | audit | detected |
| `auth-token-passthrough-post` | AUTH-TOKEN-PASSTHROUGH | post_patch_fixed | yes | negative | clean | auth-audit | detected |
| `cleartext-http-trifecta-post` | CLEARTEXT-HTTP-TRIFECTA | post_patch_fixed | yes | negative | clean | auth-audit, graph | detected |
| `rugpull-post-approval-post` | RUGPULL-POST-APPROVAL | post_patch_fixed | yes | negative | clean | verify, graph | clean |
| `github-trifecta-exfil-post` | GITHUB-TRIFECTA-EXFIL | post_patch_fixed | yes | negative | clean | graph | clean |
| `header-unicode-poison-post` | HEADER-UNICODE-POISON | post_patch_fixed | yes | negative | clean | audit | detected |
| `homoglyph-shadow-post` | HOMOGLYPH-SHADOW | post_patch_fixed | yes | negative | clean | shadow | clean |
| `runtime-allowlist-patch-post` | RUNTIME-ALLOWLIST-PATCH | post_patch_fixed | yes | negative | clean | graph, probe-chain | detected |
| `oob-handler-path-traversal-post` | OOB-HANDLER-PATH-TRAVERSAL | post_patch_fixed | yes | negative | clean | audit | clean |
| `clean-filesystem-model` | CLEAN-FILESYSTEM-MODEL | upstream_reference | yes | negative | clean | audit, graph | detected |
| `clean-git-model` | CLEAN-GIT-MODEL | upstream_reference | yes | negative | clean | audit, graph | detected |
| `clean-memory-model` | CLEAN-MEMORY-MODEL | upstream_reference | yes | negative | clean | audit, graph | clean |
| `clean-postgres-model` | CLEAN-POSTGRES-MODEL | upstream_reference | yes | negative | clean | audit, graph | detected |

## Threat Model Boundaries & Honest Limitations

- **Scope.** Latch analyzes what a client can observe: tool metadata,
  JSON Schemas, annotations, headers, cross-server wiring, credentials,
  and live tool behaviour for the two calls in a trifecta. It does not
  read handler source code, so pure implementation bugs are out of scope.
- **Out-of-scope misses recorded:** counted as false negatives in the
  overall table, never quietly excluded, and marked
  `in_latch_threat_model: false` in `regression_results.json`:

  - `OOB-HANDLER-PATH-TRAVERSAL`
  - `OOB-HANDLER-SQLI`
- **Runtime guards are treated as ground truth.** When `probe-chain`
  runs, its verdict overrides the static graph, because a guard that
  blocks the live canary means the path is not exploitable as served.
  Probing is non-destructive: benign read arguments, a loopback-only
  sink, and a random canary. An egress tool that rejects that loopback
  sink as an SSRF/private address is reported `UNCONFIRMED_SSRF_GUARD`,
  never "blocked"; pass `--sink-url` to test internet egress.
- **Coverage is bounded by the probe's schema synthesis.** A chain whose
  egress tool accepts no URL or string payload cannot be parameterized
  and is reported `INCONCLUSIVE_SCHEMA`, never as confirmed.
- **Bug-class labels are synthetic.** `bug_class` names the mechanism
  (`AUTH-TOKEN-PASSTHROUGH`, `RUGPULL-POST-APPROVAL`, ...). It is not a CVE
  or GHSA identifier and no advisory text is quoted. The reference-server
  cases model published tool surfaces, not captured bytes; see
  `package_eval/PACKAGE_EVAL_REPORT.md` for real package captures.
