# Pinned-package evaluation: real `tools/list` captures

Blind evaluation of Latch against real MCP servers, launched as a client
would launch them, without tailoring any engine to these packages.

## Method

`python -m package_eval.capture_manifests` starts each pinned package over
stdio, captures the `tools/list` response verbatim, resolves the pinned
version from the npm registry or PyPI, and hashes the canonical tool list.
Captures marked `live_subprocess` were harvested here; any kept
`pinned_package_capture` snapshot is a previous verbatim capture of the
same package version. `python -m package_eval.run_package_eval` then runs
`audit_manifest`, `analyze_capability_graph`, `analyze_shadowing` and
`run_auth_audit` against those records plus the naive keyword baseline,
and scores the multi-server compositions built from the unmodified
captures.

These are first-party reference servers, so the expected result is clean:
any finding below is reported as a finding, not tuned away.

## Captured packages

| Package | Version | Ecosystem | Protocol | Tools | SHA-256 | Capture |
| --- | --- | --- | --- | --- | --- | --- |
| `@modelcontextprotocol/server-everything` | 2.3.0 | npm | `2026-07-28` | 22 | `2933e591ac78202e…` | `live_subprocess` |
| `@modelcontextprotocol/server-filesystem` | 2.3.0 | npm | `2026-07-28` | 16 | `b53f2e27460f105d…` | `live_subprocess` |
| `@modelcontextprotocol/server-memory` | 2.1.1 | npm | `2026-07-28` | 9 | `f6c207f6b59b72de…` | `live_subprocess` |
| `mcp-server-fetch` | 2026.11.11 | pypi | `2026-07-28` | 1 | `4a6dfa4e396475e3…` | `live_subprocess` |
| `mcp-server-git` | 2026.11.11 | pypi | `2026-07-28` | 14 | `bd88748c777e6a3a…` | `live_subprocess` |

Totals: 5 packages, 62 tools captured.

## Latch vs. the naive baseline

| Scanner | Flagged packages | Clean packages | False-positive rate |
| --- | --- | --- | --- |
| **Latch** | 1 | 4 | 0.20 |
| Naive keyword/substring baseline | 4 | 1 | 0.80 |

Latch findings on real packages: `npm-server-everything`.

The baseline flags: `npm-server-everything`, `npm-server-filesystem`, `pypi-mcp-server-fetch`, `pypi-mcp-server-git` -- ordinary tool descriptions (`ignore`, `http://`, `token`, …) are enough to trip it.

## What the real-package findings are telling us

Two results deserve to be read as limitations rather than
detections, and they are counted against Latch in the numbers
above:

- **`@modelcontextprotocol/server-everything`** is the SDK's
  diagnostics server. `get-env` really does read environment
  variables, and `get-header-params`, `gzip-file-as-resource` and
  the `trigger-*` tools carry parameter names and open-world
  annotations that Latch's generic egress heuristics match. There
  is no third-party sink in that surface, so the static
  ingest -> read -> egress paths are an over-approximation of a
  capability graph, not a live exfiltration path.
- **`filesystem-plus-git`** pairs file ingestion/reads with
  `git_commit`, `git_create_branch` and `git_merge`. Those are
  write verbs pointing at the local repository, not at an external
  destination, so the cross-server paths are again theoretical.

This is exactly what the static graph promises -- "could these
capabilities line up?" -- and exactly why `latch probe-chain`
exists: a dry run shows the synthesized calls, and a live probe
with an operator sink settles whether data actually leaves. The
blind evaluation is more useful for surfacing this than a
hand-tuned corpus would be, so it stays in the report.

## Per-package detail

### `@modelcontextprotocol/server-everything` 2.3.0 (22 tools)

- Tools: `echo`, `get-annotated-message`, `get-env`, `get-header-params`, `get-resource-links`, `get-resource-reference`, `get-roots-list`, `get-structured-content`, `get-sum`, `get-tiny-image`, `gzip-file-as-resource`, `simulate-research-query`, `trigger-elicitation-request`, `trigger-elicitation-request-async`, `trigger-list-changed`, `trigger-log-messages`, `trigger-long-running-operation`, `trigger-multi-step-elicitation`, `trigger-resource-update`, `trigger-sampling-request`, `trigger-sampling-request-async`, `trigger-url-elicitation`
- Launched as: `['npx', '--yes', '@modelcontextprotocol/server-everything']`
- Latch `audit` finding: `ANNOTATION_CONTRADICTION` [MEDIUM] on `get-header-params`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:gzip-file-as-resource`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:gzip-file-as-resource`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:gzip-file-as-resource`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request-async`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request-async`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request-async`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-url-elicitation`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-url-elicitation`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:gzip-file-as-resource`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:gzip-file-as-resource`
- +7 more findings (see `package_results.json`)
- Naive baseline matched: `secret`, `token`, `pass`, `ignore`, `instead`, `before`, `x-mcp-header`

### `@modelcontextprotocol/server-filesystem` 2.3.0 (16 tools)

- Tools: `append_file`, `copy_file`, `create_directory`, `directory_tree`, `edit_file`, `get_file_info`, `list_allowed_directories`, `list_directory`, `list_directory_with_sizes`, `move_file`, `read_file`, `read_media_file`, `read_multiple_files`, `read_text_file`, `search_files`, `write_file`
- Launched as: `['npx', '--yes', '@modelcontextprotocol/server-filesystem', '{sandbox}']`
- Latch: no findings
- Naive baseline matched: `ignore`, `instead`, `before`

### `@modelcontextprotocol/server-memory` 2.1.1 (9 tools)

- Tools: `add_observations`, `create_entities`, `create_relations`, `delete_entities`, `delete_observations`, `delete_relations`, `open_nodes`, `read_graph`, `search_nodes`
- Launched as: `['npx', '--yes', '@modelcontextprotocol/server-memory']`
- Latch: no findings
- Naive baseline: no keyword matches

### `mcp-server-fetch` 2026.11.11 (1 tools)

- Tools: `fetch`
- Launched as: `['uvx', 'mcp-server-fetch']`
- Latch: no findings
- Naive baseline matched: `before`

### `mcp-server-git` 2026.11.11 (14 tools)

- Tools: `git_add`, `git_branch`, `git_checkout`, `git_commit`, `git_create_branch`, `git_diff`, `git_diff_staged`, `git_diff_unstaged`, `git_log`, `git_merge`, `git_remote`, `git_reset`, `git_show`, `git_status`
- Launched as: `['uvx', 'mcp-server-git', '--repository', '{sandbox}']`
- Latch: no findings
- Naive baseline matched: `pass`

## Multi-server compositions from unmodified captures

| Composition | Servers | Tools | Static trifecta paths | Audit findings | Naive |
| --- | --- | --- | --- | --- | --- |
| `filesystem-plus-memory` | `npm-server-filesystem`, `npm-server-memory` | 25 | 0 | 0 | flagged |
| `filesystem-plus-git` | `npm-server-filesystem`, `pypi-mcp-server-git` | 30 | 27 | 0 | flagged |
| `filesystem-plus-fetch` | `npm-server-filesystem`, `pypi-mcp-server-fetch` | 17 | 0 | 0 | flagged |
| `everything-plus-filesystem` | `npm-server-everything`, `npm-server-filesystem` | 38 | 314 | 1 | flagged |

- `filesystem-plus-memory`: Local file read plus local knowledge-graph memory: both are first-party reference servers with no network egress.
  - no ingest -> read -> egress path
- `filesystem-plus-git`: Two repository-oriented servers: file access plus git history inspection, still with no outbound sink.
  - CRITICAL path trifecta-001: `npm-server-filesystem:search_files` -> `npm-server-filesystem:directory_tree` -> `pypi-mcp-server-git:git_commit`
  - CRITICAL path trifecta-002: `npm-server-filesystem:search_files` -> `npm-server-filesystem:directory_tree` -> `pypi-mcp-server-git:git_create_branch`
  - CRITICAL path trifecta-003: `npm-server-filesystem:search_files` -> `npm-server-filesystem:directory_tree` -> `pypi-mcp-server-git:git_merge`
  - CRITICAL path trifecta-004: `npm-server-filesystem:search_files` -> `npm-server-filesystem:get_file_info` -> `pypi-mcp-server-git:git_commit`
  - CRITICAL path trifecta-005: `npm-server-filesystem:search_files` -> `npm-server-filesystem:get_file_info` -> `pypi-mcp-server-git:git_create_branch`
  - CRITICAL path trifecta-006: `npm-server-filesystem:search_files` -> `npm-server-filesystem:get_file_info` -> `pypi-mcp-server-git:git_merge`
  - CRITICAL path trifecta-007: `npm-server-filesystem:search_files` -> `npm-server-filesystem:list_directory` -> `pypi-mcp-server-git:git_commit`
  - CRITICAL path trifecta-008: `npm-server-filesystem:search_files` -> `npm-server-filesystem:list_directory` -> `pypi-mcp-server-git:git_create_branch`
  - +19 more paths (see `package_results.json`)
- `filesystem-plus-fetch`: File read plus a web fetcher: the closest official pairing to an ingest/egress chain, so the static graph deserves a look.
  - no ingest -> read -> egress path
- `everything-plus-filesystem`: The SDK's everything server (the largest captured surface) mounted beside the filesystem server.
  - CRITICAL path trifecta-001: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:directory_tree` -> `npm-server-everything:get-header-params`
  - CRITICAL path trifecta-002: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:directory_tree` -> `npm-server-everything:gzip-file-as-resource`
  - CRITICAL path trifecta-003: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:directory_tree` -> `npm-server-everything:trigger-resource-update`
  - CRITICAL path trifecta-004: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:directory_tree` -> `npm-server-everything:trigger-sampling-request`
  - CRITICAL path trifecta-005: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:directory_tree` -> `npm-server-everything:trigger-sampling-request-async`
  - CRITICAL path trifecta-006: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:directory_tree` -> `npm-server-everything:trigger-url-elicitation`
  - CRITICAL path trifecta-007: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:get_file_info` -> `npm-server-everything:get-header-params`
  - CRITICAL path trifecta-008: `npm-server-everything:get-annotated-message` -> `npm-server-filesystem:get_file_info` -> `npm-server-everything:gzip-file-as-resource`
  - +306 more paths (see `package_results.json`)

## What this proves, and what it does not

- **Real surfaces, real provenance.** Every row above comes from an
  actual package launch with a registry-resolved version and a digest
  of the captured tool list; the JSON under `captured_manifests/` is the
  raw record, not a hand-written model.
- **Blind evaluation.** No rule or vocabulary was adjusted for these
  packages; they are scored exactly as any other configuration would be.
- **Only metadata is exercised.** Captures contain `tools/list` bytes.
  Handler behaviour, RBAC and network policy are not observed here;
  `latch probe-chain` is the execution-aware complement.
- **Small sample.** Five reference servers is not the MCP ecosystem.
  The result is evidence about first-party surfaces, not a claim about
  registry-wide precision.
- **Compositions are still static.** A clean composition means the
  published schemas do not line up into a chain, not that the servers
  can never exfiltrate.
