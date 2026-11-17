# Pinned-package evaluation: real `tools/list` captures

Blind evaluation of Latch against real MCP packages, launched as a client
would launch them, without tailoring any engine to these packages.

## Method

`python -m package_eval.capture_manifests` starts each pinned package,
records the `tools/list` response verbatim, and resolves the pinned
version from the npm registry or PyPI. Proxy packages (`mcp-remote`,
`mcp-proxy`) advertise no tools of their own, so their real CLI is
invoked and the cleartext endpoint they expose is probed instead.
`python -m package_eval.run_package_eval` then runs `audit_manifest`,
`analyze_capability_graph`, `analyze_shadowing` and `run_auth_audit`
against those records plus the naive keyword baseline.

Three kinds of target are scored separately:

- **in-model real targets** -- single-server trifectas published by
  real servers (GitHub, Slack), cleartext or unauthenticated transport
  proxies and bridges, a literal bearer token committed to a client
  config, and two cross-server compositions. A static manifest auditor
  can see all of these.
- **out-of-model real CVEs** -- pre-patch handler-level path traversal
  and git argument injection. Those live in handler code, not in
  `tools/list`, so they are counted honestly as misses in overall recall.
- **clean reference servers** -- first-party servers expected to be
  clean; every finding on them is a false positive.

No rule or vocabulary was adjusted for any of these packages.

## Captured packages

| Package | Version | Kind | Ecosystem | Protocol | Tools | In threat model | SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mcp-remote` | 0.14.3 | `proxy_metadata` | npm | `n/a` | 0 | yes | `fe2f3b4ef49492d8…` |
| `mcp-remote` | 0.14.3 | `proxy_metadata` | npm | `n/a` | 0 | yes | `fe2f3b4ef49492d8…` |
| `@modelcontextprotocol/server-everything` | 2.3.0 | `stdio_tools` | npm | `2026-07-28` | 22 | no | `2933e591ac78202e…` |
| `@modelcontextprotocol/server-filesystem` | 0.6.2 | `stdio_tools` | npm | `2024-11-05` | 9 | no | `009e3f7d1f7db401…` |
| `@modelcontextprotocol/server-filesystem` | 2.3.0 | `stdio_tools` | npm | `2026-07-28` | 16 | no | `b53f2e27460f105d…` |
| `@modelcontextprotocol/server-github` | 2025.4.8 | `stdio_tools` | npm | `2024-11-05` | 26 | yes | `db7bf13088866f34…` |
| `@modelcontextprotocol/server-memory` | 2.1.1 | `stdio_tools` | npm | `2026-07-28` | 9 | no | `f6c207f6b59b72de…` |
| `@modelcontextprotocol/server-puppeteer` | 2025.5.12 | `stdio_tools` | npm | `2024-11-05` | 7 | no | `6320ef8a667f43fb…` |
| `@modelcontextprotocol/server-slack` | 2025.4.25 | `stdio_tools` | npm | `2024-11-05` | 8 | yes | `84b82c2ec58a9655…` |
| `supergateway` | 3.1.0 | `proxy_metadata` | npm | `n/a` | 0 | yes | `fe2f3b4ef49492d8…` |
| `mcp-proxy` | 0.8.2 | `proxy_metadata` | pypi | `n/a` | 0 | yes | `fe2f3b4ef49492d8…` |
| `mcp-server-fetch` | 2026.11.11 | `stdio_tools` | pypi | `2026-07-28` | 1 | no | `4a6dfa4e396475e3…` |
| `mcp-server-git` | 2025.9.25 | `stdio_tools` | pypi | `2025-03-26` | 12 | no | `5d147f83d15000cf…` |
| `mcp-server-git` | 2026.11.11 | `stdio_tools` | pypi | `2026-07-28` | 14 | no | `bd88748c777e6a3a…` |

Totals: 14 packages, 124 tools captured (4 proxy/transport packages expose no tools of their own).

## Real-package targets

| Target | Package / composition | Class | In model | Expected | Latch | Outcome | Rules |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `npm-mcp-remote-0-14-3-static-header` | `mcp-remote` 0.14.3 over `https://remote-mcp.example.com/sse` | `hardcoded_static_credential` | yes | yes | yes | detected | `HARDCODED_STATIC_CREDENTIAL` |
| `npm-mcp-remote-0-14-3` | `mcp-remote` 0.14.3 over `http://remote-mcp.example.com/sse` | `cleartext_http_oauth_transport` | yes | yes | yes | detected | `INSECURE_HTTP_AUTH_TRANSPORT` |
| `npm-server-filesystem-0-6-2` | `@modelcontextprotocol/server-filesystem` 0.6.2 | `handler_implementation_cve` | no | yes | no | missed | — |
| `npm-server-github-2025-4-8` | `@modelcontextprotocol/server-github` 2025.4.8 | `single_server_lethal_trifecta` | yes | yes | yes | detected | `LETHAL_TRIFECTA` |
| `npm-server-slack-2025-4-25` | `@modelcontextprotocol/server-slack` 2025.4.25 | `single_server_lethal_trifecta` | yes | yes | yes | detected | `LETHAL_TRIFECTA` |
| `npm-supergateway-3-1-0` | `supergateway` 3.1.0 over `http://0.0.0.0:18080/sse` | `unauthenticated_cleartext_sse_bridge` | yes | yes | yes | detected | `INSECURE_HTTP_AUTH_TRANSPORT` |
| `pypi-mcp-proxy-0-8-2` | `mcp-proxy` 0.8.2 over `http://0.0.0.0:18008/sse` | `unauthenticated_cleartext_sse_bridge` | yes | yes | yes | detected | `INSECURE_HTTP_AUTH_TRANSPORT` |
| `pypi-mcp-server-git-2025-9-25` | `mcp-server-git` 2025.9.25 | `handler_implementation_cve` | no | yes | no | missed | — |
| `B` | `npm-server-filesystem` + `pypi-mcp-server-fetch` | `cross_server_composition` | yes | yes | no | missed | — |
| `D` | `npm-server-puppeteer-2025-5-12` + `npm-server-filesystem` | `cross_server_composition` | yes | yes | yes | detected | `LETHAL_TRIFECTA` |

## Detection and false positives

| Metric | Value |
| --- | --- |
| In-scope real-package recall | 0.88 (7/8) |
| Overall real-package recall | 0.70 (7/10) |
| Latch false-positive rate on clean packages | 0.17 (1/6) |
| Naive baseline false-positive rate | 0.83 |

- Detected in scope: `npm-mcp-remote-0-14-3-static-header`, `npm-mcp-remote-0-14-3`, `npm-server-github-2025-4-8`, `npm-server-slack-2025-4-25`, `npm-supergateway-3-1-0`, `pypi-mcp-proxy-0-8-2`, `D`
- Missed in scope: `B`
- Out-of-model CVEs (handler code, not `tools/list`): `npm-server-filesystem-0-6-2` (CVE-2025-53109, CVE-2025-53110), `pypi-mcp-server-git-2025-9-25` (CVE-2025-68145, CVE-2025-68143)

## Before vs. after the static graph precision fix

The pre-fix model treated every local state mutation as an
`EXTERNAL_EGRESS` sink and emitted one path per
(ingest, read, egress) triple. The current engine separates
`LOCAL_WRITE`, only emits a path when a real egress sink exists, and
collapses every read tool feeding the same `(ingest, egress)` pair.

| Composition | Before: paths | Before: CRITICAL | After: paths | After: CRITICAL | Read tools collapsed into paths |
| --- | --- | --- | --- | --- | --- |
| `filesystem-plus-memory` | 0 | 0 | 0 | 0 | 0 |
| `filesystem-plus-git` | 27 | 27 | 0 | 0 | 0 |
| `filesystem-plus-fetch` | 0 | 0 | 0 | 0 | 0 |
| `puppeteer-plus-filesystem` | 0 | 0 | 1 | 1 | 8 |
| `everything-plus-filesystem` | 314 | 302 | 11 | 11 | 108 |

- `filesystem-plus-git`: **27 CRITICAL** paths become **0 CRITICAL** paths. `git_commit`, `git_merge`, `git_create_branch`, `git_checkout`, `git_reset` and `git_add` are local state mutations; there is no network sink in that configuration, so no exfiltration path exists.
- `everything-plus-filesystem`: 314 raw combinations collapse to 11 unique `(ingest, egress)` pairs (28.5x fewer rows), each listing up to 9 read tools in `read_tools`.

## Multi-server compositions from unmodified captures

| Composition | Servers | Tools | Static paths | Expected | Outcome | Naive |
| --- | --- | --- | --- | --- | --- | --- |
| `filesystem-plus-memory` | `npm-server-filesystem`, `npm-server-memory` | 25 | 0 | no | true_negative | flagged |
| `filesystem-plus-git` | `npm-server-filesystem`, `pypi-mcp-server-git` | 30 | 0 | no | true_negative | flagged |
| `filesystem-plus-fetch` | `npm-server-filesystem`, `pypi-mcp-server-fetch` | 17 | 0 | yes | missed | flagged |
| `puppeteer-plus-filesystem` | `npm-server-puppeteer-2025-5-12`, `npm-server-filesystem` | 23 | 1 | yes | detected | flagged |
| `everything-plus-filesystem` | `npm-server-everything`, `npm-server-filesystem` | 38 | 11 | no | false_positive | flagged |

- `filesystem-plus-memory`: Local file read plus local knowledge-graph memory: every write is local state, so there is no outbound sink.
  - no ingest -> read -> egress path
- `filesystem-plus-git`: Two repository-oriented servers: file read plus git history and local commits. No outbound sink exists.
  - no ingest -> read -> egress path
- `filesystem-plus-fetch`: Target B: real untrusted web ingestion (mcp-server-fetch) beside real private workspace reads (server-filesystem).
  - no ingest -> read -> egress path
  - why it is missed: mcp-server-fetch is GET-only: it has no payload parameter, so the static graph does not model it as an egress sink. Data can still leave in a caller-chosen query string, which `latch probe-chain` verifies at runtime, but the static path enumeration has nothing to enumerate here.
- `puppeteer-plus-filesystem`: Target D: real untrusted web navigation and page scripting (server-puppeteer) beside real private workspace reads (server-filesystem).
  - CRITICAL path trifecta-001: `npm-server-filesystem:search_files` -> `npm-server-filesystem:directory_tree` (+7 more read tools) -> `npm-server-puppeteer-2025-5-12:puppeteer_navigate`
- `everything-plus-filesystem`: The SDK's everything server (the largest captured surface) mounted beside the filesystem server. Its diagnostics tools have no third-party sink, so any path is over-approximation.
  - CRITICAL path trifecta-001: `npm-server-everything:get-annotated-message` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:get-header-params`
  - CRITICAL path trifecta-002: `npm-server-everything:get-annotated-message` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:gzip-file-as-resource`
  - CRITICAL path trifecta-003: `npm-server-everything:gzip-file-as-resource` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:get-header-params`
  - CRITICAL path trifecta-004: `npm-server-everything:trigger-sampling-request` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:get-header-params`
  - CRITICAL path trifecta-005: `npm-server-everything:trigger-sampling-request` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:gzip-file-as-resource`
  - CRITICAL path trifecta-006: `npm-server-everything:trigger-sampling-request-async` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:get-header-params`
  - CRITICAL path trifecta-007: `npm-server-everything:trigger-sampling-request-async` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:gzip-file-as-resource`
  - CRITICAL path trifecta-008: `npm-server-everything:trigger-url-elicitation` -> `npm-server-everything:get-env` (+9 more read tools) -> `npm-server-everything:get-header-params`
  - +3 more paths (see `package_results.json`)

## What the real-package findings are telling us

- **`@modelcontextprotocol/server-everything`** is the SDK's
  diagnostics server. `get-env` really does read environment
  variables, and `get-header-params`, `gzip-file-as-resource` and
  the `trigger-*` tools carry parameter names and open-world
  annotations that Latch's generic egress heuristics match. There is
  no third-party sink in that surface, so the remaining static paths
  are an over-approximation, and they are counted as false positives
  above.
- **The fetch + filesystem composition is a real blind miss.** A
  GET-only fetcher can leak data in a query string, but it has no
  payload parameter, so the static graph has no egress sink to
  enumerate. This is recorded as a miss, not relabelled after the
  fact; `latch probe-chain` is the execution-aware complement.
- **Pre-patch handler CVEs are out of model.** Path traversal and git
  argument injection happen inside the handlers, not in the published
  schema, so `0` findings on those captures is the honest result and
  it is what overall recall is measured against.

## Per-package detail

### `mcp-remote` 0.14.3 (0 tools, `proxy_metadata`)

- Exposed transport: `https://remote-mcp.example.com/sse` (no tools of its own)
- CLI probe: exit 0, usage `Usage: mcp-remote <https://server-url> [callback-port] [--debug]`
- Launched as: `npx --yes mcp-remote@0.14.3 https://remote-mcp.example.com/sse --header Authorization: Bearer mcpprobe_fixture_static_token_9f2a`
- In Latch's threat model: yes (`hardcoded_static_credential`)
- Latch `auth-audit` finding: `HARDCODED_STATIC_CREDENTIAL` [HIGH] on `headers.Authorization`
- Naive baseline matched: `token`, `bearer`

### `mcp-remote` 0.14.3 (0 tools, `proxy_metadata`)

- Exposed transport: `http://remote-mcp.example.com/sse` (no tools of its own)
- CLI probe: exit 0, usage `Usage: mcp-remote <https://server-url> [callback-port] [--debug]`
- Launched as: `npx --yes mcp-remote@0.14.3 http://remote-mcp.example.com/sse --allow-http`
- In Latch's threat model: yes (`cleartext_http_oauth_transport`)
- Latch `auth-audit` finding: `INSECURE_HTTP_AUTH_TRANSPORT` [CRITICAL] on `url`
- Naive baseline matched: `http://`

### `@modelcontextprotocol/server-everything` 2.3.0 (22 tools, `stdio_tools`)

- Tools: `echo`, `get-annotated-message`, `get-env`, `get-header-params`, `get-resource-links`, `get-resource-reference`, `get-structured-content`, `get-sum`, `get-tiny-image`, `gzip-file-as-resource`, `trigger-list-changed`, `trigger-log-messages`, `trigger-long-running-operation`, `trigger-resource-update`, `get-roots-list`, `trigger-elicitation-request`, `trigger-multi-step-elicitation`, `trigger-url-elicitation`, `trigger-sampling-request`, `simulate-research-query`, `trigger-sampling-request-async`, `trigger-elicitation-request-async`
- Launched as: `npx --yes @modelcontextprotocol/server-everything`
- In Latch's threat model: no (`clean_reference_server`)
- Latch `audit` finding: `ANNOTATION_CONTRADICTION` [MEDIUM] on `get-header-params`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:gzip-file-as-resource`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-sampling-request-async`
- Latch `graph` finding: `LETHAL_TRIFECTA` [CRITICAL] on `npm-server-everything:trigger-url-elicitation`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:get-annotated-message`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:trigger-sampling-request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:trigger-sampling-request-async`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-everything:trigger-url-elicitation`
- Naive baseline matched: `secret`, `token`, `pass`, `ignore`, `instead`, `before`, `x-mcp-header`

### `@modelcontextprotocol/server-filesystem` 0.6.2 (9 tools, `stdio_tools`)

- Tools: `read_file`, `read_multiple_files`, `write_file`, `create_directory`, `list_directory`, `move_file`, `search_files`, `get_file_info`, `list_allowed_directories`
- Launched as: `npx --yes @modelcontextprotocol/server-filesystem@0.6.2 {sandbox}`
- In Latch's threat model: no (`handler_implementation_cve`)
- Latch: no findings
- Naive baseline matched: `before`, `http://`

### `@modelcontextprotocol/server-filesystem` 2.3.0 (16 tools, `stdio_tools`)

- Tools: `read_file`, `read_text_file`, `read_media_file`, `read_multiple_files`, `write_file`, `append_file`, `edit_file`, `create_directory`, `list_directory`, `list_directory_with_sizes`, `directory_tree`, `move_file`, `copy_file`, `search_files`, `get_file_info`, `list_allowed_directories`
- Launched as: `npx --yes @modelcontextprotocol/server-filesystem {sandbox}`
- In Latch's threat model: no (`clean_reference_server`)
- Latch: no findings
- Naive baseline matched: `ignore`, `instead`, `before`

### `@modelcontextprotocol/server-github` 2025.4.8 (26 tools, `stdio_tools`)

- Tools: `create_or_update_file`, `search_repositories`, `create_repository`, `get_file_contents`, `push_files`, `create_issue`, `create_pull_request`, `fork_repository`, `create_branch`, `list_commits`, `list_issues`, `update_issue`, `add_issue_comment`, `search_code`, `search_issues`, `search_users`, `get_issue`, `get_pull_request`, `list_pull_requests`, `create_pull_request_review`, `merge_pull_request`, `get_pull_request_files`, `get_pull_request_status`, `update_pull_request_branch`, `get_pull_request_comments`, `get_pull_request_reviews`
- Launched as: `npx --yes @modelcontextprotocol/server-github@2025.4.8`
- In Latch's threat model: yes (`single_server_lethal_trifecta`)
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:create_pull_request_review`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:get_issue`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-github-2025-4-8:get_issue`
- +143 more findings (see `package_results.json`)
- Naive baseline matched: `http://`

### `@modelcontextprotocol/server-memory` 2.1.1 (9 tools, `stdio_tools`)

- Tools: `create_entities`, `create_relations`, `add_observations`, `delete_entities`, `delete_observations`, `delete_relations`, `read_graph`, `search_nodes`, `open_nodes`
- Launched as: `npx --yes @modelcontextprotocol/server-memory`
- In Latch's threat model: no (`clean_reference_server`)
- Latch: no findings
- Naive baseline: no keyword matches

### `@modelcontextprotocol/server-puppeteer` 2025.5.12 (7 tools, `stdio_tools`)

- Tools: `puppeteer_navigate`, `puppeteer_screenshot`, `puppeteer_click`, `puppeteer_fill`, `puppeteer_select`, `puppeteer_hover`, `puppeteer_evaluate`
- Launched as: `npx --yes @modelcontextprotocol/server-puppeteer@2025.5.12`
- In Latch's threat model: no (`cross_server_composition_member`)
- Latch: no findings
- Naive baseline matched: `instead`

### `@modelcontextprotocol/server-slack` 2025.4.25 (8 tools, `stdio_tools`)

- Tools: `slack_list_channels`, `slack_post_message`, `slack_reply_to_thread`, `slack_add_reaction`, `slack_get_channel_history`, `slack_get_thread_replies`, `slack_get_users`, `slack_get_user_profile`
- Launched as: `npx --yes @modelcontextprotocol/server-slack@2025.4.25`
- In Latch's threat model: yes (`single_server_lethal_trifecta`)
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_channel_history`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_channel_history`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_thread_replies`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_thread_replies`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_user_profile`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_user_profile`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_users`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_get_users`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_list_channels`
- Latch `graph` finding: `LETHAL_TRIFECTA` [HIGH] on `npm-server-slack-2025-4-25:slack_list_channels`
- Naive baseline: no keyword matches

### `supergateway` 3.1.0 (0 tools, `proxy_metadata`)

- Exposed transport: `http://0.0.0.0:18080/sse` (no tools of its own)
- CLI probe: exit 0
- Cleartext probe: HTTP 200 `text/event-stream`, auth challenge: none
- Launched as: `npx --yes supergateway@3.1.0 --stdio npx -y @modelcontextprotocol/server-everything@2.3.0 --port 18080 --host 0.0.0.0`
- In Latch's threat model: yes (`unauthenticated_cleartext_sse_bridge`)
- Latch `auth-audit` finding: `INSECURE_HTTP_AUTH_TRANSPORT` [CRITICAL] on `url`
- Naive baseline matched: `http://`

### `mcp-proxy` 0.8.2 (0 tools, `proxy_metadata`)

- Exposed transport: `http://0.0.0.0:18008/sse` (no tools of its own)
- CLI probe: exit 0
- Cleartext probe: HTTP 200 `text/event-stream`, auth challenge: none
- Launched as: `uvx --from mcp-proxy==0.8.2 mcp-proxy --port 18008 --host 0.0.0.0 npx @modelcontextprotocol/server-filesystem@2.3.0 {sandbox}`
- In Latch's threat model: yes (`unauthenticated_cleartext_sse_bridge`)
- Latch `auth-audit` finding: `INSECURE_HTTP_AUTH_TRANSPORT` [CRITICAL] on `url`
- Naive baseline matched: `http://`

### `mcp-server-fetch` 2026.11.11 (1 tools, `stdio_tools`)

- Tools: `fetch`
- Launched as: `uvx mcp-server-fetch`
- In Latch's threat model: no (`cross_server_composition_member`)
- Latch: no findings
- Naive baseline matched: `before`

### `mcp-server-git` 2025.9.25 (12 tools, `stdio_tools`)

- Tools: `git_status`, `git_diff_unstaged`, `git_diff_staged`, `git_diff`, `git_commit`, `git_add`, `git_reset`, `git_log`, `git_create_branch`, `git_checkout`, `git_show`, `git_branch`
- Launched as: `uvx --with pydantic==2.10.6 --with mcp==1.9.4 --from mcp-server-git==2025.9.25 mcp-server-git --repository {sandbox}`
- In Latch's threat model: no (`handler_implementation_cve`)
- Latch: no findings
- Naive baseline matched: `pass`

### `mcp-server-git` 2026.11.11 (14 tools, `stdio_tools`)

- Tools: `git_status`, `git_diff_unstaged`, `git_diff_staged`, `git_diff`, `git_commit`, `git_add`, `git_reset`, `git_log`, `git_create_branch`, `git_checkout`, `git_merge`, `git_show`, `git_branch`, `git_remote`
- Launched as: `uvx mcp-server-git --repository {sandbox}`
- In Latch's threat model: no (`clean_reference_server`)
- Latch: no findings
- Naive baseline matched: `pass`

## What this proves, and what it does not

- **Real surfaces, real provenance.** Every row above comes from an
  actual package launch with a registry-resolved version and a digest
  of the captured tool list; the JSON under `captured_manifests/` is
  the raw record, not a hand-written model.
- **Real vulnerabilities are included.** The corpus now contains
  genuine pre-patch releases plus real transport exposures, not only
  clean first-party servers, so recall is measured rather than
  assumed.
- **Blind evaluation.** No rule or vocabulary was adjusted for these
  packages; they are scored exactly as any other configuration would
  be.
- **Only metadata is exercised.** Captures contain `tools/list` bytes
  and real transport configuration. Handler behaviour, RBAC and
  network policy are not observed here; `latch probe-chain` is the
  execution-aware complement.
- **Small sample.** 14 packages and 5 compositions are not the MCP ecosystem. The result is evidence about these targets, not a claim about registry-wide precision.
- **Compositions are still static.** A clean composition means the
  published schemas do not line up into a chain, not that the servers
  can never exfiltrate.
