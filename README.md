# MCPProbe

Deterministic security verification and schema pinning for
[Model Context Protocol](https://modelcontextprotocol.io) servers.

MCPProbe captures a server's `tools/list` response, pins every tool definition
into a reviewable lockfile with a SHA-256 digest, and later proves that the live
tool surface still matches what you reviewed. Any added, removed or edited tool
fails verification — including a single invisible Unicode character sneaked
into a tool description.

## Install

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

`pydantic` and `click` are the only runtime dependencies; `pytest` lives in the
`dev` extra.

## Usage

Capture the server's tool list and pin it:

```bash
mcpprobe pin --input tools-list.json --server-id github-mcp --output mcpprobe.lock.json
```

Commit `mcpprobe.lock.json` alongside your config. Later, re-capture and verify:

```bash
mcpprobe verify --input tools-list.json --lockfile mcpprobe.lock.json
mcpprobe verify --input tools-list.json --lockfile mcpprobe.lock.json --json
```

Both raw manifests (`{"tools": [...]}`) and full JSON-RPC envelopes are
accepted:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {"tools": [{"name": "echo", "description": "Echo text back."}], "ttlMs": 60000}
}
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Verification passed — no drift. |
| `1`  | Drift detected: `ADDED_TOOL`, `REMOVED_TOOL` or `MODIFIED_TOOL`. |
| `2`  | Invalid input: bad JSON, missing file, malformed MCP tool schema. |

`--json` emits a structured report:

```json
{
  "actual_manifest_sha256": "…",
  "drift": [
    {"actual_sha256": "…", "expected_sha256": "…", "kind": "MODIFIED_TOOL", "tool_name": "echo"}
  ],
  "expected_manifest_sha256": "…",
  "passed": false,
  "schema_version": "1.0",
  "server_id": "github-mcp"
}
```

## How digests are computed

**Canonical JSON.** A tool is serialized with `sort_keys=True`,
`separators=(",", ":")` and `ensure_ascii=False`, then UTF-8 encoded. Every
declared field — `name`, `title`, `description`, `inputSchema`,
`outputSchema`, `annotations` — plus any extra/extension field the server sent
is included, and nested JSON Schema objects are sorted recursively. Schemas
that differ only in key order therefore hash identically.

**Text is never normalized.** Whitespace, zero-width spaces, BOMs and every
other character inside `description` or a schema description are hashed exactly
as delivered, so a byte-level edit always changes the digest.

**Per-tool digest.** `hash_tool` is the lowercase hex SHA-256 of the canonical
JSON. It is what drives `MODIFIED_TOOL` detection.

**Manifest digest.** `hash_manifest` sorts tools by name, hashes the joined
`"<name>:<sha256>"` entries with SHA-256, and so is insensitive to `tools`
array order while still changing for any added, removed or modified tool.

```python
from mcpprobe.lockfile import create_lockfile, save_lockfile, verify_manifest
from mcpprobe.models import parse_tools_payload

tools = parse_tools_payload(manifest_json)
lockfile = create_lockfile(manifest_json, "github-mcp")
save_lockfile(lockfile, Path("mcpprobe.lock.json"))
report = verify_manifest(fresh_manifest_json, lockfile)
print(report.passed, [item.kind for item in report.drift])
```

## Tests

```bash
.venv/bin/pytest -v
```
