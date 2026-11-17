"""Tests for the OAuth 2.1 / RFC 9728 authorization hygiene auditor."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner

from mcpprobe.cli import cli
from mcpprobe.config_loader import ServerSpec
from mcpprobe.models import ProbeError, ToolDefinition
from mcpprobe.oauth_audit import (
    is_dummy_value,
    is_env_placeholder,
    redact_secret,
    run_auth_audit,
)

SECRET = "ghp_supersecretvalue123456"
OTHER_SECRET = "mcpprobe_fixture_other_99a8b7c6"

REMOTE_URL = "https://mcp.example.com/mcp"
CHALLENGE_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
VALID_METADATA = {
    "resource": REMOTE_URL,
    "authorization_servers": ["https://auth.example.com"],
}


def http_spec(
    server_id: str = "remote",
    url: str = REMOTE_URL,
    headers: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
) -> ServerSpec:
    return ServerSpec(
        server_id=server_id,
        transport="http",
        url=url,
        headers=headers or {},
        env=env or {},
    )


def static_spec(
    server_id: str = "local",
    tools: list[dict[str, Any]] | None = None,
    env: dict[str, str] | None = None,
) -> ServerSpec:
    return ServerSpec(
        server_id=server_id,
        transport="static",
        manifest_payload={"tools": tools or []},
        env=env or {},
    )


def tool(name: str, properties: dict[str, Any] | None = None) -> ToolDefinition:
    return ToolDefinition.model_validate(
        {
            "name": name,
            "description": "",
            "inputSchema": {"type": "object", "properties": properties or {}},
        }
    )


def rule_ids(report: Any) -> list[str]:
    return [finding.rule_id for finding in report.findings]


def mock_transport(
    routes: dict[str, tuple[int, dict[str, str], Any]]
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        route = routes.get(str(request.url))
        if route is None:
            return httpx.Response(404, json={"error": "not_found"})
        status, headers, body = route
        return httpx.Response(status, headers=headers, json=body)

    return httpx.MockTransport(handler)


# -- redaction -------------------------------------------------------------


def test_redact_secret_format() -> None:
    digest = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()[:8]
    redacted = redact_secret(f"Bearer {SECRET}")

    assert redacted == f"{SECRET[:4]}...{SECRET[-2:]} [sha256:{digest}]"
    assert SECRET not in redacted


def test_redact_secret_strips_bearer_case_insensitively() -> None:
    assert redact_secret("bearer " + SECRET) == redact_secret(SECRET)
    assert redact_secret("BEARER " + SECRET) == redact_secret(SECRET)


def test_redact_secret_hides_short_values() -> None:
    digest = hashlib.sha256("abc123".encode("utf-8")).hexdigest()[:8]
    assert redact_secret("abc123") == f"*** [sha256:{digest}]"
    assert "abc123" not in redact_secret("abc123")


# -- placeholders ----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["${GITHUB_TOKEN}", "$GITHUB_TOKEN", "{{ secrets.TOKEN }}", "<your-token>"],
)
def test_env_placeholders_are_recognized(value: str) -> None:
    assert is_env_placeholder(value) is True


@pytest.mark.parametrize("value", ["ghp_realtoken", "${}", "${1BAD}", "", "<>"])
def test_literal_values_are_not_placeholders(value: str) -> None:
    assert is_env_placeholder(value) is False


@pytest.mark.parametrize(
    "value", ["", "   ", "changeme", "Bearer placeholder", "YOUR_TOKEN", "null"]
)
def test_dummy_values_are_recognized(value: str) -> None:
    assert is_dummy_value(value) is True


def test_real_credentials_are_not_dummy() -> None:
    assert is_dummy_value(SECRET) is False


# -- static rules ----------------------------------------------------------


def test_hardcoded_credential_is_redacted_everywhere() -> None:
    spec = http_spec(
        url="https://mcp.example.com/mcp",
        headers={"Authorization": f"Bearer {SECRET}"},
        env={"GITHUB_TOKEN": OTHER_SECRET},
    )

    report = run_auth_audit([spec])

    assert rule_ids(report) == [
        "HARDCODED_STATIC_CREDENTIAL",
        "HARDCODED_STATIC_CREDENTIAL",
    ]
    assert all(finding.severity == "HIGH" for finding in report.findings)
    rendered = json.dumps(report.model_dump(mode="json"))
    assert SECRET not in rendered
    assert OTHER_SECRET not in rendered
    digests = {
        hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        for value in (SECRET, OTHER_SECRET)
    }
    for finding in report.findings:
        assert finding.evidence is not None
        assert "[sha256:" in finding.evidence
    assert all(digest in rendered for digest in digests)


def test_env_placeholder_produces_no_findings() -> None:
    spec = http_spec(
        url="https://mcp.example.com/mcp",
        headers={"Authorization": "Bearer ${GITHUB_TOKEN}"},
    )

    report = run_auth_audit([spec])

    assert report.findings == []
    assert report.passed is True
    assert report.server_count == 1


def test_dummy_values_are_ignored() -> None:
    spec = http_spec(headers={"Authorization": "Bearer changeme"})

    assert run_auth_audit([spec]).findings == []


def test_cross_server_credential_reuse_critical() -> None:
    specs = [
        http_spec("github", "https://github.example.com/mcp", {"Authorization": f"Bearer {SECRET}"}),
        http_spec("evil-mcp", "https://evil.example.com/mcp", {"Authorization": f"Bearer {SECRET}"}),
    ]

    report = run_auth_audit(specs)
    reuse = [f for f in report.findings if f.rule_id == "CROSS_SERVER_CREDENTIAL_REUSE"]

    assert len(reuse) == 1
    assert reuse[0].severity == "CRITICAL"
    assert reuse[0].servers == ["evil-mcp", "github"]
    assert "[sha256:" in (reuse[0].evidence or "")
    assert SECRET not in json.dumps(report.model_dump(mode="json"))


def test_shared_env_reference_counts_as_reuse() -> None:
    specs = [
        http_spec("github", headers={"Authorization": "Bearer ${SHARED_TOKEN}"}),
        http_spec("evil-mcp", headers={"X-Api-Key": "${SHARED_TOKEN}"}),
    ]

    report = run_auth_audit(specs)

    assert rule_ids(report) == ["CROSS_SERVER_CREDENTIAL_REUSE"]
    assert report.findings[0].severity == "CRITICAL"


def test_distinct_credentials_are_not_reuse() -> None:
    specs = [
        http_spec("github", headers={"Authorization": f"Bearer {SECRET}"}),
        http_spec("evil-mcp", headers={"Authorization": f"Bearer {OTHER_SECRET}"}),
    ]

    assert "CROSS_SERVER_CREDENTIAL_REUSE" not in rule_ids(run_auth_audit(specs))


def test_insecure_http_with_credentials_is_critical() -> None:
    spec = http_spec(
        "internal",
        "http://mcp.internal.example.com/mcp",
        {"Authorization": f"Bearer {SECRET}"},
    )

    report = run_auth_audit([spec])

    assert "INSECURE_HTTP_AUTH_TRANSPORT" in rule_ids(report)
    finding = next(
        f for f in report.findings if f.rule_id == "INSECURE_HTTP_AUTH_TRANSPORT"
    )
    assert finding.severity == "CRITICAL"
    assert finding.field_path == "url"


def test_loopback_http_is_allowed() -> None:
    spec = http_spec("local", "http://127.0.0.1:8080/mcp", {"Authorization": f"Bearer {SECRET}"})

    assert "INSECURE_HTTP_AUTH_TRANSPORT" not in rule_ids(run_auth_audit([spec]))


def test_localhost_http_is_allowed() -> None:
    spec = http_spec("local", "http://localhost:8080/mcp")
    report = run_auth_audit([spec], live=True, transport=mock_transport({}))

    assert "INSECURE_HTTP_AUTH_TRANSPORT" not in rule_ids(report)


def test_https_is_not_insecure_transport() -> None:
    spec = http_spec("remote", REMOTE_URL, {"Authorization": f"Bearer {SECRET}"})

    assert "INSECURE_HTTP_AUTH_TRANSPORT" not in rule_ids(run_auth_audit([spec]))


def test_insecure_http_without_credentials_needs_live() -> None:
    spec = http_spec("internal", "http://mcp.internal.example.com/mcp")

    assert "INSECURE_HTTP_AUTH_TRANSPORT" not in rule_ids(run_auth_audit([spec]))


def test_token_passthrough_parameter() -> None:
    manifests = {
        "github": [
            tool("create_issue", {"access_token": {"type": "string"}, "title": {"type": "string"}}),
            tool("safe_tool", {"query": {"type": "string"}}),
        ]
    }

    report = run_auth_audit([static_spec("github")], manifests)

    assert rule_ids(report) == ["TOKEN_PASSTHROUGH_RISK"]
    assert report.findings[0].severity == "HIGH"
    assert report.findings[0].field_path == "tools.create_issue"
    assert "access_token" in (report.findings[0].evidence or "")


def test_token_passthrough_camel_and_header_binding() -> None:
    manifests = {
        "github": [
            tool("a", {"accessToken": {"type": "string"}}),
            tool("b", {"payload": {"type": "string", "x-mcp-header": "X-Access-Token"}}),
        ]
    }

    report = run_auth_audit([static_spec("github")], manifests)

    assert rule_ids(report) == ["TOKEN_PASSTHROUGH_RISK", "TOKEN_PASSTHROUGH_RISK"]


def test_identity_server_is_exempt_from_passthrough() -> None:
    manifests = {"auth-service": [tool("exchange", {"refresh_token": {"type": "string"}})]}

    assert run_auth_audit([static_spec("auth-service")], manifests).findings == []


def test_static_snapshot_without_credentials_passes() -> None:
    manifests = {"github": [tool("get_issue", {"issue_number": {"type": "integer"}})]}

    report = run_auth_audit([static_spec("github")], manifests)

    assert report.passed is True
    assert report.findings == []


def test_findings_are_sorted_by_severity_then_rule() -> None:
    specs = [
        http_spec(
            "internal",
            "http://mcp.internal.example.com/mcp",
            {"Authorization": f"Bearer {SECRET}", "X-Api-Key": OTHER_SECRET},
        )
    ]

    report = run_auth_audit(specs)
    severities = [finding.severity for finding in report.findings]

    assert severities[0] == "CRITICAL"
    assert severities == sorted(
        severities, key=lambda item: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[item]
    )


# -- live RFC 9728 probing -------------------------------------------------


def test_live_probe_sends_rfc_compliant_discover_request() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/.well-known/oauth-protected-resource/mcp":
            return httpx.Response(200, json=VALID_METADATA)
        return httpx.Response(
            401,
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{CHALLENGE_URL}"'},
            json={},
        )

    report = run_auth_audit(
        [http_spec()], live=True, transport=httpx.MockTransport(handler)
    )

    assert report.passed is True
    post = seen[0]
    assert post.method == "POST"
    assert post.url == httpx.URL(REMOTE_URL)
    assert post.headers["accept"] == "application/json, text/event-stream"
    assert post.headers["mcp-protocol-version"] == "2026-07-28"
    assert post.headers["mcp-method"] == "server/discover"
    assert json.loads(post.content) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {},
    }
    assert report.live_probed_servers == ["remote"]


def test_live_missing_www_authenticate_prm() -> None:
    transport = mock_transport(
        {REMOTE_URL: (401, {"WWW-Authenticate": 'Bearer realm="mcp"'}, {})}
    )

    report = run_auth_audit([http_spec()], live=True, transport=transport)

    assert "MISSING_WWW_AUTHENTICATE_PRM" in rule_ids(report)
    assert report.passed is False


def test_live_prm_resource_mismatch_is_critical() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (
                401,
                {"WWW-Authenticate": f'Bearer resource_metadata="{CHALLENGE_URL}"'},
                {},
            ),
            CHALLENGE_URL: (
                200,
                {},
                {
                    "resource": "https://other-service.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                },
            ),
        }
    )

    report = run_auth_audit([http_spec()], live=True, transport=transport)
    mismatch = next(
        f for f in report.findings if f.rule_id == "PRM_RESOURCE_MISMATCH"
    )

    assert mismatch.severity == "CRITICAL"
    assert "other-service.example.com" in (mismatch.evidence or "")
    assert REMOTE_URL in (mismatch.evidence or "")
    assert report.passed is False


def test_live_valid_metadata_is_clean() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (
                401,
                {"WWW-Authenticate": f'Bearer resource_metadata="{CHALLENGE_URL}"'},
                {},
            ),
            CHALLENGE_URL: (200, {}, VALID_METADATA),
        }
    )

    report = run_auth_audit([http_spec()], live=True, transport=transport)

    assert report.findings == []
    assert report.passed is True


def test_live_open_server_is_flagged() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (200, {}, {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}}),
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp": (
                404,
                {},
                {},
            ),
            "https://mcp.example.com/.well-known/oauth-protected-resource": (
                200,
                {},
                VALID_METADATA,
            ),
        }
    )

    report = run_auth_audit([http_spec()], live=True, transport=transport)
    open_finding = next(
        f for f in report.findings if f.rule_id == "OPEN_UNAUTHENTICATED_REMOTE_MCP"
    )

    assert open_finding.severity == "HIGH"
    assert "no authentication" in open_finding.message
    assert "unauthenticated" in (open_finding.evidence or "")


def test_live_authenticated_server_is_not_open() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (200, {}, {"jsonrpc": "2.0", "id": 1, "result": {}}),
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp": (
                200,
                {},
                VALID_METADATA,
            ),
        }
    )
    spec = http_spec(headers={"Authorization": f"Bearer {SECRET}"})

    report = run_auth_audit([spec], live=True, transport=transport)

    assert "OPEN_UNAUTHENTICATED_REMOTE_MCP" not in rule_ids(report)


def test_live_metadata_path_fallback() -> None:
    url = "https://mcp.example.com/v1/mcp"
    transport = mock_transport(
        {
            url: (401, {}, {}),
            "https://mcp.example.com/.well-known/oauth-protected-resource": (
                200,
                {},
                {"resource": url, "authorization_servers": ["https://auth.example.com"]},
            ),
        }
    )

    report = run_auth_audit(
        [http_spec("versioned", url)], live=True, transport=transport
    )

    assert rule_ids(report) == ["MISSING_WWW_AUTHENTICATE_PRM"]


def test_live_metadata_without_required_fields_is_missing() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (401, {"WWW-Authenticate": 'Bearer resource_metadata="' + CHALLENGE_URL + '"'}, {}),
            CHALLENGE_URL: (200, {}, {"resource": REMOTE_URL}),
        }
    )

    report = run_auth_audit([http_spec()], live=True, transport=transport)

    assert rule_ids(report) == ["MISSING_PROTECTED_RESOURCE_METADATA"]
    assert "authorization_servers" in (report.findings[0].message)


def test_fail_on_threshold_is_respected() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (401, {"WWW-Authenticate": f'Bearer resource_metadata="{CHALLENGE_URL}"'}, {}),
            CHALLENGE_URL: (404, {}, {}),
        }
    )

    strict = run_auth_audit([http_spec()], live=True, transport=transport)
    relaxed = run_auth_audit(
        [http_spec()], live=True, transport=transport, fail_on="HIGH"
    )

    assert rule_ids(strict) == ["MISSING_PROTECTED_RESOURCE_METADATA"]
    assert strict.passed is False
    assert relaxed.passed is True


def test_live_transport_failure_is_a_probe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with pytest.raises(ProbeError):
        run_auth_audit(
            [http_spec()], live=True, transport=httpx.MockTransport(handler)
        )


def test_live_only_probes_http_specs() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (401, {"WWW-Authenticate": f'Bearer resource_metadata="{CHALLENGE_URL}"'}, {}),
            CHALLENGE_URL: (200, {}, VALID_METADATA),
        }
    )

    report = run_auth_audit(
        [http_spec("remote"), static_spec("local")], live=True, transport=transport
    )

    assert report.live_probed_servers == ["remote"]
    assert report.server_count == 2


def test_resource_matching_normalizes_default_ports_and_trailing_slashes() -> None:
    transport = mock_transport(
        {
            REMOTE_URL: (
                401,
                {"WWW-Authenticate": f'Bearer resource_metadata="{CHALLENGE_URL}"'},
                {},
            ),
            CHALLENGE_URL: (
                200,
                {},
                {
                    "resource": "https://mcp.example.com:443/mcp/",
                    "authorization_servers": ["https://auth.example.com"],
                },
            ),
        }
    )

    assert run_auth_audit([http_spec()], live=True, transport=transport).passed is True


# -- CLI -------------------------------------------------------------------


def write_config(path: Path, servers: dict[str, Any]) -> Path:
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


def test_cli_auth_audit_flags_hardcoded_secret_without_leaking_it(tmp_path: Path) -> None:
    config = write_config(
        tmp_path / "agent.json",
        {
            "remote": {
                "url": REMOTE_URL,
                "headers": {"Authorization": f"Bearer {SECRET}"},
            }
        },
    )
    sarif_path = tmp_path / "auth.sarif"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "auth-audit",
            "--config",
            str(config),
            "--format",
            "json",
            "--sarif",
            str(sarif_path),
        ],
    )

    assert result.exit_code == 1, result.output
    assert SECRET not in result.output
    assert SECRET not in sarif_path.read_text(encoding="utf-8")
    payload = json.loads(result.output)
    assert payload["passed"] is False
    assert payload["findings"][0]["rule_id"] == "HARDCODED_STATIC_CREDENTIAL"


def test_cli_auth_audit_placeholder_config_passes(tmp_path: Path) -> None:
    config = write_config(
        tmp_path / "agent.json",
        {
            "remote": {
                "url": REMOTE_URL,
                "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"},
            }
        },
    )

    result = CliRunner().invoke(cli, ["auth-audit", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert "AUTH AUDIT PASSED" in result.output


def test_cli_auth_audit_fail_on_high_ignores_medium(tmp_path: Path) -> None:
    config = write_config(
        tmp_path / "agent.json",
        {"remote": {"url": REMOTE_URL, "headers": {"Authorization": "Bearer ${TOKEN}"}}},
    )

    result = CliRunner().invoke(
        cli, ["auth-audit", "--config", str(config), "--fail-on", "CRITICAL"]
    )

    assert result.exit_code == 0, result.output


def test_cli_auth_audit_requires_a_target() -> None:
    result = CliRunner().invoke(cli, ["auth-audit"])

    assert result.exit_code == 2, result.output


def test_cli_auth_audit_malformed_manifest_exits_two() -> None:
    result = CliRunner().invoke(cli, ["auth-audit", "--server-manifest", "nope"])

    assert result.exit_code == 2, result.output


def test_cli_auth_audit_server_manifest_token_passthrough(tmp_path: Path) -> None:
    manifest_path = tmp_path / "github.json"
    manifest_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "create_issue",
                        "description": "",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"access_token": {"type": "string"}},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        ["auth-audit", "--server-manifest", f"github={manifest_path}", "--format", "json"],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["findings"][0]["rule_id"] == "TOKEN_PASSTHROUGH_RISK"
    assert payload["findings"][0]["severity"] == "HIGH"
