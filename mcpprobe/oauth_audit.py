"""OAuth 2.1 / RFC 9728 confused-deputy and authorization hygiene auditor.

MCP clients authenticate to each mounted server separately, but an agent holds
every server's credentials at once. That makes two failures common:

* the same token is pasted into several servers, so one compromised server can
  replay it against the rest (confused deputy / credential reuse);
* credentials or OAuth tokens travel in clear text, in tool arguments, or
  without any audience binding, so a token minted for one resource is accepted
  by another.

Everything statically checkable is checked from the ``ServerSpec`` list; with
``live=True`` each HTTP server is also probed for RFC 9728 Protected Resource
Metadata, ``WWW-Authenticate`` compliance and canonical ``resource`` audiences.

Secrets never appear in a finding, a JSON report or a SARIF artifact: every
value is redacted to ``prefix...suffix [sha256:<8hex>]`` so identical shared
credentials correlate without leaking.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Sequence
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

import httpx
from pydantic import BaseModel, Field

from .config_loader import ServerSpec
from .models import ProbeError, ToolDefinition, severity_rank

AuthRuleId = Literal[
    "CROSS_SERVER_CREDENTIAL_REUSE",
    "HARDCODED_STATIC_CREDENTIAL",
    "INSECURE_HTTP_AUTH_TRANSPORT",
    "TOKEN_PASSTHROUGH_RISK",
    "OPEN_UNAUTHENTICATED_REMOTE_MCP",
    "MISSING_WWW_AUTHENTICATE_PRM",
    "MISSING_PROTECTED_RESOURCE_METADATA",
    "PRM_RESOURCE_MISMATCH",
]

AuthSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

#: Header names that carry a credential.
SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "cookie",
        "x-access-token",
    }
)

#: Env keys that carry a credential, matched case-insensitively.
SENSITIVE_ENV_SUFFIXES = (
    "_TOKEN",
    "_SECRET",
    "_KEY",
    "_PASSWORD",
    "_PASSWD",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_PAT",
)

SENSITIVE_ENV_EXACT = frozenset({"BEARER_TOKEN", "API_KEY"})

#: Hosts where cleartext HTTP is acceptable (development only).
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

#: Server ids that *are* the identity provider, so forwarding tokens is their job.
IDENTITY_SERVER_TOKENS = frozenset({"auth", "oauth", "oidc", "iam", "sso", "login"})

#: Tool parameters that carry someone else's OAuth token.
PASSTHROUGH_PARAM_NAMES = frozenset(
    {
        "access_token",
        "id_token",
        "oauth_token",
        "bearer_token",
        "refresh_token",
        "session_token",
        "auth_token",
        "jwt",
        "user_jwt",
        "oauth_access_token",
        "id_jwt",
        "bearer",
    }
)

#: Backwards-compatible alias for the original name.
TOKEN_PARAMETER_NAMES = PASSTHROUGH_PARAM_NAMES

#: Query-string keys that must never carry a live credential.
SENSITIVE_QUERY_KEYS = frozenset(
    {"api_key", "apikey", "token", "access_token", "secret", "password"}
)

_DUMMY_VALUES = frozenset(
    {
        "",
        "changeme",
        "placeholder",
        "your_token",
        "your-token",
        "your_api_key",
        "your-api-key",
        "replace_me",
        "replace-me",
        "xxx",
        "todo",
        "none",
        "null",
    }
)

_ENV_PLACEHOLDER_PATTERNS = (
    re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$"),
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
    re.compile(r"^\{\{.*\}\}$"),
    re.compile(r"^<[^<>]+>$"),
)

_DISCOVER_REQUEST: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "server/discover",
    "params": {},
}

_DISCOVER_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2026-07-28",
    "Mcp-Method": "server/discover",
}

_METADATA_PATH = "/.well-known/oauth-protected-resource"

_RESOURCE_METADATA_RE = re.compile(
    r"resource_metadata\s*=\s*(?:\"([^\"]+)\"|([^\s,]+))", re.IGNORECASE
)

_DEFAULT_PORTS = {"http": 80, "https": 443}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class AuthFinding(BaseModel):
    """One authorization-hygiene finding."""

    rule_id: AuthRuleId
    severity: AuthSeverity
    servers: list[str] = Field(default_factory=list)
    field_path: str
    message: str
    evidence: str | None = None


class AuthAuditReport(BaseModel):
    """Whole-configuration authorization audit."""

    server_count: int
    live_probed_servers: list[str] = Field(default_factory=list)
    findings: list[AuthFinding] = Field(default_factory=list)
    passed: bool


# -- redaction & placeholders ----------------------------------------------


def _strip_bearer(value: str) -> str:
    core = value.strip()
    if core[:7].lower() == "bearer ":
        core = core[7:].strip()
    return core


def redact_secret(raw: str) -> str:
    """Redact a credential to a correlatable, non-reversible fingerprint."""

    core = _strip_bearer(raw)
    digest = hashlib.sha256(core.encode("utf-8")).hexdigest()[:8]
    if len(core) >= 10:
        return f"{core[:4]}...{core[-2:]} [sha256:{digest}]"
    return f"*** [sha256:{digest}]"


def is_env_placeholder(val: str) -> bool:
    """True when ``val`` is an environment/CI interpolation, not a literal."""

    stripped = val.strip()
    return any(pattern.match(stripped) for pattern in _ENV_PLACEHOLDER_PATTERNS)


def is_dummy_value(val: str) -> bool:
    """True for empty or obviously fake credential values."""

    return _strip_bearer(val).lower() in _DUMMY_VALUES


def _is_template_value(value: str) -> bool:
    """True when the value is an interpolation, with or without ``Bearer ``."""

    return is_env_placeholder(value) or is_env_placeholder(_strip_bearer(value))


def _is_sensitive_env_key(key: str) -> bool:
    upper = key.upper()
    if upper in SENSITIVE_ENV_EXACT:
        return True
    return any(upper.endswith(suffix) for suffix in SENSITIVE_ENV_SUFFIXES)


def _query_credentials(url: str | None) -> list[tuple[str, str]]:
    """``(key, value)`` for live credentials embedded in a URL query string."""

    if not url:
        return []
    hits: list[tuple[str, str]] = []
    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key.lower() not in SENSITIVE_QUERY_KEYS:
            continue
        if not value or is_dummy_value(value) or _is_template_value(value):
            continue
        hits.append((key, value))
    return hits


def _sensitive_credentials(spec: ServerSpec) -> list[tuple[str, str, str]]:
    """``(field_path, label, raw_value)`` for every credential on a spec."""

    entries: list[tuple[str, str, str]] = []
    for name in sorted(spec.headers or {}):
        if name.lower() in SENSITIVE_HEADER_NAMES:
            entries.append((f"headers.{name}", name, (spec.headers or {})[name]))
    for key in sorted(spec.env or {}):
        if _is_sensitive_env_key(key):
            entries.append((f"env.{key}", key, (spec.env or {})[key]))
    return entries


def _has_sensitive_headers(spec: ServerSpec) -> bool:
    return any(name.lower() in SENSITIVE_HEADER_NAMES for name in (spec.headers or {}))


def _is_loopback_url(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in LOOPBACK_HOSTS


# -- token passthrough ------------------------------------------------------


def _snake_case(value: str) -> str:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    return re.sub(r"[^a-z0-9]+", "_", spaced.lower()).strip("_")


def _normalize_token_name(value: str) -> str:
    normalized = _snake_case(value)
    if normalized.startswith("x_"):
        normalized = normalized[2:]
    return normalized


def _server_tokens(server_id: str) -> set[str]:
    return {token.lower() for token in re.split(r"[^A-Za-z0-9]+", server_id) if token}


def _token_carriers(tool: ToolDefinition) -> list[tuple[str, str]]:
    """``(field_path, label)`` for every OAuth token carrier in a tool schema."""

    hits: list[tuple[str, str]] = []
    properties = tool.inputSchema.get("properties")
    if not isinstance(properties, dict):
        return hits

    for name in sorted(properties):
        schema = properties[name]
        if _normalize_token_name(name) in PASSTHROUGH_PARAM_NAMES:
            hits.append((f"inputSchema.properties.{name}", name))
        header = schema.get("x-mcp-header") if isinstance(schema, dict) else None
        if isinstance(header, str) and _normalize_token_name(header) in PASSTHROUGH_PARAM_NAMES:
            hits.append((f"inputSchema.properties.{name}.x-mcp-header", header))
    return hits


# -- static configuration rules --------------------------------------------


def audit_auth_specs(
    specs: Sequence[ServerSpec],
    manifests: dict[str, list[ToolDefinition]] | None = None,
    *,
    live: bool = False,
) -> list[AuthFinding]:
    """Apply every rule that needs no network access."""

    findings: list[AuthFinding] = []
    ordered = sorted(specs, key=lambda spec: spec.server_id)

    for spec in ordered:
        # HARDCODED_STATIC_CREDENTIAL
        for field_path, label, value in _sensitive_credentials(spec):
            if _is_template_value(value) or is_dummy_value(value):
                continue
            findings.append(
                AuthFinding(
                    rule_id="HARDCODED_STATIC_CREDENTIAL",
                    severity="HIGH",
                    servers=[spec.server_id],
                    field_path=field_path,
                    message=(
                        f"{label} on server '{spec.server_id}' is a literal"
                        " credential committed to configuration; move it to an"
                        " environment reference or secret store."
                    ),
                    evidence=f"{label}: {redact_secret(value)}",
                )
            )

        # HARDCODED_STATIC_CREDENTIAL in the URL query string. Query strings
        # leak into access logs, proxies and Referer headers, so a literal key
        # there is both exposed and unrotatable.
        for key, value in _query_credentials(spec.url):
            findings.append(
                AuthFinding(
                    rule_id="HARDCODED_STATIC_CREDENTIAL",
                    severity="HIGH",
                    servers=[spec.server_id],
                    field_path=f"url.query.{key}",
                    message=(
                        f"server '{spec.server_id}' carries a literal credential in"
                        f" its URL query string ({key}=...); query strings are logged"
                        " by proxies and servers. Move it to a header from an"
                        " environment reference."
                    ),
                    evidence=f"{key}: {redact_secret(value)}",
                )
            )

        # INSECURE_HTTP_AUTH_TRANSPORT
        if spec.transport == "http" and spec.url:
            parts = urlsplit(spec.url)
            if (
                parts.scheme.lower() == "http"
                and (parts.hostname or "").lower() not in LOOPBACK_HOSTS
                and (_has_sensitive_headers(spec) or live)
            ):
                findings.append(
                    AuthFinding(
                        rule_id="INSECURE_HTTP_AUTH_TRANSPORT",
                        severity="CRITICAL",
                        servers=[spec.server_id],
                        field_path="url",
                        message=(
                            f"server '{spec.server_id}' is reached over cleartext"
                            " HTTP with credentials in play; anyone on the path can"
                            " read or replay them. Use HTTPS."
                        ),
                        evidence=f"{spec.url} (host {parts.hostname})",
                    )
                )

    # CROSS_SERVER_CREDENTIAL_REUSE
    shared: dict[str, dict[str, tuple[str, str]]] = {}
    for spec in ordered:
        for field_path, _label, value in _sensitive_credentials(spec):
            if is_dummy_value(value):
                continue
            normalized = _strip_bearer(value)
            if not normalized:
                continue
            shared.setdefault(normalized, {})[spec.server_id] = (field_path, value)

    for normalized in sorted(shared):
        owners = shared[normalized]
        if len(owners) < 2:
            continue
        servers = sorted(owners)
        sample = owners[servers[0]][1]
        findings.append(
            AuthFinding(
                rule_id="CROSS_SERVER_CREDENTIAL_REUSE",
                severity="CRITICAL",
                servers=servers,
                field_path=", ".join(f"{server}.{owners[server][0]}" for server in servers),
                message=(
                    f"Servers {', '.join(servers)} use the same credential; one"
                    " compromised server can replay it against the others"
                    " (confused deputy). Give every server its own scoped"
                    " credential."
                ),
                evidence=f"shared credential {redact_secret(sample)}",
            )
        )

    # TOKEN_PASSTHROUGH_RISK
    if manifests:
        for server_id in sorted(manifests):
            if _server_tokens(server_id) & IDENTITY_SERVER_TOKENS:
                continue
            for tool in sorted(manifests[server_id], key=lambda item: item.name):
                carriers = _token_carriers(tool)
                if not carriers:
                    continue
                findings.append(
                    AuthFinding(
                        rule_id="TOKEN_PASSTHROUGH_RISK",
                        severity="HIGH",
                        servers=[server_id],
                        field_path=f"tools.{tool.name}",
                        message=(
                            f"tool '{server_id}:{tool.name}' accepts an OAuth token"
                            " as a tool argument or header, so an agent can be"
                            " steered into forwarding a user token upstream"
                            " (token passthrough / replay)."
                        ),
                        evidence="; ".join(
                            f"{path} ({label})" for path, label in carriers
                        ),
                    )
                )

    return findings


# -- RFC 9728 live probing --------------------------------------------------


def _jsonrpc_succeeded(response: httpx.Response) -> bool:
    try:
        payload = response.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and "result" in payload and "error" not in payload


def _resource_metadata_url(challenge: str) -> str | None:
    match = _RESOURCE_METADATA_RE.search(challenge or "")
    if match is None:
        return None
    value = (match.group(1) or match.group(2) or "").strip().strip('"')
    return value or None


def _metadata_candidates(url: str) -> list[str]:
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    bare = f"{origin}{_METADATA_PATH}"
    path = parts.path.rstrip("/")
    candidates = [f"{bare}{path}"] if path else []
    candidates.append(bare)
    return candidates


async def _fetch_metadata(
    client: httpx.AsyncClient, candidates: Sequence[str]
) -> tuple[str | None, Any]:
    """Return the first candidate that answers 200 with JSON."""

    for candidate in candidates:
        try:
            response = await client.get(
                candidate, headers={"Accept": "application/json"}
            )
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue
        try:
            return candidate, response.json()
        except ValueError:
            continue
    return None, None


def _normalized_path(path: str) -> str:
    return path.rstrip("/") or "/"


def _endpoint(url: str) -> tuple[str, str, int | None, str]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    return (
        scheme,
        (parts.hostname or "").lower(),
        parts.port or _DEFAULT_PORTS.get(scheme),
        _normalized_path(parts.path),
    )


def _resource_matches(resource: str, target: str) -> bool:
    """True when ``resource`` binds the same endpoint as ``target``."""

    resource_endpoint = _endpoint(resource)
    target_endpoint = _endpoint(target)
    if resource_endpoint[:3] != target_endpoint[:3]:
        return False

    resource_path = resource_endpoint[3]
    target_path = target_endpoint[3]
    if resource_path == target_path:
        return True
    if "/" in (resource_path, target_path):
        # An origin-level resource covers everything beneath it.
        if resource_path == "/" or target_path == "/":
            return True
    return target_path.startswith(f"{resource_path}/") or resource_path.startswith(
        f"{target_path}/"
    )


def _metadata_shape_error(metadata: Any) -> str | None:
    if not isinstance(metadata, dict):
        return "metadata is not a JSON object"
    resource = metadata.get("resource")
    if not isinstance(resource, str) or not resource.strip():
        return "metadata has no string 'resource'"
    servers = metadata.get("authorization_servers")
    if not isinstance(servers, list) or not servers:
        return "metadata has no non-empty 'authorization_servers'"
    return None


async def probe_http_auth(
    spec: ServerSpec,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 10.0,
) -> list[AuthFinding]:
    """Probe one HTTP server's challenge and RFC 9728 metadata."""

    if spec.transport != "http" or not spec.url:
        return []

    url = spec.url
    findings: list[AuthFinding] = []

    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        try:
            response = await client.post(
                url, json=_DISCOVER_REQUEST, headers=_DISCOVER_HEADERS
            )
        except httpx.HTTPError as exc:
            raise ProbeError(f"cannot probe {url}: {exc}") from exc

        if (
            response.status_code == 200
            and _jsonrpc_succeeded(response)
            and not _is_loopback_url(url)
            and not _has_sensitive_headers(spec)
        ):
            findings.append(
                AuthFinding(
                    rule_id="OPEN_UNAUTHENTICATED_REMOTE_MCP",
                    severity="HIGH",
                    servers=[spec.server_id],
                    field_path="url",
                    message=(
                        f"server '{spec.server_id}' answers MCP requests from the"
                        " public internet with no authentication at all; anyone who"
                        " can reach it can drive its tools."
                    ),
                    evidence=f"{url} returned an unauthenticated 200 result",
                )
            )

        challenge = response.headers.get("www-authenticate", "")
        metadata_url = _resource_metadata_url(challenge)
        if response.status_code == 401 and metadata_url is None:
            findings.append(
                AuthFinding(
                    rule_id="MISSING_WWW_AUTHENTICATE_PRM",
                    severity="HIGH",
                    servers=[spec.server_id],
                    field_path="WWW-Authenticate",
                    message=(
                        f"server '{spec.server_id}' rejects unauthenticated calls"
                        " but its 401 challenge advertises no resource_metadata, so"
                        " clients cannot discover the protected-resource metadata"
                        " or the right audience."
                    ),
                    evidence=f"WWW-Authenticate: {challenge or '<absent>'}",
                )
            )

        candidates: list[str] = []
        if metadata_url is not None:
            candidates.append(metadata_url)
        for candidate in _metadata_candidates(url):
            if candidate not in candidates:
                candidates.append(candidate)

        fetched_url, metadata = await _fetch_metadata(client, candidates)
        shape_error = _metadata_shape_error(metadata) if fetched_url else None

        if fetched_url is None:
            findings.append(
                AuthFinding(
                    rule_id="MISSING_PROTECTED_RESOURCE_METADATA",
                    severity="MEDIUM",
                    servers=[spec.server_id],
                    field_path=_METADATA_PATH.lstrip("/"),
                    message=(
                        f"no RFC 9728 protected-resource metadata is served for"
                        f" '{spec.server_id}', so an MCP client cannot learn the"
                        " canonical resource or which authorization server to use."
                    ),
                    evidence=f"tried {', '.join(candidates)}",
                )
            )
        elif shape_error is not None:
            findings.append(
                AuthFinding(
                    rule_id="MISSING_PROTECTED_RESOURCE_METADATA",
                    severity="MEDIUM",
                    servers=[spec.server_id],
                    field_path=_METADATA_PATH.lstrip("/"),
                    message=(
                        f"protected-resource metadata at {fetched_url} is"
                        f" incomplete: {shape_error}."
                    ),
                    evidence=f"{fetched_url}: {shape_error}",
                )
            )
        else:
            resource = str(metadata["resource"])
            if not _resource_matches(resource, url):
                findings.append(
                    AuthFinding(
                        rule_id="PRM_RESOURCE_MISMATCH",
                        severity="CRITICAL",
                        servers=[spec.server_id],
                        field_path="resource",
                        message=(
                            f"metadata advertises resource '{resource}' for"
                            f" '{spec.server_id}' but the server is reached at"
                            f" '{url}'; tokens minted for one audience are accepted"
                            " by the other (confused deputy)."
                        ),
                        evidence=(
                            f"expected {url} but advertised {resource}"
                            f" ({fetched_url})"
                        ),
                    )
                )

    return findings


async def _probe_all(
    specs: Sequence[ServerSpec],
    *,
    transport: httpx.AsyncBaseTransport | None,
    timeout: float,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    for spec in specs:
        findings.extend(
            await probe_http_auth(spec, transport=transport, timeout=timeout)
        )
    return findings


# -- entry point ------------------------------------------------------------


def run_auth_audit(
    specs: Sequence[ServerSpec],
    manifests: dict[str, list[ToolDefinition]] | None = None,
    *,
    live: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 10.0,
    fail_on: str = "MEDIUM",
) -> AuthAuditReport:
    """Run every static rule, plus RFC 9728 probing when ``live``."""

    findings = audit_auth_specs(specs, manifests, live=live)
    probed: list[str] = []

    if live:
        http_specs = sorted(
            (spec for spec in specs if spec.transport == "http" and spec.url),
            key=lambda spec: spec.server_id,
        )
        probed = [spec.server_id for spec in http_specs]
        findings.extend(
            asyncio.run(_probe_all(http_specs, transport=transport, timeout=timeout))
        )

    findings.sort(
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.rule_id,
            tuple(finding.servers),
            finding.field_path,
        )
    )

    threshold = severity_rank(fail_on)
    return AuthAuditReport(
        server_count=len(specs),
        live_probed_servers=probed,
        findings=findings,
        passed=all(severity_rank(finding.severity) < threshold for finding in findings),
    )
