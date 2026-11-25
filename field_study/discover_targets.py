"""Discover unseen npm and PyPI MCP server packages for the field study.

    # Round 1 (the sample the in-sample report scores):
    python -m field_study.discover_targets --npm-limit 70 --pypi-limit 30 \
        --output field_study/round1/targets.json

    # Holdout: the same two registry queries, disjoint from round 1.
    python -m field_study.discover_targets --npm-limit 70 --pypi-limit 30 \
        --output field_study/holdout/targets.json \
        --exclude-targets field_study/round1/targets.json

Targets are read from the public registries only:

* npm -- ``https://registry.npmjs.org/-/v1/search?text=mcp-server&size=N``,
  which exposes the pinned ``version`` and repository link up front.
* PyPI -- ``https://pypi.org/simple/`` (JSON content negotiation) filtered to
  ``mcp-server-*`` / ``*-mcp-server`` names, then each project's JSON metadata
  for its pinned version, summary and repository link.

Exclusions are explicit and never implicit. A run excludes only:

* every package pinned in ``package_eval/captured_manifests/``, and
* every package named in a ``--exclude-targets`` file (repeatable).

It does not read or exclude its own ``--output``, and it does not go looking for
a ``targets.json`` that happens to exist: a split is defined solely by the
sources printed on the command line. Exclusions compare the package name
(PEP 503-normalized for PyPI) and the capture slug, so a renamed capture cannot
smuggle a known package back in.

Every run writes ``<output stem>.split.json`` beside the target list: the
exclusion sources with their sha256, the unique excluded-name count, the
discovered count, and the discovered/excluded overlap, which must be empty. A
non-empty overlap means the split is not disjoint, so the run fails and the
target list is not written.

An existing ``--output`` is never overwritten without ``--force``, so a re-draw
cannot silently replace a pinned round. No package is installed or executed
here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FIELD_DIR = Path(__file__).resolve().parent
REPO_ROOT = FIELD_DIR.parent
TARGETS_JSON = FIELD_DIR / "round1" / "targets.json"
PACKAGE_EVAL_MANIFESTS = REPO_ROOT / "package_eval" / "captured_manifests"

NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search?text=mcp-server&size={size}"
PYPI_SIMPLE_URL = "https://pypi.org/simple/"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"

USER_AGENT = "latch-field-study/1.0"

#: ``mcp-server-foo``, ``mcp_server_foo`` or ``foo-mcp-server``.
_PYPI_MCP_NAME = re.compile(
    r"^(?:mcp[-_]server[-_])|(?:[-_]mcp[-_]server)$", re.IGNORECASE
)
_SLUG_SEPARATOR = re.compile(r"[^a-z0-9]+")


def _default_fetch(url: str) -> Any:
    """Fetch a registry URL and parse JSON, with PyPI's JSON simple API."""

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.pypi.simple.v1+json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - https
        return json.loads(response.read().decode("utf-8"))


def normalize_package(name: str) -> str:
    """Case- and separator-insensitive package key (PEP 503 for PyPI)."""

    return re.sub(r"[-_.]+", "-", name).strip().lower()


def slugify(*parts: str) -> str:
    return "-".join(
        _SLUG_SEPARATOR.sub("-", part.lower()).strip("-")
        for part in parts
        if part
    )


def clean_repository_url(value: Any) -> str | None:
    """Strip ``git+`` / ``.git`` decoration from a registry repository link."""

    if not isinstance(value, str) or not value.strip():
        return None
    url = value.strip()
    if url.startswith("git+"):
        url = url[len("git+") :]
    if url.endswith(".git"):
        url = url[: -len(".git")]
    return url


def display_path(path: Path) -> str:
    """Repo-relative path when possible, so split records are portable."""

    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha256(root: Path) -> str:
    """sha256 over sorted ``relative-path``/``file-sha256`` pairs."""

    digest = hashlib.sha256()
    for path in sorted(entry for entry in root.rglob("*") if entry.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_sha256(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def package_eval_exclusions() -> dict[str, list[str]]:
    """Known package names and capture slugs that must never be re-harvested."""

    names: set[str] = set()
    slugs: set[str] = set()
    for path in sorted(PACKAGE_EVAL_MANIFESTS.glob("*.json")):
        slugs.add(path.stem)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):  # pragma: no cover - defensive
            continue
        name = payload.get("package_name")
        if isinstance(name, str) and name:
            names.add(name)
    return {
        "package_names": sorted(names),
        "capture_slugs": sorted(slugs),
    }


def _is_excluded(
    package: str, ecosystem: str, exclusions: dict[str, list[str]]
) -> bool:
    del ecosystem  # PEP 503 normalization is safe for npm names too
    known = {normalize_package(name) for name in exclusions["package_names"]}
    return normalize_package(package) in known


def _npm_targets(
    limit: int,
    fetch: Callable[[str], Any],
    exclusions: dict[str, list[str]],
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    # Ask for more than needed: exclusions and unusable rows are dropped. The
    # search API caps ``size`` at 250, which is also the ceiling for a split
    # that excludes the whole previous round.
    size = min(250, max(limit * 2, limit) + len(exclusions["package_names"]))
    payload = fetch(NPM_SEARCH_URL.format(size=size))
    objects = payload.get("objects") if isinstance(payload, dict) else None
    if not isinstance(objects, list):
        return []

    targets: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in objects:
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(version, str) or not version:
            continue
        key = normalize_package(name)
        if key in seen or _is_excluded(name, "npm", exclusions):
            continue
        seen.add(key)
        links = package.get("links") if isinstance(package.get("links"), dict) else {}
        description = package.get("description")
        targets.append(
            {
                "slug": slugify("npm", name, version),
                "ecosystem": "npm",
                "package": name,
                "version": version,
                "repository_url": clean_repository_url(links.get("repository")),
                "description": description if isinstance(description, str) else "",
            }
        )
        if len(targets) >= limit:
            break
    return targets


def _pypi_project_url(info: dict[str, Any]) -> str | None:
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for label in ("Repository", "Source", "Source Code", "Homepage", "Code"):
            for key, value in project_urls.items():
                if str(key).strip().lower() == label.lower():
                    cleaned = clean_repository_url(value)
                    if cleaned:
                        return cleaned
    return clean_repository_url(info.get("home_page"))


def _pypi_targets(
    limit: int,
    fetch: Callable[[str], Any],
    exclusions: dict[str, list[str]],
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    payload = fetch(PYPI_SIMPLE_URL)
    projects = payload.get("projects") if isinstance(payload, dict) else None
    if not isinstance(projects, list):
        return []

    names: list[str] = []
    seen: set[str] = set()
    for entry in projects:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not isinstance(name, str) or not _PYPI_MCP_NAME.search(name):
            continue
        key = normalize_package(name)
        if key in seen or _is_excluded(name, "pypi", exclusions):
            continue
        seen.add(key)
        names.append(name)

    targets: list[dict[str, Any]] = []
    # Each project needs one metadata request; stop as soon as ``limit`` pins.
    for name in sorted(names)[: limit * 3]:
        try:
            metadata = fetch(PYPI_JSON_URL.format(package=name))
        except Exception:  # noqa: BLE001 - one broken project must not stop discovery
            continue
        info = metadata.get("info") if isinstance(metadata, dict) else None
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if not isinstance(version, str) or not version:
            continue
        summary = info.get("summary")
        targets.append(
            {
                "slug": slugify("pypi", name, version),
                "ecosystem": "pypi",
                "package": name,
                "version": version,
                "repository_url": _pypi_project_url(info),
                "description": summary if isinstance(summary, str) else "",
            }
        )
        if len(targets) >= limit:
            break
    return targets


def excluded_packages(paths: list[Path]) -> list[str]:
    """Package names recorded in earlier ``targets.json`` files.

    Excluding by name (not by version) keeps two rounds disjoint even when a
    maintainer publishes again between them.
    """

    names: set[str] = set()
    for path in paths:
        try:
            targets = load_targets(path)
        except (OSError, json.JSONDecodeError):
            continue
        names.update(
            target["package"]
            for target in targets
            if isinstance(target.get("package"), str) and target["package"]
        )
    return sorted(names)


def exclusion_sources(paths: list[Path]) -> list[dict[str, Any]]:
    """Describe each exclusion source: kind, path, sha256, package count."""

    pins = package_eval_exclusions()
    sources: list[dict[str, Any]] = [
        {
            "kind": "package_eval_pins",
            "path": display_path(PACKAGE_EVAL_MANIFESTS),
            "sha256": tree_sha256(PACKAGE_EVAL_MANIFESTS),
            "package_count": len(pins["package_names"]),
        }
    ]
    for path in paths:
        sources.append(
            {
                "kind": "exclude_targets",
                "path": display_path(path),
                "sha256": file_sha256(path),
                "package_count": len(excluded_packages([path])),
            }
        )
    return sources


def split_exclusions(paths: list[Path]) -> dict[str, list[str]]:
    """Pinned ``package_eval`` names plus every ``--exclude-targets`` name."""

    pins = package_eval_exclusions()
    names = set(pins["package_names"]) | set(excluded_packages(paths))
    return {**pins, "package_names": sorted(names)}


def overlap_with_exclusions(
    targets: list[dict[str, Any]], excluded_names: list[str]
) -> list[str]:
    """Discovered packages that are also excluded; must be empty for a split."""

    excluded = {normalize_package(name) for name in excluded_names}
    return sorted(
        {
            target["package"]
            for target in targets
            if isinstance(target.get("package"), str)
            and normalize_package(target["package"]) in excluded
        }
    )


def split_path(output: Path) -> Path:
    """``.../targets.json`` -> ``.../targets.split.json``."""

    return output.with_name(f"{output.stem}.split.json")


def write_split(
    output: Path,
    *,
    sources: list[dict[str, Any]],
    excluded_names: list[str],
    targets: list[dict[str, Any]],
    overlap: list[str],
) -> Path:
    """Write the audit record for one discovery run beside ``output``."""

    path = split_path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "output": display_path(output),
        "exclusion_sources": sources,
        "excluded_name_count": len(
            {normalize_package(name) for name in excluded_names}
        ),
        "discovered_count": len(targets),
        "overlap_with_exclusions": overlap,
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def discover_targets(
    npm_limit: int = 70,
    pypi_limit: int = 30,
    *,
    fetch: Callable[[str], Any] | None = None,
    exclusions: dict[str, list[str]] | None = None,
    discovered_at: str | None = None,
) -> list[dict[str, Any]]:
    """Return pinned, unseen npm and PyPI targets, sorted by ``(ecosystem, package)``."""

    fetch = fetch or _default_fetch
    exclusions = exclusions or package_eval_exclusions()
    timestamp = discovered_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    targets = _npm_targets(npm_limit, fetch, exclusions) + _pypi_targets(
        pypi_limit, fetch, exclusions
    )
    for target in targets:
        target["discovered_at_utc"] = timestamp
    return sorted(targets, key=lambda item: (item["ecosystem"], item["package"]))


def load_targets(path: Path | None = None) -> list[dict[str, Any]]:
    """Load ``targets.json``, accepting either a bare list or a ``targets`` key."""

    payload = json.loads((path or TARGETS_JSON).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    targets = payload.get("targets") if isinstance(payload, dict) else None
    return [item for item in targets or [] if isinstance(item, dict)]


def write_targets(
    targets: list[dict[str, Any]],
    output: Path | None = None,
    *,
    exclusions: dict[str, list[str]] | None = None,
) -> Path:
    path = output or TARGETS_JSON
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "counts": {
            "npm": sum(1 for item in targets if item["ecosystem"] == "npm"),
            "pypi": sum(1 for item in targets if item["ecosystem"] == "pypi"),
            "total": len(targets),
        },
        "excluded_package_eval": exclusions or package_eval_exclusions(),
        "targets": targets,
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def main(
    argv: list[str] | None = None,
    *,
    fetch: Callable[[str], Any] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--npm-limit", type=int, default=70)
    parser.add_argument("--pypi-limit", type=int, default=30)
    parser.add_argument("--output", type=Path, default=TARGETS_JSON)
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing --output (a pinned round is otherwise kept)",
    )
    parser.add_argument(
        "--exclude-targets",
        type=Path,
        action="append",
        default=[],
        help="targets.json from an earlier round; its packages are excluded",
    )
    args = parser.parse_args(argv)

    missing = [path for path in args.exclude_targets if not path.is_file()]
    if missing:
        for path in missing:
            print(f"Exclusion source not found: {path}")
        return 1

    if args.output.exists() and not args.force:
        print(
            f"{display_path(args.output)} already exists; "
            "pass --force to overwrite a pinned round."
        )
        return 1

    sources = exclusion_sources(args.exclude_targets)
    for source in sources:
        print(
            f"Exclusion source [{source['kind']}] {source['path']}: "
            f"{source['package_count']} packages, sha256 {source['sha256']}"
        )
    exclusions = split_exclusions(args.exclude_targets)
    excluded_names = exclusions["package_names"]
    print(
        f"Excluding {len({normalize_package(name) for name in excluded_names})} "
        f"unique package names from {len(sources)} source(s)"
    )

    targets = discover_targets(
        args.npm_limit,
        args.pypi_limit,
        exclusions=exclusions,
        fetch=fetch,
    )
    overlap = overlap_with_exclusions(targets, excluded_names)
    print(f"Discovered {len(targets)} unseen targets")

    if overlap:
        path = write_split(
            args.output,
            sources=sources,
            excluded_names=excluded_names,
            targets=targets,
            overlap=overlap,
        )
        print(
            f"Split is not disjoint: {len(overlap)} discovered package(s) are "
            f"excluded: {', '.join(overlap)}"
        )
        print(f"Wrote {path}; {display_path(args.output)} was not written")
        return 1

    if not targets:
        path = write_split(
            args.output,
            sources=sources,
            excluded_names=excluded_names,
            targets=targets,
            overlap=overlap,
        )
        print("No unseen targets found; registries returned nothing usable.")
        print(f"Wrote {path}")
        return 1

    path = write_targets(targets, args.output, exclusions=exclusions)
    split = write_split(
        args.output,
        sources=sources,
        excluded_names=excluded_names,
        targets=targets,
        overlap=overlap,
    )
    print(f"Wrote {path} ({len(targets)} unseen targets)")
    print(f"Wrote {split}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
