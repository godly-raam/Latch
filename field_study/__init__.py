"""Unseen-package field study harness for ``mcpprobe`` (Latch).

Two phases, deliberately separated:

``discover_targets``
    Registry-only discovery of npm and PyPI MCP server packages that do **not**
    already appear in ``package_eval/captured_manifests/``.

``run_field_study --harvest``
    Launches each pinned package once, with a minimal environment and a strict
    timeout, and records its ``tools/list`` surface. This executes third-party
    code and belongs inside a disposable container.

``run_field_study --analyze``
    Runs Latch's static engines over the recorded captures. Offline, no package
    execution, deterministic output.
"""
