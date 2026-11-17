"""Guard the supported floor: every source file must parse on Python 3.11.

PEP 701 (Python 3.12) relaxed f-strings so an expression may contain a
backslash, a nested string with the same quote, or a comment. That syntax is a
``SyntaxError`` on 3.11, which the project still supports, and a 3.12+ dev
environment accepts it silently. This test tokenizes every Python file in the
repository and fails on PEP 701-only constructs, so CI on the floor version
cannot be the first place the problem shows up.
"""

from __future__ import annotations

import io
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE_DIRS = (
    "mcpprobe",
    "tests",
    "benchmark",
    "package_eval",
    "synthetic_regression",
    "adversarial",
    "head_to_head",
)

_FSTRING_OPENERS = {"FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"}
#: Token types that only exist once the tokenizer understands 3.12 f-strings.
_FSTRING_TOKEN_NAMES = {name for name in _FSTRING_OPENERS if hasattr(tokenize, name)}


def python_files() -> list[Path]:
    files: list[Path] = []
    for directory in SOURCE_DIRS:
        files.extend(sorted((ROOT / directory).rglob("*.py")))
    return files


def fstring_expression_backslashes(path: Path) -> list[str]:
    """Return one message per backslash found inside an f-string expression."""

    source = path.read_text(encoding="utf-8")
    problems: list[str] = []
    depth = 0
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        name = tokenize.tok_name[token.type]
        if name == "FSTRING_START":
            depth += 1
            continue
        if name == "FSTRING_END":
            depth -= 1
            continue
        # ``FSTRING_MIDDLE`` is literal text, where a backslash is fine.
        if depth and name != "FSTRING_MIDDLE" and "\\" in token.string:
            problems.append(f"line {token.start[0]}: {token.string!r}")
    return problems


def test_no_pep701_fstring_expressions() -> None:
    files = python_files()

    assert files, "no Python files discovered"
    assert any(path.name == "test_transport.py" for path in files)

    problems = {
        str(path.relative_to(ROOT)): found
        for path in files
        if (found := fstring_expression_backslashes(path))
    }

    assert problems == {}


def test_every_source_file_compiles() -> None:
    for path in python_files():
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
