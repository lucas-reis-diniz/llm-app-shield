# llmapp_shield/utils/ignore.py
"""
Ignore Filter — Respects .llmappignore files (like .gitignore).

Supports gitignore-style patterns using the pathspec library.
Auto-discovers .llmappignore in the target directory or parents.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import pathspec
    HAS_PATHSPEC = True
except ImportError:
    HAS_PATHSPEC = False


# Always ignore these paths regardless of .llmappignore
DEFAULT_IGNORE_PATTERNS = [
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    ".git/",
    ".hg/",
    ".svn/",
    "node_modules/",
    ".venv/",
    "venv/",
    "env/",
    ".env/",
    "dist/",
    "build/",
    "*.egg-info/",
    ".tox/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".pytest_cache/",
    "*.min.js",
    "*.bundle.js",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "*.lock",
]


class IgnoreFilter:
    """
    Filters file paths based on .llmappignore patterns.

    Merges default ignore patterns with user-defined patterns
    from .llmappignore files.
    """

    def __init__(
        self,
        ignore_file: Optional[Path] = None,
        root: Optional[Path] = None,
    ) -> None:
        self.root = root or Path.cwd()
        self._patterns: list[str] = list(DEFAULT_IGNORE_PATTERNS)

        # Auto-discover .llmappignore
        if ignore_file is None:
            ignore_file = self._find_ignore_file()

        if ignore_file and ignore_file.exists():
            self._patterns.extend(self._parse_ignore_file(ignore_file))

        # Build pathspec matcher
        if HAS_PATHSPEC:
            self._spec = pathspec.PathSpec.from_lines("gitwildmatch", self._patterns)
        else:
            self._spec = None

    def should_ignore(self, path: Path) -> bool:
        """Return True if the path should be ignored."""
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            relative = path

        path_str = str(relative).replace("\\", "/")

        if self._spec is not None:
            return self._spec.match_file(path_str)

        # Fallback: simple pattern matching
        for pattern in DEFAULT_IGNORE_PATTERNS:
            clean = pattern.rstrip("/").lstrip("*.")
            if clean and clean in path_str:
                return True
        return False

    def _find_ignore_file(self) -> Optional[Path]:
        """Walk up directory tree to find .llmappignore."""
        search_dir = self.root if self.root.is_dir() else self.root.parent
        for parent in [search_dir] + list(search_dir.parents):
            candidate = parent / ".llmappignore"
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _parse_ignore_file(path: Path) -> list[str]:
        """Parse .llmappignore file, stripping comments and blank lines."""
        patterns = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
        except OSError:
            pass
        return patterns
