# llmapp_shield/utils/file_utils.py
"""
File Collector — Discovers source files to scan.

Walks target directories, applies ignore filters,
and returns a deduplicated list of scannable file paths.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from llmapp_shield.utils.ignore import IgnoreFilter


# Supported file extensions per language
LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py"],
    "typescript": [".ts", ".tsx"],
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
}

# Hard size limit: skip files larger than 1 MB
MAX_FILE_SIZE_BYTES = 1_000_000


class FileCollector:
    """
    Discovers and collects source files for scanning.

    Handles both single-file targets and directory traversal,
    applying ignore patterns and language filters.
    """

    def __init__(self, target: Path, ignore_filter: Optional[IgnoreFilter] = None) -> None:
        self.target = target
        self.ignore_filter = ignore_filter or IgnoreFilter(root=target if target.is_dir() else target.parent)

    def collect(self, languages: Optional[list[str]] = None) -> list[Path]:
        """
        Collect all scannable files.

        Args:
            languages: List of language names to include. None = all supported.

        Returns:
            Sorted, deduplicated list of file paths.
        """
        # Build set of allowed extensions
        if languages:
            allowed_exts: set[str] = set()
            for lang in languages:
                allowed_exts.update(LANGUAGE_EXTENSIONS.get(lang, []))
        else:
            allowed_exts = {ext for exts in LANGUAGE_EXTENSIONS.values() for ext in exts}

        files: list[Path] = []

        if self.target.is_file():
            if self._is_acceptable(self.target, allowed_exts):
                files.append(self.target)
        elif self.target.is_dir():
            files.extend(self._walk_directory(self.target, allowed_exts))

        return sorted(set(files))

    def _walk_directory(self, directory: Path, allowed_exts: set[str]) -> list[Path]:
        """Recursively walk directory collecting matching files."""
        result: list[Path] = []

        try:
            for item in directory.iterdir():
                if self.ignore_filter.should_ignore(item):
                    continue

                if item.is_dir():
                    result.extend(self._walk_directory(item, allowed_exts))
                elif item.is_file() and self._is_acceptable(item, allowed_exts):
                    result.append(item)
        except PermissionError:
            pass

        return result

    def _is_acceptable(self, path: Path, allowed_exts: set[str]) -> bool:
        """Check if a file should be included in the scan."""
        # Extension check
        if path.suffix.lower() not in allowed_exts:
            return False

        # Size check
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                return False
        except OSError:
            return False

        # Ignore filter check
        if self.ignore_filter.should_ignore(path):
            return False

        return True
