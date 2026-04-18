# tests/conftest.py
"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import pytest
from pathlib import Path


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).parent.parent / "examples" / "vulnerable_apps"


@pytest.fixture
def python_file(tmp_path: Path) -> Path:
    return tmp_path / "test_app.py"


@pytest.fixture
def ts_file(tmp_path: Path) -> Path:
    return tmp_path / "test_app.ts"


# tests/test_scanner.py
"""Tests for the core Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path

import pytest

from llmapp_shield.scanner import Scanner, ScanConfig
from llmapp_shield.models import Severity


class TestScanner:
    def _make_config(self, target: Path, **kwargs) -> ScanConfig:
        return ScanConfig(target=target, **kwargs)

    def test_scan_single_vulnerable_file(self, tmp_path: Path):
        """Scanner should find vulnerabilities in a vulnerable Python file."""
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text(
            'import openai\n'
            'openai.api_key = "sk-realkey123456789012345678901234567890AB"\n'
            'prompt = f"Answer: {user_input}"\n'
            'response = openai.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])\n'
        )

        config = self._make_config(vuln_file)
        scanner = Scanner(config)
        result = scanner.run()

        assert result.scanned_files == 1
        assert result.total_findings > 0

    def test_scan_empty_directory(self, tmp_path: Path):
        """Scanner should return 0 findings for an empty directory."""
        config = self._make_config(tmp_path)
        scanner = Scanner(config)
        result = scanner.run()
        assert result.total_findings == 0

    def test_scan_with_severity_filter(self, tmp_path: Path):
        """Scanner should respect minimum severity filter."""
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text(
            'openai.api_key = "sk-realkey123456789012345678901234567890AB"\n'
        )
        config = self._make_config(vuln_file, min_severity="critical")
        scanner = Scanner(config)
        result = scanner.run()
        # All findings should be critical or above
        for f in result.findings:
            assert f.severity == Severity.CRITICAL

    def test_scan_ignores_non_source_files(self, tmp_path: Path):
        """Scanner should not scan binary or unrecognized files."""
        (tmp_path / "data.json").write_text('{"key": "value"}')
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
        (tmp_path / "app.py").write_text("x = 1")  # Clean Python file

        config = self._make_config(tmp_path)
        scanner = Scanner(config)
        result = scanner.run()
        assert result.total_findings == 0

    def test_has_severity_threshold(self, tmp_path: Path):
        """has_severity should correctly identify threshold breaches."""
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text('openai.api_key = "sk-realkey123456789012345678901234567890AB"\n')

        config = self._make_config(vuln_file)
        scanner = Scanner(config)
        result = scanner.run()

        if result.critical_count > 0:
            assert result.has_severity("critical") is True
        assert result.has_severity("info") is True  # Everything has info or above
