# tests/test_scanner.py
"""Tests for the core Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path


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
        vuln_file.write_text('openai.api_key = "sk-realkey123456789012345678901234567890AB"\n')
        config = self._make_config(vuln_file, min_severity="critical")
        scanner = Scanner(config)
        result = scanner.run()
        for f in result.findings:
            assert f.severity == Severity.CRITICAL

    def test_scan_ignores_non_source_files(self, tmp_path: Path):
        """Scanner should not scan binary or unrecognized files."""
        (tmp_path / "data.json").write_text('{"key": "value"}')
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
        (tmp_path / "clean.py").write_text("x = 1 + 1\nprint(x)\n")

        config = self._make_config(tmp_path)
        scanner = Scanner(config)
        result = scanner.run()
        assert result.total_findings == 0

    def test_scan_respects_llmappignore(self, tmp_path: Path):
        """Scanner should respect .llmappignore patterns."""
        # Create ignored subdir
        ignored_dir = tmp_path / "node_modules"
        ignored_dir.mkdir()
        (ignored_dir / "vuln.py").write_text(
            'openai.api_key = "sk-realkey123456789012345678901234567890AB"\n'
        )
        # Clean file in main dir
        (tmp_path / "clean.py").write_text("x = 1\n")

        config = self._make_config(tmp_path)
        scanner = Scanner(config)
        result = scanner.run()
        assert result.total_findings == 0  # node_modules ignored

    def test_has_severity_threshold(self, tmp_path: Path):
        vuln_file = tmp_path / "app.py"
        vuln_file.write_text('openai.api_key = "sk-realkey123456789012345678901234567890AB"\n')
        config = self._make_config(vuln_file)
        scanner = Scanner(config)
        result = scanner.run()
        assert result.has_severity("info") is True

    def test_deduplication(self, tmp_path: Path):
        """Duplicate findings (same file+line+rule) should be removed."""
        vuln_file = tmp_path / "app.py"
        # Same vulnerable pattern repeated could produce duplicates
        vuln_file.write_text(
            'openai.api_key = "sk-realkey123456789012345678901234567890AB"\n'
        )
        config = self._make_config(vuln_file)
        scanner = Scanner(config)
        result = scanner.run()

        # Check for duplicates: same (file, line, rule_id)
        seen: set[tuple[str, int, str]] = set()
        for f in result.findings:
            key = (str(f.file_path), f.line, f.rule_id)
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)