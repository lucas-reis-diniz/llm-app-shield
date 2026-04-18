# llmapp_shield/scanner.py
"""
Core Scanner — Orchestrates the full security analysis pipeline.

Flow:
  1. Discover files (respecting .llmappignore)
  2. For each file: run all applicable detectors
  3. Aggregate findings
  4. (Optional) Run LLM-as-Judge for semantic validation
  5. Return ScanResult
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from llmapp_shield.models import Finding, ScanResult, Severity
from llmapp_shield.rules.loader import RuleLoader
from llmapp_shield.utils.ignore import IgnoreFilter
from llmapp_shield.utils.file_utils import FileCollector


# Severity ordering for threshold comparisons
SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    target: Path
    min_severity: str = "low"
    fail_on: Optional[str] = None
    llm_judge: bool = False
    llm_provider: str = "ollama"
    llm_model: str = "llama3.2"
    llm_endpoint: str = "http://localhost:11434"
    ignore_file: Optional[Path] = None
    report_language: str = "en-US"
    verbose: bool = False
    output_format: str = "terminal"
    output_path: Optional[Path] = None
    languages: list[str] = field(default_factory=lambda: ["python", "typescript", "javascript"])


class Scanner:
    """
    Main scanner orchestrator.

    Discovers source files, runs all detectors, aggregates findings,
    and optionally applies LLM-as-Judge for semantic validation.
    """

    def __init__(self, config: ScanConfig, console: Optional[Console] = None) -> None:
        self.config = config
        self.console = console or Console()
        self.rule_loader = RuleLoader()
        self._findings: list[Finding] = []

    def run(self) -> ScanResult:
        """Execute the full scan pipeline and return results."""
        # Load ignore patterns
        ignore_filter = IgnoreFilter(self.config.ignore_file, self.config.target)

        # Collect files
        collector = FileCollector(self.config.target, ignore_filter)
        files = collector.collect(languages=self.config.languages)

        if self.config.verbose:
            self.console.print(f"[dim]📁 Found {len(files)} file(s) to scan[/dim]")

        # Load all rules
        rules = self.rule_loader.load_all()

        # Import detectors
        from llmapp_shield.detectors.prompt_injection import PromptInjectionDetector
        from llmapp_shield.detectors.data_leak import DataLeakDetector
        from llmapp_shield.detectors.insecure_output import InsecureOutputDetector
        from llmapp_shield.detectors.excessive_agency import ExcessiveAgencyDetector
        from llmapp_shield.detectors.rag_security import RAGSecurityDetector
        from llmapp_shield.detectors.secret_exposure import SecretExposureDetector
        from llmapp_shield.detectors.jailbreak import JailbreakDetector

        detectors = [
            PromptInjectionDetector(),
            DataLeakDetector(),
            InsecureOutputDetector(),
            ExcessiveAgencyDetector(),
            RAGSecurityDetector(),
            SecretExposureDetector(),
            JailbreakDetector(),
        ]

        all_findings: list[Finding] = []

        # Scan with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {len(files)} file(s)...", total=len(files)
            )

            for file_path in files:
                if self.config.verbose:
                    progress.print(f"[dim]  → {file_path}[/dim]")

                try:
                    source_code = file_path.read_text(encoding="utf-8", errors="replace")
                    lang = _detect_language(file_path)

                    for detector in detectors:
                        findings = detector.analyze(
                            source_code=source_code,
                            file_path=file_path,
                            language=lang,
                            rules=rules,
                        )
                        all_findings.extend(findings)

                except Exception as e:
                    if self.config.verbose:
                        self.console.print(f"[yellow]⚠️  Error scanning {file_path}: {e}[/yellow]")

                progress.advance(task)

        # Filter by minimum severity
        min_level = SEVERITY_ORDER.get(self.config.min_severity, 0)
        filtered = [
            f for f in all_findings
            if SEVERITY_ORDER.get(f.severity.value, 0) >= min_level
        ]

        # Optional: LLM Judge pass
        if self.config.llm_judge and filtered:
            filtered = self._run_llm_judge(filtered)

        # Deduplicate findings (same file + line + rule)
        seen: set[tuple[str, int, str]] = set()
        deduped: list[Finding] = []
        for f in filtered:
            key = (str(f.file_path), f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return ScanResult(
            findings=deduped,
            scanned_files=len(files),
            total_files_discovered=len(files),
            config=self.config,
        )

    def _run_llm_judge(self, findings: list[Finding]) -> list[Finding]:
        """
        Optional: Use a local LLM (Ollama) or Groq to validate findings semantically.
        Filters out likely false positives.
        """
        try:
            from llmapp_shield.utils.llm_judge import LLMJudge

            judge = LLMJudge(
                provider=self.config.llm_provider,
                model=self.config.llm_model,
                endpoint=self.config.llm_endpoint,
            )
            self.console.print("[dim]🤖 Running LLM-as-Judge validation...[/dim]")
            return judge.validate(findings)
        except Exception as e:
            self.console.print(f"[yellow]⚠️  LLM Judge unavailable: {e}. Skipping.[/yellow]")
            return findings


def _detect_language(file_path: Path) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
    }
    return ext_map.get(file_path.suffix.lower(), "unknown")
