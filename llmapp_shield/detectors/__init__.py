# llmapp_shield/detectors/__init__.py
"""
Detectors package.

Each detector module specializes in a specific vulnerability category
from the OWASP LLM Top 10. All detectors share a common base class.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory


class BaseDetector(ABC):
    """
    Abstract base class for all vulnerability detectors.

    Subclasses implement the `analyze` method to detect specific
    categories of LLM security vulnerabilities in source code.
    """

    # Override in subclass
    CATEGORY: str = "generic"
    SUPPORTED_LANGUAGES: list[str] = ["python", "typescript", "javascript"]

    def analyze(
        self,
        source_code: str,
        file_path: Path,
        language: str,
        rules: list[Rule],
    ) -> list[Finding]:
        """
        Analyze source code for vulnerabilities.

        Args:
            source_code: Raw source text of the file.
            file_path: Path to the file being analyzed.
            language: Detected language ("python", "typescript", etc.)
            rules: List of all loaded rules (detector uses relevant subset).

        Returns:
            List of Finding objects for detected vulnerabilities.
        """
        if language not in self.SUPPORTED_LANGUAGES and "unknown" not in self.SUPPORTED_LANGUAGES:
            return []

        # Filter rules relevant to this detector
        relevant_rules = [
            r for r in rules
            if r.category == self.CATEGORY
            and r.enabled
            and (r.language is None or r.language == language)
        ]

        return self._detect(source_code, file_path, language, relevant_rules)

    @abstractmethod
    def _detect(
        self,
        source_code: str,
        file_path: Path,
        language: str,
        rules: list[Rule],
    ) -> list[Finding]:
        """Implement detection logic in subclasses."""
        ...

    def _regex_scan(
        self,
        source_code: str,
        file_path: Path,
        rule: Rule,
        extra_tags: Optional[list[str]] = None,
    ) -> list[Finding]:
        """
        Generic regex-based scan helper.

        Searches for pattern matches line by line and returns findings.
        """
        findings: list[Finding] = []
        lines = source_code.splitlines()

        try:
            compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            return []

        for match in compiled.finditer(source_code):
            # Calculate line number from match position
            line_num = source_code[: match.start()].count("\n") + 1
            col_num = match.start() - source_code.rfind("\n", 0, match.start()) - 1

            # Get surrounding code for snippet
            snippet_lines = lines[max(0, line_num - 2): line_num + 1]
            code_snippet = "\n".join(snippet_lines)

            owasp = None
            if rule.owasp_id:
                owasp = OWASPCategory(
                    id=rule.owasp_id,
                    name=rule.owasp_name or "",
                    url=f"https://owasp.org/www-project-top-10-for-large-language-model-applications/#{rule.owasp_id.lower()}",
                )

            finding = Finding(
                rule_id=rule.id,
                title=rule.name,
                severity=Severity(rule.severity),
                category=rule.category,
                owasp=owasp,
                file_path=file_path,
                line=line_num,
                column=col_num,
                code_snippet=code_snippet,
                description=rule.description,
                description_pt=rule.description_pt,
                recommendation=rule.recommendation,
                recommendation_pt=rule.recommendation_pt,
                fix_example=rule.fix_example,
                confidence=rule.confidence,
                references=rule.references,
                tags=(rule.tags or []) + (extra_tags or []),
                detected_by="regex",
            )
            findings.append(finding)

        return findings
