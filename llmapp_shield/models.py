# llmapp_shield/models.py
"""
Core data models for LLMAppShield.

All models use Pydantic v2 for validation and serialization.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

class Severity(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def emoji(self) -> str:
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "red bold",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }[self.value]

    @property
    def order(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class OWASPCategory(BaseModel):
    """OWASP LLM Top 10 category reference."""
    id: str = Field(..., description="e.g. LLM01")
    name: str
    url: str = ""


class Finding(BaseModel):
    """
    A single security vulnerability finding.

    Represents one detected issue in the scanned source code,
    including location, severity, explanation, and suggested fix.
    """

    rule_id: str = Field(..., description="Unique rule identifier, e.g. LLM01-001")
    title: str
    severity: Severity
    category: str = Field(..., description="Detector category slug")
    owasp: Optional[OWASPCategory] = None

    # Location
    file_path: Path
    line: int = 0
    column: int = 0
    code_snippet: str = ""

    # Explanation
    description: str
    description_pt: str = ""  # Portuguese translation
    recommendation: str = ""
    recommendation_pt: str = ""
    fix_example: str = ""

    # Metadata
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    false_positive_likelihood: float = Field(default=0.1, ge=0.0, le=1.0)
    detected_by: str = "static_analysis"  # or "llm_judge", "regex"

    @field_validator("line", "column", mode="before")
    @classmethod
    def ensure_non_negative(cls, v: Any) -> int:
        return max(0, int(v or 0))

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        data = self.model_dump()
        data["file_path"] = str(self.file_path)
        data["severity"] = self.severity.value
        return data


class ScanResult(BaseModel):
    """
    Complete results of a security scan.

    Aggregates all findings across all scanned files,
    organized by severity and category.
    """

    model_config = {"arbitrary_types_allowed": True}

    findings: list[Finding] = Field(default_factory=list)
    scanned_files: int = 0
    total_files_discovered: int = 0
    config: Any = None  # ScanConfig — avoid circular import
    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    @property
    def by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.category, []).append(f)
        return result

    @property
    def by_file(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(str(f.file_path), []).append(f)
        return result

    def has_severity(self, severity: str) -> bool:
        """Check if any finding exists at or above the given severity level."""
        from llmapp_shield.scanner import SEVERITY_ORDER
        threshold = SEVERITY_ORDER.get(severity, 0)
        return any(
            SEVERITY_ORDER.get(f.severity.value, 0) >= threshold
            for f in self.findings
        )

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted by severity (highest first), then by file."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.order, str(f.file_path), f.line),
        )


class Rule(BaseModel):
    """
    A detection rule loaded from YAML.

    Rules are the declarative definitions of what patterns to look for.
    Each rule maps to one or more detectors.
    """

    id: str
    name: str
    category: str
    severity: str
    language: Optional[str] = None  # None means "any"
    description: str = ""
    description_pt: str = ""
    pattern: str = ""  # Regex or AST pattern
    pattern_type: str = "regex"  # regex, ast, semgrep
    recommendation: str = ""
    recommendation_pt: str = ""
    fix_example: str = ""
    owasp_id: Optional[str] = None
    owasp_name: Optional[str] = None
    confidence: float = 0.8
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
