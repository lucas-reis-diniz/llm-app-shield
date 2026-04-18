# llmapp_shield/detectors/secret_exposure.py
"""
Secret Exposure Detector — OWASP LLM06 / Supply Chain.

Detects API keys, tokens, and credentials hardcoded in LLM application code,
prompt templates, or configuration files.
"""

from __future__ import annotations

import re
from pathlib import Path

from llmapp_shield.detectors import BaseDetector
from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory

_OWASP = OWASPCategory(
    id="LLM06",
    name="Sensitive Information Disclosure",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
)

# Known API key patterns for LLM providers
_SECRET_PATTERNS: list[tuple[str, str, str, Severity]] = [
    ("SEC-OPENAI-001", r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key hardcoded", Severity.CRITICAL),
    ("SEC-OPENAI-PROJ-001", r"sk-proj-[a-zA-Z0-9_\-]{50,}", "OpenAI Project API key hardcoded", Severity.CRITICAL),
    ("SEC-ANTHROPIC-001", r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API key hardcoded", Severity.CRITICAL),
    ("SEC-GROQ-001", r"gsk_[a-zA-Z0-9]{50,}", "Groq API key hardcoded", Severity.CRITICAL),
    ("SEC-HUGGINGFACE-001", r"hf_[a-zA-Z0-9]{30,}", "HuggingFace token hardcoded", Severity.HIGH),
    ("SEC-COHERE-001", r"[a-zA-Z0-9]{40}(?=-cohere)", "Cohere API key pattern", Severity.HIGH),
    ("SEC-PINECONE-001", r"[a-zA-Z0-9\-]{36}-[a-zA-Z0-9]{8}", "Pinecone API key pattern", Severity.HIGH),
    ("SEC-AWS-001", r"AKIA[0-9A-Z]{16}", "AWS Access Key hardcoded", Severity.CRITICAL),
    ("SEC-GCP-001", r"AIza[0-9A-Za-z\-_]{35}", "Google API key hardcoded", Severity.HIGH),
    (
        "SEC-GENERIC-001",
        r'(?:api[_\-]?key|secret[_\-]?key|auth[_\-]?token|access[_\-]?token)\s*[=:]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
        "Generic API key or secret hardcoded in code",
        Severity.HIGH,
    ),
    (
        "SEC-PASSWORD-001",
        r'(?:password|passwd|pwd|db_pass|database_password)\s*[=:]\s*["\'][^"\']{4,}["\']',
        "Password hardcoded in source code",
        Severity.CRITICAL,
    ),
    (
        "SEC-BEARER-001",
        r'["\']?[Bb]earer\s+[a-zA-Z0-9\-_\.]{20,}["\']?',
        "Bearer token hardcoded in source code",
        Severity.HIGH,
    ),
]


class SecretExposureDetector(BaseDetector):
    CATEGORY = "secret_exposure"

    def _detect(self, source_code: str, file_path: Path, language: str, rules: list[Rule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if rule.pattern_type == "regex":
                findings.extend(self._regex_scan(source_code, file_path, rule))

        lines = source_code.splitlines()
        for rule_id, pattern, description, severity in _SECRET_PATTERNS:
            try:
                compiled = re.compile(pattern, re.MULTILINE)
                for match in compiled.finditer(source_code):
                    matched = match.group(0)
                    # Skip obvious placeholders
                    if any(p in matched.lower() for p in ["xxx", "your_", "example", "replace", "placeholder", "<"]):
                        continue
                    # Skip test files for lower-severity findings
                    if severity in (Severity.LOW, Severity.MEDIUM) and _is_test_file(file_path):
                        continue

                    line_num = source_code[: match.start()].count("\n") + 1
                    snippet = "\n".join(lines[max(0, line_num - 2): min(len(lines), line_num + 1)])

                    findings.append(Finding(
                        rule_id=rule_id,
                        title=f"Hardcoded Secret: {description}",
                        severity=severity,
                        category=self.CATEGORY,
                        owasp=_OWASP,
                        file_path=file_path,
                        line=line_num,
                        column=0,
                        code_snippet=snippet,
                        description=f"{description}. Hardcoded credentials can be extracted from source code, version control history, or logs.",
                        description_pt=f"{description}. Credenciais hardcoded podem ser extraídas do código-fonte, histórico do git ou logs.",
                        recommendation=(
                            "Move all secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). "
                            "Rotate the exposed credential immediately. Add pre-commit hooks (git-secrets, detect-secrets) to prevent future exposure."
                        ),
                        fix_example=_FIX_SECRETS,
                        confidence=0.90,
                        tags=["secret", "credential", "hardcoded", "llm06"],
                        detected_by="regex",
                    ))
            except re.error:
                continue
        return findings


def _is_test_file(path: Path) -> bool:
    return any(s in str(path).lower() for s in ["test", "spec", "fixture", "mock"])


_FIX_SECRETS = '''
# ❌ VULNERABLE — API key hardcoded
import openai
openai.api_key = "sk-abc123yourrealkey"  # CRITICAL: visible in git history!

client = anthropic.Anthropic(api_key="sk-ant-yourrealkey")

# ✅ SECURE — Use environment variables
import os
from anthropic import Anthropic

client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

# Or use python-dotenv for local development
from dotenv import load_dotenv
load_dotenv()  # Reads from .env file (add .env to .gitignore!)
client = Anthropic()  # Auto-reads ANTHROPIC_API_KEY from env

# ✅ ALSO: Add to .gitignore
# .env
# *.key
# secrets/

# ✅ Rotate immediately if you\'ve committed a key
# 1. Revoke the key at platform.openai.com / console.anthropic.com
# 2. Remove from git history: git-filter-repo or BFG Repo Cleaner
# 3. Generate new key and store in secrets manager
'''
