# llmapp_shield/detectors/jailbreak.py
"""
Jailbreak Pattern Detector.

Detects known jailbreak phrases and prompt patterns embedded in system prompts,
templates, or test code that could indicate the application is vulnerable to
jailbreak attacks or is actively testing/using jailbreak techniques.

This detector is intentionally conservative — it flags code that contains
known jailbreak patterns (DAN, roleplay overrides, etc.) which should NOT
appear in production system prompts or application code.
"""

from __future__ import annotations

import re
from pathlib import Path

from llmapp_shield.detectors import BaseDetector
from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory

_OWASP = OWASPCategory(
    id="LLM01",
    name="Prompt Injection / Jailbreak",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
)

# Known jailbreak phrases and patterns
_JAILBREAK_PATTERNS: list[tuple[str, str, Severity]] = [
    # DAN and similar override attempts
    (r"(?:do anything now|DAN mode|DAN prompt)", "DAN jailbreak pattern detected in code", Severity.HIGH),
    (r"(?:ignore (?:all )?(?:previous|above|prior) instructions?)", "Instruction override jailbreak pattern", Severity.HIGH),
    (r"(?:you are now|pretend (?:you are|to be)|act as if you(?:'re| are)) (?:a|an) (?:evil|unrestricted|unfiltered|uncensored)", "Roleplay jailbreak for unrestricted AI", Severity.HIGH),
    (r"(?:jailbreak|jail-break|jail break)(?:ed|ing)? (?:mode|prompt|version)", "Explicit jailbreak mode reference", Severity.HIGH),
    (r"(?:developer mode|devmode|god mode|unrestricted mode)", "Developer/God mode jailbreak attempt", Severity.MEDIUM),
    (r"(?:forget|ignore|disregard|bypass) (?:your|all) (?:safety|ethical|content) (?:guidelines|filters|restrictions|training)", "Safety filter bypass attempt", Severity.CRITICAL),
    (r"your (?:new|true|real|actual) (?:name|identity|persona) is", "Identity override pattern", Severity.HIGH),
    (r"(?:as an AI without restrictions|without any (?:restrictions|limitations|filters))", "Restriction removal pattern", Severity.HIGH),
    (r"(?:hypothetically|in a fictional story|roleplay where) (?:you|an AI) (?:can|could|would) (?:help|provide|give)", "Fictional context bypass", Severity.MEDIUM),
    # System prompt extraction
    (r"(?:reveal|show|print|output|tell me) (?:your|the) (?:system|initial|base) (?:prompt|instructions?)", "System prompt extraction attempt", Severity.HIGH),
    (r"(?:what (?:are|were) your|repeat your) (?:instructions?|system prompt|initial prompt)", "System prompt extraction attempt", Severity.HIGH),
]


class JailbreakDetector(BaseDetector):
    """
    Detects jailbreak patterns in application code.

    Flags code that contains known jailbreak phrases — these should
    never appear in production system prompts or LLM templates.
    """

    CATEGORY = "jailbreak"

    def _detect(self, source_code: str, file_path: Path, language: str, rules: list[Rule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if rule.pattern_type == "regex":
                findings.extend(self._regex_scan(source_code, file_path, rule))

        lines = source_code.splitlines()
        for pattern, description, severity in _JAILBREAK_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Only flag if inside a string (prompt) or comment context
                    if not _is_in_string_context(line_text, match.group(0)):
                        continue

                    snippet = "\n".join(lines[max(0, line_num - 2): min(len(lines), line_num + 2)])
                    findings.append(Finding(
                        rule_id="JB-001",
                        title=f"Jailbreak Pattern in Code: {description.split('—')[0].strip()}",
                        severity=severity,
                        category=self.CATEGORY,
                        owasp=_OWASP,
                        file_path=file_path,
                        line=line_num,
                        column=0,
                        code_snippet=snippet,
                        description=(
                            f"{description}. Jailbreak patterns in production code may indicate "
                            "the application is vulnerable to injection attacks or contains "
                            "insecure prompt engineering practices."
                        ),
                        description_pt=(
                            f"{description}. Padrões de jailbreak no código de produção podem indicar "
                            "que a aplicação é vulnerável a ataques de injeção ou contém práticas "
                            "inseguras de engenharia de prompt."
                        ),
                        recommendation=(
                            "Remove jailbreak patterns from production code. "
                            "If testing jailbreak resistance, do so in isolated test environments. "
                            "Implement output content filtering and system prompt protection."
                        ),
                        fix_example="# Remove jailbreak patterns from prompts and code.\n# If testing, use dedicated red-team environments, not production code.",
                        confidence=0.70,  # Slightly lower — could be test code
                        tags=["jailbreak", "prompt-injection", "llm01"],
                        detected_by="regex",
                    ))
            except re.error:
                continue
        return findings


def _is_in_string_context(line: str, matched: str) -> bool:
    """Heuristic: check if the match is likely inside a string literal."""
    # If the line contains quotes before the match position, likely in string
    quote_count = line.count('"') + line.count("'") + line.count("`")
    return quote_count >= 1 or "#" in line or "//" in line
