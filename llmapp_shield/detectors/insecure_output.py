# llmapp_shield/detectors/insecure_output.py
"""
Insecure Output Handling Detector — OWASP LLM02.

Detects patterns where LLM output is used without proper sanitization,
enabling XSS, SQL injection, SSRF, or code execution via model output.

Covers:
- LLM output rendered directly as HTML (XSS)
- LLM output used in SQL queries (SQL injection via LLM)
- LLM output executed as code (eval, exec, subprocess)
- LLM output used in OS commands
- Missing output length/content validation
- Direct use of LLM-generated URLs in requests
"""

from __future__ import annotations

import re
from pathlib import Path

from llmapp_shield.detectors import BaseDetector
from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory


_OWASP_LLM02 = OWASPCategory(
    id="LLM02",
    name="Insecure Output Handling",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/llm02-insecure-output-handling",
)

# Variables that typically hold LLM output
_LLM_OUTPUT_VARS = (
    r"(?:llm_response|ai_response|aiResponse|llmResponse|modelResponse|model_response|completion|response|output|"
    r"generated|result|answer|generated_text|llm_output|ai_output|bot_response|"
    r"chat_response|gpt_response|claude_response)"
)

# Python patterns
_PYTHON_DANGEROUS_OUTPUT_PATTERNS: list[tuple[str, str, str, Severity]] = [
    (
        "LLM02-XSS-001",
        rf"(?:render_template_string|Markup|mark_safe|format_html)\s*\(\s*{_LLM_OUTPUT_VARS}",
        "LLM output rendered as raw HTML (XSS risk)",
        Severity.CRITICAL,
    ),
    (
        "LLM02-EVAL-001",
        rf"(?:eval|exec|compile)\s*\(\s*{_LLM_OUTPUT_VARS}",
        "LLM output passed to eval/exec (Remote Code Execution risk)",
        Severity.CRITICAL,
    ),
    (
        "LLM02-SQL-001",
        rf"(?:cursor\.execute|db\.execute|engine\.execute|session\.execute)\s*\(.*?{_LLM_OUTPUT_VARS}",
        "LLM output interpolated into SQL query (SQL Injection via LLM)",
        Severity.CRITICAL,
    ),
    (
        "LLM02-OS-001",
        rf"(?:os\.system|subprocess\.(?:run|call|check_output|Popen)|os\.popen)\s*\(\s*(?:f[\"'].*{_LLM_OUTPUT_VARS}|{_LLM_OUTPUT_VARS})",
        "LLM output used in OS/shell command (Command Injection risk)",
        Severity.CRITICAL,
    ),
    (
        "LLM02-SSRF-001",
        rf"(?:requests\.(?:get|post|put)|httpx\.(?:get|post)|urllib\.request\.urlopen)\s*\(\s*{_LLM_OUTPUT_VARS}",
        "LLM output used as URL in HTTP request (SSRF risk)",
        Severity.HIGH,
    ),
    (
        "LLM02-TEMPLATE-001",
        rf"(?:jinja2\.Template|Template)\s*\(\s*{_LLM_OUTPUT_VARS}\s*\)\.render",
        "LLM output used as Jinja2 template (Server-Side Template Injection risk)",
        Severity.CRITICAL,
    ),
    (
        "LLM02-FILE-001",
        rf"(?:open|write_text|write_bytes)\s*\(\s*{_LLM_OUTPUT_VARS}",
        "LLM output written directly to file without validation",
        Severity.MEDIUM,
    ),
    (
        "LLM02-PICKLE-001",
        rf"(?:pickle\.loads|pickle\.load|dill\.loads)\s*\(\s*{_LLM_OUTPUT_VARS}",
        "LLM output deserialized with pickle (arbitrary code execution risk)",
        Severity.CRITICAL,
    ),
]

# TypeScript/JavaScript patterns
_TS_DANGEROUS_OUTPUT_PATTERNS: list[tuple[str, str, str, Severity]] = [
    (
        "LLM02-XSS-TS-001",
        r"(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)\s*[=:]\s*(?:\{?\s*__html\s*:\s*)?" + _LLM_OUTPUT_VARS,
        "LLM output set as innerHTML/dangerouslySetInnerHTML (XSS risk)",
        Severity.CRITICAL,
    ),
    (
        "LLM02-EVAL-TS-001",
        r"(?:eval|new Function|setTimeout|setInterval)\s*\(\s*" + _LLM_OUTPUT_VARS,
        "LLM output passed to eval/Function constructor (Code Execution risk)",
        Severity.CRITICAL,
    ),
    (
        "LLM02-SQL-TS-001",
        r"(?:db\.query|pool\.query|client\.query|connection\.query)\s*\(\s*[`\"\'].*\$\{" + _LLM_OUTPUT_VARS,
        "LLM output interpolated into SQL query (SQL Injection via LLM)",
        Severity.CRITICAL,
    ),
]


class InsecureOutputDetector(BaseDetector):
    """
    Detects Insecure Output Handling vulnerabilities (OWASP LLM02).

    Finds cases where LLM-generated content is used in dangerous contexts
    without proper validation, sanitization, or escaping.
    """

    CATEGORY = "insecure_output"

    def _detect(
        self,
        source_code: str,
        file_path: Path,
        language: str,
        rules: list[Rule],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Rule-based scan
        for rule in rules:
            if rule.pattern_type == "regex":
                findings.extend(self._regex_scan(source_code, file_path, rule))

        # Built-in pattern detection
        if language == "python":
            findings.extend(self._detect_dangerous_patterns(
                source_code, file_path, _PYTHON_DANGEROUS_OUTPUT_PATTERNS
            ))
        elif language in ("typescript", "javascript"):
            findings.extend(self._detect_dangerous_patterns(
                source_code, file_path, _TS_DANGEROUS_OUTPUT_PATTERNS
            ))

        return findings

    def _detect_dangerous_patterns(
        self,
        source_code: str,
        file_path: Path,
        patterns: list[tuple[str, str, str, Severity]],
    ) -> list[Finding]:
        """Detect dangerous output handling patterns."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        for rule_id, pattern, description, severity in patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Skip comments
                    stripped = line_text.lstrip()
                    if stripped.startswith("#") or stripped.startswith("//"):
                        continue

                    snippet = "\n".join(lines[max(0, line_num - 3): min(len(lines), line_num + 2)])

                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=f"Insecure LLM Output Usage: {_short_desc(description)}",
                            severity=severity,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM02,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=(
                                f"{description}. LLM output should never be trusted as safe input "
                                "for sensitive operations. Models can be manipulated to generate "
                                "malicious content (indirect prompt injection)."
                            ),
                            description_pt=(
                                f"{description}. A saída do LLM nunca deve ser tratada como entrada "
                                "segura para operações sensíveis. Modelos podem ser manipulados para "
                                "gerar conteúdo malicioso (injeção indireta de prompt)."
                            ),
                            recommendation=_get_recommendation(rule_id),
                            recommendation_pt=_get_recommendation_pt(rule_id),
                            fix_example=_get_fix_example(rule_id),
                            confidence=0.85,
                            references=[
                                "https://owasp.org/www-project-top-10-for-large-language-model-applications/llm02-insecure-output-handling",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            ],
                            tags=["insecure-output", "llm02", _tag_from_rule_id(rule_id)],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue

        return findings


def _short_desc(description: str) -> str:
    return description.split("(")[0].strip()


def _tag_from_rule_id(rule_id: str) -> str:
    mapping = {
        "XSS": "xss",
        "EVAL": "code-execution",
        "SQL": "sql-injection",
        "OS": "command-injection",
        "SSRF": "ssrf",
        "TEMPLATE": "ssti",
        "FILE": "file-write",
        "PICKLE": "deserialization",
    }
    for key, tag in mapping.items():
        if key in rule_id:
            return tag
    return "insecure-output"


def _get_recommendation(rule_id: str) -> str:
    recs = {
        "XSS": "Use a proper HTML templating engine with auto-escaping (Jinja2 with autoescape=True). Never render LLM output as raw HTML.",
        "EVAL": "Never execute LLM output as code. If code execution is required, use a sandboxed environment (RestrictedPython, Docker, etc.).",
        "SQL": "Use parameterized queries or an ORM. Never interpolate LLM output directly into SQL strings.",
        "OS": "Never pass LLM output to OS commands. Use subprocess with a list of arguments (not a shell string) and validate all inputs.",
        "SSRF": "Validate and whitelist URLs before making HTTP requests with LLM-generated URLs. Use an allowlist of trusted domains.",
        "TEMPLATE": "Never use LLM output as a template string. Treat it as data only.",
        "FILE": "Validate file paths and content before writing. Use strict path validation and content scanning.",
        "PICKLE": "Never deserialize LLM output. Use safe serialization formats (JSON) for any data exchange.",
    }
    for key, rec in recs.items():
        if key in rule_id:
            return rec
    return "Validate and sanitize all LLM output before use in sensitive operations."


def _get_recommendation_pt(rule_id: str) -> str:
    recs = {
        "XSS": "Use um motor de template HTML com auto-escape (Jinja2 com autoescape=True). Nunca renderize saída do LLM como HTML bruto.",
        "EVAL": "Nunca execute saída do LLM como código. Se execução de código for necessária, use um ambiente sandboxed.",
        "SQL": "Use queries parametrizadas ou um ORM. Nunca interpole saída do LLM diretamente em strings SQL.",
        "OS": "Nunca passe saída do LLM para comandos OS. Use subprocess com lista de argumentos e valide todas as entradas.",
        "SSRF": "Valide e use allowlist de URLs antes de fazer requisições HTTP com URLs geradas pelo LLM.",
    }
    for key, rec in recs.items():
        if key in rule_id:
            return rec
    return "Valide e sanitize toda saída do LLM antes de usar em operações sensíveis."


def _get_fix_example(rule_id: str) -> str:
    if "XSS" in rule_id:
        return '''
# ❌ VULNERABLE — LLM output as raw HTML
return render_template_string(llm_response)  # XSS!

# ✅ SECURE — Escape HTML output
from markupsafe import escape
from bleach import clean

# Option 1: Escape all HTML (safest)
safe_output = escape(llm_response)
return render_template("result.html", content=safe_output)

# Option 2: Allow only safe HTML tags (for rich text use cases)
ALLOWED_TAGS = ["b", "i", "em", "strong", "p", "br"]
safe_output = clean(llm_response, tags=ALLOWED_TAGS, strip=True)
'''
    if "EVAL" in rule_id:
        return '''
# ❌ VULNERABLE — Executing LLM output
eval(llm_response)  # Remote Code Execution!
exec(generated_code)

# ✅ SECURE — Use a sandbox if code execution is truly needed
from RestrictedPython import compile_restricted, safe_globals

def safe_exec(code: str) -> dict:
    byte_code = compile_restricted(code, "<string>", "exec")
    local_vars: dict = {}
    exec(byte_code, safe_globals, local_vars)  # noqa: S102
    return local_vars

# Better: Avoid executing LLM output entirely
# Parse structured output (JSON) instead of arbitrary code
'''
    if "SQL" in rule_id:
        return '''
# ❌ VULNERABLE — LLM output in SQL
query = f"SELECT * FROM users WHERE name = '{llm_response}'"
cursor.execute(query)  # SQL Injection!

# ✅ SECURE — Parameterized queries
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (sanitized_value,))  # Always parameterize

# Or better: Don't use LLM output for SQL at all
# Extract structured data from LLM and validate strictly
'''
    return '''
# Validate LLM output before use:
# 1. Check output length
# 2. Validate against expected format/schema
# 3. Sanitize for the specific context (HTML, SQL, shell, etc.)
# 4. Never trust LLM output as inherently safe
'''