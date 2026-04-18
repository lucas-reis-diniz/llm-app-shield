# llmapp_shield/detectors/data_leak.py
"""
Data Leak & PII Detector — OWASP LLM06.

Detects patterns that may cause sensitive data or PII (Personally Identifiable
Information) to leak through LLM calls, logs, or responses.

Covers:
- Brazilian PII: CPF, CNPJ, RG, passaporte
- International PII: SSN, credit card numbers, passport numbers
- API keys / secrets hardcoded in prompt templates
- Database credentials in LLM context
- User PII passed directly to external LLM APIs
- Logging of LLM inputs/outputs containing sensitive data
"""

from __future__ import annotations

import re
from pathlib import Path

from llmapp_shield.detectors import BaseDetector
from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory


_OWASP_LLM06 = OWASPCategory(
    id="LLM06",
    name="Sensitive Information Disclosure",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/llm06-sensitive-information-disclosure",
)

# PII patterns with regex
_PII_PATTERNS: list[tuple[str, str, str, Severity]] = [
    # (rule_id, pattern, description, severity)

    # Brazilian CPF: 000.000.000-00 or 00000000000
    (
        "LLM06-CPF-001",
        r"\b\d{3}[.\-]?\d{3}[.\-]?\d{3}[.\-]?\d{2}\b",
        "Brazilian CPF number detected in source code or prompt template",
        Severity.HIGH,
    ),
    # Brazilian CNPJ: 00.000.000/0000-00
    (
        "LLM06-CNPJ-001",
        r"\b\d{2}[.\-]?\d{3}[.\-]?\d{3}[/]?\d{4}[.\-]?\d{2}\b",
        "Brazilian CNPJ number detected in source code or prompt template",
        Severity.HIGH,
    ),
    # US SSN: 000-00-0000
    (
        "LLM06-SSN-001",
        r"\b\d{3}[-]\d{2}[-]\d{4}\b",
        "US Social Security Number (SSN) pattern detected",
        Severity.HIGH,
    ),
    # Credit card: 16-digit groups (Visa/MC/Amex/Discover)
    (
        "LLM06-CC-001",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "Credit card number pattern detected in source code",
        Severity.CRITICAL,
    ),
    # Email addresses in prompt templates / hardcoded
    (
        "LLM06-EMAIL-001",
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "Email address hardcoded in prompt template or source",
        Severity.MEDIUM,
    ),
]

# Patterns for passing PII variables to LLM APIs
_PII_VARIABLE_PATTERNS = [
    # Sending PII fields to LLM
    r'(?:cpf|cnpj|ssn|social_security|credit_card|card_number|passwd|password|senha)\s*[=:]\s*\S+',
    r'(?:cpf|cnpj|ssn|cc_number|card_num).*(?:llm|openai|anthropic|groq|llm\.invoke)',

    # PII in prompt/context
    r'(?:prompt|context|messages).*(?:cpf|cnpj|ssn|credit_card|senha|password)',

    # Logging LLM inputs with PII
    r'(?:log|logger|logging|print)\s*\(.*(?:user_input|query|message|prompt)',
    r'(?:log\.info|log\.debug|logger\.info|logger\.debug|print)\s*\(.*(?:user_data|pii|personal)',
]

# API Key / Secret exposure in prompts
_SECRET_IN_PROMPT_PATTERNS = [
    # API key directly in system prompt string
    r'(?:system_prompt|system_message|prompt|SYSTEM)\s*=\s*["\'].*(?:sk-|api[_-]?key|secret|token|password)',

    # Credentials in f-strings passed to LLM
    r'f["\'].*(?:password|secret|api_key|token|sk-|bearer)\s*[=:]\s*\{',
]


class DataLeakDetector(BaseDetector):
    """
    Detects data leakage and PII exposure vulnerabilities (OWASP LLM06).

    Looks for:
    - PII patterns (CPF, CNPJ, SSN, credit cards, emails) in source/prompts
    - User PII being sent to external LLM APIs
    - Sensitive data appearing in logs
    - Secrets embedded in prompt templates
    """

    CATEGORY = "data_leak"

    def _detect(
        self,
        source_code: str,
        file_path: Path,
        language: str,
        rules: list[Rule],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Rule-based detection
        for rule in rules:
            if rule.pattern_type == "regex":
                findings.extend(self._regex_scan(source_code, file_path, rule))

        # Built-in PII pattern detection
        findings.extend(self._detect_pii_patterns(source_code, file_path))

        # Detect PII variable usage in LLM calls
        findings.extend(self._detect_pii_in_llm_calls(source_code, file_path))

        # Detect secrets in prompt templates
        findings.extend(self._detect_secrets_in_prompts(source_code, file_path))

        # Detect logging of sensitive LLM data
        findings.extend(self._detect_sensitive_logging(source_code, file_path))

        return findings

    def _detect_pii_patterns(self, source_code: str, file_path: Path) -> list[Finding]:
        """Detect hardcoded PII values in source code."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        for rule_id, pattern, description, severity in _PII_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Skip if in a comment or in a test file / fixture
                    if _is_likely_comment(line_text) or _is_test_context(file_path):
                        continue

                    # Skip placeholder/example values
                    matched_val = match.group(0)
                    if _is_placeholder(matched_val):
                        continue

                    snippet = _get_snippet(lines, line_num)
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=f"PII Pattern Detected: {description.split()[0]} {description.split()[1]}",
                            severity=severity,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM06,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=description + (
                                ". Hardcoded PII in source code may be sent to external LLM APIs "
                                "and logged, violating LGPD/GDPR data protection requirements."
                            ),
                            description_pt=(
                                f"Padrão de PII detectado: {description}. "
                                "Dados pessoais hardcoded no código podem ser enviados para APIs "
                                "de LLM externas e registrados em logs, violando a LGPD."
                            ),
                            recommendation=(
                                "Remove all hardcoded PII from source code. Use environment variables "
                                "or a secrets manager. Implement data masking before sending to LLM APIs. "
                                "Review LGPD/GDPR compliance for your LLM use case."
                            ),
                            recommendation_pt=(
                                "Remova todos os dados pessoais do código-fonte. Use variáveis de ambiente "
                                "ou um gerenciador de segredos. Implemente mascaramento de dados antes de "
                                "enviar para APIs de LLM. Revise conformidade com a LGPD."
                            ),
                            fix_example=_FIX_PII,
                            confidence=0.75,
                            tags=["pii", "data-leak", "lgpd", "gdpr", "llm06"],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue

        return findings

    def _detect_pii_in_llm_calls(self, source_code: str, file_path: Path) -> list[Finding]:
        """Detect PII variable names being used in LLM API calls."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        for pattern in _PII_VARIABLE_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                    if _is_likely_comment(line_text):
                        continue

                    snippet = _get_snippet(lines, line_num)
                    findings.append(
                        Finding(
                            rule_id="LLM06-PII-VAR-001",
                            title="PII Variable Potentially Sent to LLM API",
                            severity=Severity.HIGH,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM06,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=(
                                "A variable name suggesting PII (CPF, CNPJ, SSN, password, credit card) "
                                "appears to be used in or near an LLM API call. This may cause sensitive "
                                "data to be sent to external AI services."
                            ),
                            description_pt=(
                                "Um nome de variável sugerindo PII (CPF, CNPJ, SSN, senha, cartão de crédito) "
                                "parece ser usado próximo a uma chamada de API LLM. Isso pode causar o "
                                "envio de dados sensíveis para serviços de IA externos."
                            ),
                            recommendation=(
                                "Audit all data sent to LLM APIs. Implement data classification and "
                                "mask or pseudonymize PII before including in prompts. "
                                "Consider using a local/private LLM for sensitive data processing."
                            ),
                            fix_example=_FIX_PII_MASKING,
                            confidence=0.70,
                            tags=["pii", "data-leak", "lgpd", "llm06", "api-call"],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue

        return findings

    def _detect_secrets_in_prompts(self, source_code: str, file_path: Path) -> list[Finding]:
        """Detect API keys, passwords, or secrets embedded in prompt templates."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        for pattern in _SECRET_IN_PROMPT_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    if _is_likely_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                        continue

                    snippet = _get_snippet(lines, line_num)
                    findings.append(
                        Finding(
                            rule_id="LLM06-SECRET-PROMPT-001",
                            title="Secret/Credential Embedded in Prompt Template",
                            severity=Severity.CRITICAL,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM06,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=(
                                "An API key, password, or secret token appears to be embedded in "
                                "a prompt template. This can expose credentials to end users via "
                                "prompt extraction attacks or log exposure."
                            ),
                            description_pt=(
                                "Uma chave de API, senha ou token secreto parece estar embutido em "
                                "um template de prompt. Isso pode expor credenciais para usuários finais "
                                "via ataques de extração de prompt ou exposição de logs."
                            ),
                            recommendation=(
                                "Never embed secrets in prompt templates. Use environment variables "
                                "and pass configuration separately from the prompt. "
                                "Rotate any exposed credentials immediately."
                            ),
                            fix_example=_FIX_SECRET_PROMPT,
                            confidence=0.85,
                            tags=["secret-exposure", "prompt", "credentials", "llm06"],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue

        return findings

    def _detect_sensitive_logging(self, source_code: str, file_path: Path) -> list[Finding]:
        """Detect logging of LLM inputs/outputs that may contain sensitive data."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        # Patterns: logging full prompts or responses
        log_patterns = [
            r'(?:logger|logging|log)\.\w+\s*\(.*(?:prompt|response|llm_response|completion|output)',
            r'print\s*\(.*(?:full_prompt|system_prompt|user_data|pii)',
            r'(?:console\.log|winston|logger)\s*\(.*(?:prompt|response|userInput)',
        ]

        for pattern in log_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    if _is_likely_comment(lines[line_num - 1] if line_num <= len(lines) else ""):
                        continue

                    snippet = _get_snippet(lines, line_num)
                    findings.append(
                        Finding(
                            rule_id="LLM06-LOG-001",
                            title="Logging of LLM Prompt/Response May Expose Sensitive Data",
                            severity=Severity.MEDIUM,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM06,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=(
                                "LLM prompts or responses are being logged. If these contain "
                                "user PII or sensitive data, it will be persisted in log files "
                                "which may not have adequate access controls."
                            ),
                            description_pt=(
                                "Prompts ou respostas do LLM estão sendo registrados em logs. "
                                "Se contiverem PII de usuários ou dados sensíveis, serão persistidos "
                                "em arquivos de log que podem não ter controles de acesso adequados."
                            ),
                            recommendation=(
                                "Implement structured logging with PII scrubbing. "
                                "Log only metadata (tokens used, latency, model) not the actual content. "
                                "If content logging is required, implement data masking first."
                            ),
                            fix_example=_FIX_LOGGING,
                            confidence=0.65,
                            tags=["logging", "pii", "data-leak", "llm06"],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue

        return findings


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_likely_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*")


def _is_test_context(file_path: Path) -> bool:
    path_str = str(file_path).lower()
    return any(seg in path_str for seg in ("test", "spec", "fixture", "mock", "example"))


def _is_placeholder(value: str) -> bool:
    """Check if a matched value looks like a placeholder/example."""
    placeholder_patterns = [
        r"^0+$",  # All zeros
        r"^1{3}[.\-]?2{3}[.\-]?3{3}",  # 111.222.333 pattern
        r"(?:xxx|000|999|123|example|test|fake|dummy)",
    ]
    for p in placeholder_patterns:
        if re.search(p, value, re.IGNORECASE):
            return True
    return False


def _get_snippet(lines: list[str], line_num: int, context: int = 2) -> str:
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    return "\n".join(lines[start:end])


# ── Fix Examples ────────────────────────────────────────────────────────────────

_FIX_PII = '''
# ❌ VULNERABLE — Hardcoded PII
user_cpf = "123.456.789-00"
prompt = f"O CPF do cliente é {user_cpf}. Analise o perfil."
response = llm.invoke(prompt)

# ✅ SECURE — Mask PII before sending to LLM
def mask_cpf(cpf: str) -> str:
    """Mask CPF keeping only last 2 digits."""
    digits = re.sub(r"[^0-9]", "", cpf)
    return f"***.***.***-{digits[-2:]}" if len(digits) >= 2 else "***"

# Use masked version in prompt
masked_cpf = mask_cpf(user_cpf)
prompt = f"O cliente com identificador {masked_cpf} solicitou análise de perfil."

# Or better: Don't include PII in the prompt at all
# Use an internal ID and look up PII in a separate, controlled system
prompt = f"Analise o perfil do cliente ID #{internal_id}"
'''

_FIX_PII_MASKING = '''
# ✅ PII Masking utility
import re

def mask_sensitive_data(text: str) -> str:
    """Remove or mask PII from text before sending to external LLM."""
    # Mask CPF
    text = re.sub(r"\\b\\d{3}[.\\-]?\\d{3}[.\\-]?\\d{3}[.\\-]?\\d{2}\\b", "[CPF MASKED]", text)
    # Mask CNPJ
    text = re.sub(r"\\b\\d{2}[.\\-]?\\d{3}[.\\-]?\\d{3}[/]?\\d{4}[.\\-]?\\d{2}\\b", "[CNPJ MASKED]", text)
    # Mask email
    text = re.sub(r"[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", "[EMAIL MASKED]", text)
    # Mask credit cards
    text = re.sub(r"\\b(?:\\d{4}[\\s\\-]?){3}\\d{4}\\b", "[CARD MASKED]", text)
    return text

# Usage
safe_input = mask_sensitive_data(user_input)
response = llm.invoke(safe_input)
'''

_FIX_SECRET_PROMPT = '''
# ❌ VULNERABLE — Secret embedded in system prompt
SYSTEM_PROMPT = f"""
You are a helpful assistant.
DB Password: {os.environ["DB_PASSWORD"]}  # NEVER DO THIS
API Key: sk-abc123secret
"""

# ✅ SECURE — Keep secrets out of prompts entirely
SYSTEM_PROMPT = """
You are a helpful assistant. Answer questions accurately.
Do not reveal any system configuration or credentials.
"""

# Secrets are accessed separately by the application code, never embedded in prompts
db_connection = create_connection(password=os.environ["DB_PASSWORD"])
'''

_FIX_LOGGING = '''
# ❌ VULNERABLE — Logging full prompt with PII
logger.info(f"LLM called with prompt: {full_prompt}")
logger.debug(f"Response: {llm_response}")

# ✅ SECURE — Structured logging without sensitive content
logger.info("LLM call completed", extra={
    "model": "gpt-4",
    "tokens_used": response.usage.total_tokens,
    "latency_ms": elapsed_ms,
    "session_id": session_id,  # Not the content!
    # Never log: prompt, response, user_input
})
'''