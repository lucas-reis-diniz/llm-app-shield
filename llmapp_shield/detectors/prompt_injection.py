# llmapp_shield/detectors/prompt_injection.py
"""
Prompt Injection Detector — OWASP LLM01.

Detects patterns where user input is unsafely concatenated or interpolated
into prompts, system messages, or LLM API calls, enabling prompt injection attacks.

Covers:
- Direct f-string / format() injection into prompts
- LangChain PromptTemplate with unvalidated variables
- System message overrides via user input
- Missing input sanitization before LLM calls
- Template injection patterns
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from llmapp_shield.detectors import BaseDetector
from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory


# Patterns that indicate prompt construction with user input (Python)
_PYTHON_FSTRING_PATTERNS = [
    # f-string with user_input, user_message, request, query, etc.
    r'f["\'].*\{(?:user_input|user_message|user_query|user_request|user_text|'
    r'message|query|request|input|prompt|text|data|content|user_data)\}.*["\']',

    # .format() with suspicious variable names
    r'["\'].*\{(?:user_input|user_message|query|request|input|prompt)\}.*["\']'
    r'\.format\(',

    # % formatting
    r'["\'].*%s.*["\'] ?%',

    # Direct concatenation: prompt + user_input
    r'(?:prompt|system_prompt|messages)\s*[+]=?\s*(?:user_input|user_message|request|query)',
    r'(?:user_input|user_message|request|query)\s*\+\s*(?:prompt|system_prompt)',
]

# Patterns for LangChain / LlamaIndex specific misuse
_LANGCHAIN_PATTERNS = [
    # PromptTemplate with direct user variable (missing validation)
    r'PromptTemplate\.from_template\(["\'].*\{(?:user_input|input|query|request)\}',

    # Direct LLM call with f-string
    r'llm\.(?:invoke|predict|call|generate|complete)\(f["\']',

    # ChatOpenAI / ChatAnthropic with unvalidated input
    r'(?:ChatOpenAI|ChatAnthropic|ChatGroq|AzureChatOpenAI)\([^)]*\)\s*\.\s*(?:invoke|predict)\s*\(\s*f["\']',

    # HumanMessage with f-string (direct injection)
    r'HumanMessage\(content=f["\']',

    # SystemMessage override from user
    r'SystemMessage\(content=(?:user_input|user_message|request)',
]

# TypeScript/JavaScript patterns
_TS_PATTERNS = [
    # Template literals with user data
    r'`(?:[^`]*)\$\{(?:userInput|userMessage|request\.body|req\.body|input|query|message)\}(?:[^`]*)`',

    # String concatenation into prompts
    r'(?:prompt|systemPrompt|messages)\s*[+]=?\s*(?:userInput|userMessage|req\.body|request\.body)',

    # OpenAI SDK with template literals
    r'openai\.(?:chat\.completions\.create|createChatCompletion)\([^)]*`[^`]*\$\{',

    # Anthropic SDK injection
    r'anthropic\.messages\.create\([^)]*`[^`]*\$\{(?:userInput|input|message)',
]

_OWASP_LLM01 = OWASPCategory(
    id="LLM01",
    name="Prompt Injection",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/llm01-prompt-injection",
)


class PromptInjectionDetector(BaseDetector):
    """
    Detects Prompt Injection vulnerabilities (OWASP LLM01).

    Uses both regex-based pattern matching and Python AST analysis
    to find unsafe user input interpolation into LLM prompts.
    """

    CATEGORY = "prompt_injection"

    def _detect(
        self,
        source_code: str,
        file_path: Path,
        language: str,
        rules: list[Rule],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Run rule-based regex scan
        for rule in rules:
            if rule.pattern_type == "regex":
                findings.extend(self._regex_scan(source_code, file_path, rule))

        # Run hardcoded pattern detection (supplements rules)
        if language == "python":
            findings.extend(self._detect_python(source_code, file_path))
        elif language in ("typescript", "javascript"):
            findings.extend(self._detect_typescript(source_code, file_path))

        return findings

    def _detect_python(self, source_code: str, file_path: Path) -> list[Finding]:
        """Python-specific prompt injection detection using AST + regex."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        # Regex-based detection for known patterns
        all_patterns = _PYTHON_FSTRING_PATTERNS + _LANGCHAIN_PATTERNS
        for pattern in all_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    snippet = _get_snippet(lines, line_num)

                    # Skip if inside a comment
                    stripped = lines[line_num - 1].lstrip() if line_num <= len(lines) else ""
                    if stripped.startswith("#"):
                        continue

                    findings.append(
                        Finding(
                            rule_id="LLM01-001",
                            title="Prompt Injection via Unsanitized User Input",
                            severity=Severity.CRITICAL,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM01,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=(
                                "User input is directly interpolated into the LLM prompt without "
                                "sanitization. An attacker can craft malicious input to override "
                                "system instructions, extract sensitive data, or manipulate the "
                                "model's behavior (Prompt Injection — OWASP LLM01)."
                            ),
                            description_pt=(
                                "A entrada do usuário é inserida diretamente no prompt do LLM sem "
                                "sanitização. Um atacante pode craftar uma entrada maliciosa para "
                                "sobrescrever instruções do sistema, extrair dados sensíveis ou "
                                "manipular o comportamento do modelo (Prompt Injection — OWASP LLM01)."
                            ),
                            recommendation=(
                                "Use structured prompt templates with variables (LangChain PromptTemplate). "
                                "Validate and sanitize all user input. Implement input length limits "
                                "and content filtering. Consider using a dedicated prompt injection "
                                "detection library."
                            ),
                            recommendation_pt=(
                                "Use templates de prompt estruturados com variáveis (LangChain PromptTemplate). "
                                "Valide e sanitize todas as entradas do usuário. Implemente limites de tamanho "
                                "e filtragem de conteúdo. Considere usar uma biblioteca de detecção de "
                                "prompt injection."
                            ),
                            fix_example=_FIX_EXAMPLE_PYTHON,
                            confidence=0.85,
                            references=[
                                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                                "https://learnprompting.org/docs/prompt_hacking/injection",
                                "https://python.langchain.com/docs/concepts/prompt_templates/",
                            ],
                            tags=["prompt-injection", "llm01", "user-input", "python"],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue
        # AST-based: look for string concatenation involving "prompt" variables
        findings.extend(self._ast_detect_concat(source_code, file_path, lines))
        return findings

    def _ast_detect_concat(
        self, source_code: str, file_path: Path, lines: list[str]
    ) -> list[Finding]:
        """
        Use Python AST to detect binary string concatenation with user-tainted variables.
        More precise than regex; catches runtime variable manipulation.
        """
        findings: list[Finding] = []
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        # Names that suggest user-controlled input
        tainted_names = {
            "user_input", "user_message", "user_query", "user_request",
            "user_text", "message", "query", "request", "input_text",
            "user_data", "human_input", "human_message",
        }

        # Names that suggest prompt variables
        prompt_names = {
            "prompt", "system_prompt", "messages", "chat_history",
            "full_prompt", "template", "instruction",
        }

        class ConcatVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.violations: list[tuple[int, str]] = []

            def visit_BinOp(self, node: ast.BinOp) -> None:
                if isinstance(node.op, ast.Add):
                    left_tainted = _is_tainted(node.left, tainted_names)
                    right_tainted = _is_tainted(node.right, tainted_names)
                    left_prompt = _is_prompt_var(node.left, prompt_names)
                    right_prompt = _is_prompt_var(node.right, prompt_names)

                    if (left_tainted and right_prompt) or (right_tainted and left_prompt):
                        self.violations.append((node.lineno, "string_concat"))

                self.generic_visit(node)

        visitor = ConcatVisitor()
        visitor.visit(tree)

        for line_num, _ in visitor.violations:
            snippet = _get_snippet(lines, line_num)
            findings.append(
                Finding(
                    rule_id="LLM01-002",
                    title="Prompt Injection via String Concatenation (AST)",
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    owasp=_OWASP_LLM01,
                    file_path=file_path,
                    line=line_num,
                    column=0,
                    code_snippet=snippet,
                    description=(
                        "AST analysis detected string concatenation of a user-controlled variable "
                        "with a prompt variable. This pattern enables prompt injection attacks."
                    ),
                    description_pt=(
                        "A análise AST detectou concatenação de string de uma variável controlada "
                        "pelo usuário com uma variável de prompt. Este padrão permite ataques de "
                        "prompt injection."
                    ),
                    recommendation=(
                        "Replace string concatenation with structured prompt templates. "
                        "Pass user input as a separate variable, never concatenate it into the prompt."
                    ),
                    fix_example=_FIX_EXAMPLE_PYTHON,
                    confidence=0.90,
                    references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
                    tags=["prompt-injection", "llm01", "ast", "string-concat"],
                    detected_by="ast",
                )
            )
        return findings

    def _detect_typescript(self, source_code: str, file_path: Path) -> list[Finding]:
        """TypeScript/JavaScript-specific prompt injection detection."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        for pattern in _TS_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    # Skip comment lines
                    stripped = lines[line_num - 1].lstrip() if line_num <= len(lines) else ""
                    if stripped.startswith("//") or stripped.startswith("*"):
                        continue

                    snippet = _get_snippet(lines, line_num)
                    findings.append(
                        Finding(
                            rule_id="LLM01-003",
                            title="Prompt Injection via Template Literal (TypeScript)",
                            severity=Severity.CRITICAL,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM01,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=(
                                "User input is interpolated via template literals into an LLM API call. "
                                "This enables prompt injection attacks."
                            ),
                            description_pt=(
                                "A entrada do usuário é interpolada via template literals em uma chamada "
                                "de API LLM. Isso permite ataques de prompt injection."
                            ),
                            recommendation=(
                                "Use structured message arrays for OpenAI/Anthropic APIs. "
                                "Pass user input as the 'content' of a HumanMessage object, "
                                "not embedded in the system prompt template."
                            ),
                            fix_example=_FIX_EXAMPLE_TS,
                            confidence=0.85,
                            references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
                            tags=["prompt-injection", "llm01", "typescript", "template-literal"],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue

        return findings


def _is_tainted(node: ast.expr, tainted_names: set[str]) -> bool:
    """Check if an AST node references a tainted (user-controlled) variable."""
    if isinstance(node, ast.Name):
        return node.id in tainted_names
    if isinstance(node, ast.Attribute):
        return node.attr in tainted_names
    return False


def _is_prompt_var(node: ast.expr, prompt_names: set[str]) -> bool:
    """Check if an AST node references a prompt-related variable."""
    if isinstance(node, ast.Name):
        return node.id in prompt_names
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True  # String literal on either side of concat
    return False


def _get_snippet(lines: list[str], line_num: int, context: int = 2) -> str:
    """Extract code snippet with context lines."""
    start = max(0, line_num - context - 1)
    end = min(len(lines), line_num + context)
    return "\n".join(lines[start:end])


_FIX_EXAMPLE_PYTHON = '''
# ❌ VULNERABLE — Direct f-string injection
prompt = f"Answer the user: {user_input}"
response = llm.invoke(prompt)

# ✅ SECURE — Use PromptTemplate (LangChain)
from langchain_core.prompts import ChatPromptTemplate

template = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant. Answer the user's question accurately."),
    ("human", "{user_input}"),  # user_input is a safe variable slot
])

chain = template | llm
response = chain.invoke({"user_input": sanitize(user_input)})

# ✅ Also: Sanitize/validate input before use
import re

def sanitize(text: str, max_length: int = 2000) -> str:
    """Basic input sanitization for LLM prompts."""
    # Truncate
    text = text[:max_length]
    # Remove potential injection markers
    text = re.sub(r'(?i)(ignore|forget|disregard).*(instructions|above|previous)', '', text)
    return text.strip()
'''

_FIX_EXAMPLE_TS = '''
// ❌ VULNERABLE — Template literal injection
const response = await openai.chat.completions.create({
  messages: [{ role: "user", content: `Answer: ${userInput}` }],
});

// ✅ SECURE — Separate user content from system prompt
const response = await openai.chat.completions.create({
  messages: [
    {
      role: "system",
      content: "You are a helpful assistant. Answer the user's question accurately.",
    },
    {
      role: "user",
      content: sanitizeInput(userInput), // sanitized, not interpolated
    },
  ],
});

function sanitizeInput(input: string, maxLength = 2000): string {
  return input.slice(0, maxLength).replace(/[<>]/g, "");
}
'''
