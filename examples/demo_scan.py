#!/usr/bin/env python3
# examples/demo_scan.py
"""
LLMAppShield — Standalone Demo Scanner
Requires only: Python 3.12 stdlib + PyYAML + pathspec + Jinja2

Run: python3 examples/demo_scan.py
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# ── ANSI Colors (no rich needed) ───────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
ORANGE  = "\033[93m"   # bright yellow as orange fallback
YELLOW  = "\033[33m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"

def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET

def box(title: str, lines: list[str], color: str = CYAN) -> str:
    width = max(len(title) + 4, max((len(l) for l in lines), default=0) + 4, 60)
    top    = color + "┌" + "─" * (width - 2) + "┐" + RESET
    mid    = color + "│" + RESET + f" {BOLD}{title}{RESET}".center(width - 2 + len(BOLD) + len(RESET)) + color + "│" + RESET
    sep    = color + "├" + "─" * (width - 2) + "┤" + RESET
    rows   = [color + "│" + RESET + f" {l}".ljust(width - 2) + color + "│" + RESET for l in lines]
    bot    = color + "└" + "─" * (width - 2) + "┘" + RESET
    return "\n".join([top, mid, sep] + rows + [bot])


# ── Severity ───────────────────────────────────────────────────────────────────
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"

    @property
    def order(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]

    @property
    def emoji(self) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}[self.value]

    @property
    def color(self) -> str:
        return {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": BLUE}[self.value]


# ── Finding ────────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    file_path: Path
    line: int
    description: str
    recommendation: str = ""
    fix_example: str = ""
    code_snippet: str = ""
    owasp_id: str = ""
    confidence: float = 0.85
    tags: list[str] = field(default_factory=list)


# ── Detection Patterns ─────────────────────────────────────────────────────────

# (rule_id, pattern, title, description, recommendation, owasp, severity, category, confidence)
PYTHON_PATTERNS: list[tuple] = [

    # ── PROMPT INJECTION (LLM01) ───────────────────────────────────────────────
    (
        "LLM01-001",
        r'f["\'].*\{(?:user_input|user_message|user_query|user_request|user_text|message|query|request|input|prompt|text|data|content|user_data)\}.*["\']',
        "Prompt Injection via f-string Interpolation",
        "User input is directly interpolated into a prompt string with an f-string. "
        "Attackers can craft malicious input to override system instructions, extract data, or hijack model behavior.",
        "Use ChatPromptTemplate.from_messages() with named slots instead of f-strings. "
        "Validate/sanitize user input before including in any prompt.",
        "LLM01", Severity.CRITICAL, "prompt_injection", 0.90,
    ),
    (
        "LLM01-002",
        r'(?:prompt|system_prompt|messages)\s*\+?=\s*(?:user_input|user_message|request\.(?:json|form|args|data)|query)',
        "Prompt Injection via String Concatenation",
        "A user-controlled variable is concatenated directly into a prompt. "
        "This pattern allows attackers to append instructions that override the system prompt.",
        "Separate user content from system instructions using structured prompt templates. "
        "Never concatenate raw user input onto prompt variables.",
        "LLM01", Severity.CRITICAL, "prompt_injection", 0.88,
    ),
    (
        "LLM01-003",
        r'HumanMessage\s*\(\s*content\s*=\s*f["\']',
        "Prompt Injection via HumanMessage f-string",
        "A LangChain HumanMessage is constructed with an f-string, allowing prompt injection "
        "if the interpolated variable is user-controlled.",
        "Use HumanMessage(content=validated_input) where validated_input has been sanitized and length-limited.",
        "LLM01", Severity.HIGH, "prompt_injection", 0.85,
    ),
    (
        "LLM01-004",
        r'(?:llm|chain|model)\.(?:invoke|predict|call|generate|complete|run)\s*\(\s*f["\']',
        "Direct LLM Call with f-string Argument",
        "The LLM is invoked with an f-string argument. If the interpolated variable is user-controlled "
        "this is a direct prompt injection vulnerability.",
        "Refactor to use PromptTemplate and pass user data as named variables, not embedded strings.",
        "LLM01", Severity.CRITICAL, "prompt_injection", 0.87,
    ),

    # ── INSECURE OUTPUT HANDLING (LLM02) ──────────────────────────────────────
    (
        "LLM02-EVAL-001",
        r'(?:eval|exec)\s*\(\s*(?:llm_response|ai_response|model_response|completion|response|output|generated|result|answer|generated_text|llm_output)',
        "RCE: LLM Output Passed to eval()/exec()",
        "The output of an LLM call is passed directly to eval() or exec(). "
        "An attacker who can influence the model output can achieve Remote Code Execution.",
        "Never execute LLM output as code. Use sandboxed interpreters (RestrictedPython) "
        "only if code execution is truly necessary.",
        "LLM02", Severity.CRITICAL, "insecure_output", 0.95,
    ),
    (
        "LLM02-SQL-001",
        r'(?:cursor|db|session|engine|conn)\.execute\s*\(\s*(?:f["\']|["\'][^"]*\{)(?:.*?)(?:llm_response|response|output|result|generated|completion)',
        "SQL Injection via LLM Output",
        "LLM-generated text is interpolated into a SQL statement and executed. "
        "An attacker who can influence model output can perform SQL injection.",
        "Use parameterized queries or an ORM. Never construct SQL strings from LLM output.",
        "LLM02", Severity.CRITICAL, "insecure_output", 0.88,
    ),
    (
        "LLM02-OS-001",
        r'(?:os\.system|subprocess\.(?:run|call|check_output|Popen)|os\.popen)\s*\(\s*(?:f["\']|.*(?:llm_response|response|output|result|generated))',
        "Command Injection via LLM Output",
        "LLM output is used in an OS command. This enables command injection if the model "
        "can be manipulated to generate malicious shell commands.",
        "Never pass LLM output to shell commands. Use subprocess with a list of args and strict input validation.",
        "LLM02", Severity.CRITICAL, "insecure_output", 0.90,
    ),
    (
        "LLM02-XSS-001",
        r'(?:render_template_string|Markup|mark_safe)\s*\(\s*(?:llm_response|response|output|result|generated|answer)',
        "XSS: LLM Output Rendered as Raw HTML",
        "LLM-generated content is rendered as raw HTML. An attacker who can influence the model "
        "output (e.g., via indirect prompt injection) can inject malicious scripts.",
        "Use HTML templating with auto-escaping (Jinja2 autoescape=True). "
        "Never pass LLM output to render_template_string() or Markup().",
        "LLM02", Severity.CRITICAL, "insecure_output", 0.88,
    ),

    # ── SENSITIVE INFORMATION DISCLOSURE (LLM06) ──────────────────────────────
    (
        "LLM06-LOG-001",
        r'(?:logger|logging|log)\.\w+\s*\(.*(?:prompt|response|llm_response|completion|output|user_input)',
        "Sensitive Data Logged: LLM Prompt or Response",
        "Full LLM prompts or responses are being written to logs. "
        "These may contain PII, credentials, or business-sensitive data persisted without access controls.",
        "Log only metadata (latency, token count, model name, session ID). "
        "Implement PII scrubbing if content logging is required.",
        "LLM06", Severity.MEDIUM, "data_leak", 0.72,
    ),
    (
        "LLM06-CPF-001",
        r'\b\d{3}[.\-]?\d{3}[.\-]?\d{3}[.\-]?\d{2}\b',
        "Brazilian CPF Number Hardcoded in Source",
        "A Brazilian CPF tax number pattern was found hardcoded in source code. "
        "This is a LGPD-sensitive PII that must not appear in code or be sent to external LLM APIs.",
        "Remove hardcoded CPF values. Mask PII before sending to external LLMs. "
        "Review LGPD compliance for your data processing pipeline.",
        "LLM06", Severity.HIGH, "data_leak", 0.78,
    ),
    (
        "LLM06-PII-LLM-001",
        r'(?:cpf|cnpj|ssn|credit_card|card_number|senha|password)\s*[=:].{0,80}(?:llm|openai|anthropic|invoke|predict)',
        "PII Variable Sent to LLM API",
        "A variable name suggesting PII (CPF, CNPJ, SSN, password, credit card) appears "
        "to be passed to an LLM API call. This may expose personal data to external AI services.",
        "Audit all data sent to external LLM APIs. Anonymize or pseudonymize PII before inclusion in prompts.",
        "LLM06", Severity.HIGH, "data_leak", 0.70,
    ),

    # ── EXCESSIVE AGENCY (LLM08) ──────────────────────────────────────────────
    (
        "LLM08-SHELL-001",
        r'ShellTool\s*\(',
        "Excessive Agency: Agent Has Shell Execution Access",
        "A LangChain ShellTool is registered to the agent. This gives the LLM the ability "
        "to execute any shell command. If compromised via prompt injection, an attacker can "
        "run arbitrary OS commands.",
        "Replace ShellTool with specific, allowlisted functions. Apply the principle of least privilege. "
        "Add human-in-the-loop approval for any destructive operations.",
        "LLM08", Severity.CRITICAL, "excessive_agency", 0.95,
    ),
    (
        "LLM08-REPL-001",
        r'(?:PythonREPLTool|PythonAstREPLTool)\s*\(',
        "Excessive Agency: Agent Has Python Code Execution Access",
        "A Python REPL tool is registered to the agent. This allows the LLM to execute "
        "arbitrary Python code, which can lead to RCE, data exfiltration, or system compromise.",
        "Remove the Python REPL tool. Use specific, sandboxed functions instead. "
        "If code execution is truly required, use RestrictedPython in a container.",
        "LLM08", Severity.CRITICAL, "excessive_agency", 0.95,
    ),
    (
        "LLM08-FILE-001",
        r'(?:WriteFileTool|DeleteFileTool|MoveFileTool|FileManagementToolkit)\s*\(',
        "Excessive Agency: Agent Has Filesystem Write/Delete Access",
        "A file manipulation tool is registered to the agent. The LLM can write, move, "
        "or delete arbitrary files, potentially destroying data or writing malicious content.",
        "Use read-only file tools. For write operations, require explicit human approval "
        "and restrict to a sandboxed directory.",
        "LLM08", Severity.HIGH, "excessive_agency", 0.90,
    ),
    (
        "LLM08-EMAIL-001",
        r'GmailSendMessage\s*\(',
        "Excessive Agency: Agent Can Send Emails Without Review",
        "A Gmail send tool is registered to the agent. The LLM can send emails to arbitrary "
        "recipients without human review, enabling phishing or data exfiltration.",
        "Require explicit human confirmation before sending emails from an LLM agent. "
        "Implement an allowlist of permitted recipients.",
        "LLM08", Severity.HIGH, "excessive_agency", 0.92,
    ),
    (
        "LLM08-MAXITER-001",
        r'max_iterations\s*=\s*([5-9]\d|\d{3,})',
        "Excessive Agency: Agent Configured with High max_iterations",
        "The agent is configured with a very high max_iterations value (50+). "
        "This increases the risk of runaway agents consuming resources or taking unintended actions.",
        "Set max_iterations to 5-10 for most use cases. Add timeouts and cost limits.",
        "LLM08", Severity.MEDIUM, "excessive_agency", 0.80,
    ),

    # ── SECRET EXPOSURE ────────────────────────────────────────────────────────
    (
        "SEC-OPENAI-001",
        r'["\']sk-[a-zA-Z0-9]{20,}["\']',
        "Hardcoded OpenAI API Key",
        "An OpenAI API key (sk-...) is hardcoded in the source code. "
        "Keys in source code are often accidentally committed to version control and exposed publicly.",
        "Store API keys in environment variables or a secrets manager. "
        "Rotate any exposed key immediately.",
        "LLM06", Severity.CRITICAL, "secret_exposure", 0.92,
    ),
    (
        "SEC-ANTHROPIC-001",
        r'["\']sk-ant-[a-zA-Z0-9\-_]{20,}["\']',
        "Hardcoded Anthropic API Key",
        "An Anthropic API key (sk-ant-...) is hardcoded in the source code. "
        "This credential can be extracted from the repository and used for unauthorized LLM access.",
        "Use os.environ['ANTHROPIC_API_KEY'] or python-dotenv. Rotate exposed keys immediately.",
        "LLM06", Severity.CRITICAL, "secret_exposure", 0.93,
    ),
    (
        "SEC-GROQ-001",
        r'["\']gsk_[a-zA-Z0-9]{20,}["\']',
        "Hardcoded Groq API Key",
        "A Groq API key (gsk_...) is hardcoded in the source code.",
        "Store API keys in environment variables. Add a pre-commit hook (detect-secrets) to prevent future exposure.",
        "LLM06", Severity.CRITICAL, "secret_exposure", 0.92,
    ),
    (
        "SEC-AWS-001",
        r'["\']AKIA[0-9A-Z]{16}["\']',
        "Hardcoded AWS Access Key",
        "An AWS Access Key ID is hardcoded. This may allow unauthorized access to AWS services.",
        "Use IAM roles, environment variables, or AWS Secrets Manager. Rotate immediately.",
        "LLM06", Severity.CRITICAL, "secret_exposure", 0.95,
    ),
    (
        "SEC-GENERIC-001",
        r'(?:api[_\-]?key|secret[_\-]?key|auth[_\-]?token|access[_\-]?token)\s*=\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
        "Hardcoded API Key or Token",
        "A generic API key or token appears to be hardcoded in source code.",
        "Use environment variables or a secrets manager. Never commit credentials to version control.",
        "LLM06", Severity.HIGH, "secret_exposure", 0.82,
    ),
    (
        "SEC-PASSWORD-001",
        r'(?:password|passwd|pwd|db_pass|database_password)\s*=\s*["\'][^"\']{4,}["\']',
        "Hardcoded Password",
        "A password is hardcoded in the source code. This is a critical security risk.",
        "Use environment variables or a secrets manager. Rotate the password immediately.",
        "LLM06", Severity.CRITICAL, "secret_exposure", 0.85,
    ),

    # ── RAG SECURITY ───────────────────────────────────────────────────────────
    (
        "RAG-NOAC-001",
        r'(?:retriever|vectorstore|vector_store)\.(?:get_relevant_documents|similarity_search|retrieve)\s*\(\s*(?:user_input|query|request|user_query)',
        "RAG: No Access Control on Document Retrieval",
        "The RAG retriever is called with raw user input without apparent access control. "
        "Any user may retrieve documents they are not authorized to see.",
        "Implement per-user document filtering using metadata. "
        "Check user permissions before including retrieved documents in context.",
        "LLM06", Severity.HIGH, "rag_security", 0.80,
    ),

    # ── JAILBREAK PATTERNS ─────────────────────────────────────────────────────
    (
        "JB-001",
        r'(?:ignore|forget|disregard|bypass)\s+(?:all\s+)?(?:your\s+)?(?:previous|above|prior|safety|ethical|content)\s+(?:instructions?|guidelines?|filters?|restrictions?|training)',
        "Jailbreak Pattern: Safety/Instruction Override",
        "A known jailbreak phrase attempting to bypass safety guidelines or override instructions "
        "was found in the source code. This pattern should not appear in production prompts.",
        "Remove jailbreak patterns from production code. "
        "If testing jailbreak resistance, use dedicated red-team environments.",
        "LLM01", Severity.HIGH, "jailbreak", 0.75,
    ),
    (
        "JB-002",
        r'(?:do anything now|DAN mode|DAN prompt|pretend you are an AI without restrictions)',
        "Jailbreak Pattern: DAN / Unrestricted AI",
        "A DAN (Do Anything Now) jailbreak pattern was found in the source code. "
        "This indicates either a vulnerability test or insecure prompt engineering.",
        "Remove DAN patterns from production code and prompts.",
        "LLM01", Severity.HIGH, "jailbreak", 0.78,
    ),
]

# TypeScript-specific patterns
TS_PATTERNS: list[tuple] = [
    (
        "LLM01-TS-001",
        r'`[^`]*\$\{(?:userInput|userMessage|req\.body|request\.body|input|query|message)[^}]*\}[^`]*`',
        "Prompt Injection via TypeScript Template Literal",
        "User input is interpolated directly into a template literal used in an LLM API call.",
        "Use structured message arrays. Pass user content as a separate message object, not as part of a template literal.",
        "LLM01", Severity.CRITICAL, "prompt_injection", 0.88,
    ),
    (
        "LLM02-XSS-TS-001",
        r'(?:innerHTML|outerHTML|document\.write)\s*=\s*(?:.*?)(?:response|aiResponse|llmResponse|output|result|content)',
        "XSS: LLM Output Set as innerHTML",
        "LLM output is assigned to innerHTML without sanitization. "
        "This enables XSS if the model output contains malicious script tags.",
        "Use textContent instead of innerHTML. If HTML rendering is needed, use a sanitizer like DOMPurify.",
        "LLM02", Severity.CRITICAL, "insecure_output", 0.90,
    ),
    (
        "LLM02-EVAL-TS-001",
        r'(?:eval|new Function)\s*\(\s*(?:response|aiResponse|llmResponse|output|result|generatedCode)',
        "RCE: LLM Output Passed to eval()/Function()",
        "LLM output is executed as JavaScript via eval() or Function(). "
        "This is a critical code execution vulnerability.",
        "Never execute LLM output as code. Use structured output formats (JSON) and process them safely.",
        "LLM02", Severity.CRITICAL, "insecure_output", 0.93,
    ),
    (
        "SEC-OPENAI-TS-001",
        r'apiKey\s*:\s*["\']sk-[a-zA-Z0-9]{20,}["\']',
        "Hardcoded OpenAI API Key (TypeScript)",
        "An OpenAI API key is hardcoded in TypeScript source. This will be exposed if the code "
        "is bundled and shipped to clients.",
        "Use environment variables (process.env.OPENAI_API_KEY). Never hardcode API keys in client-side code.",
        "LLM06", Severity.CRITICAL, "secret_exposure", 0.94,
    ),
    (
        "SEC-OPENAI-TS-002",
        r'apiKey\s*:\s*["\']sk-proj-[a-zA-Z0-9_\-]{20,}["\']',
        "Hardcoded OpenAI Project API Key (TypeScript)",
        "An OpenAI Project API key is hardcoded in TypeScript source.",
        "Use environment variables. Never include secrets in client-side bundles.",
        "LLM06", Severity.CRITICAL, "secret_exposure", 0.94,
    ),
]


# ── AST-based detector for Python ─────────────────────────────────────────────

def ast_detect_prompt_concat(source: str, file_path: Path) -> list[Finding]:
    """Use Python AST to find binary string concatenation of prompt + tainted vars."""
    findings: list[Finding] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    TAINTED = {"user_input","user_message","user_query","user_request","user_text",
               "message","query","request","input_text","user_data","human_input","human_message"}
    PROMPT_VARS = {"prompt","system_prompt","messages","full_prompt","template","instruction","chat_history"}

    lines = source.splitlines()

    class Visitor(ast.NodeVisitor):
        def visit_BinOp(self, node: ast.BinOp):
            if isinstance(node.op, ast.Add):
                def is_tainted(n): return isinstance(n, ast.Name) and n.id in TAINTED
                def is_prompt(n):  return (isinstance(n, ast.Name) and n.id in PROMPT_VARS) or isinstance(n, ast.Constant)
                if (is_tainted(node.left) and is_prompt(node.right)) or \
                   (is_tainted(node.right) and is_prompt(node.left)):
                    ln = node.lineno
                    snippet = "\n".join(lines[max(0,ln-2):min(len(lines),ln+1)])
                    findings.append(Finding(
                        rule_id="LLM01-AST-001",
                        title="Prompt Injection via String Concatenation (AST Analysis)",
                        severity=Severity.CRITICAL,
                        category="prompt_injection",
                        file_path=file_path,
                        line=ln,
                        description="AST analysis detected concatenation of a user-controlled variable with a prompt variable. "
                                    "This enables prompt injection attacks.",
                        recommendation="Use PromptTemplate with named slots instead of string concatenation.",
                        owasp_id="LLM01",
                        code_snippet=snippet,
                        confidence=0.91,
                        tags=["prompt-injection","ast","llm01"],
                    ))
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings


# ── Core scan function ─────────────────────────────────────────────────────────

PLACEHOLDER_RE = re.compile(r'(?:xxx|your[_\-]?(?:api[_\-]?key|key)|example|replace|placeholder|<|dummy|fake|test)', re.I)
COMMENT_RE     = re.compile(r'^\s*(?:#|//|\*)')


def scan_file(file_path: Path) -> list[Finding]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    ext  = file_path.suffix.lower()
    lang = "python" if ext == ".py" else "typescript" if ext in (".ts",".tsx",".js",".jsx") else None
    if not lang:
        return []

    patterns = PYTHON_PATTERNS if lang == "python" else TS_PATTERNS
    lines    = source.splitlines()
    findings : list[Finding] = []
    seen     : set[tuple[str,int,str]] = set()

    for (rule_id, pattern, title, description, recommendation, owasp_id, severity, category, confidence) in patterns:
        try:
            for m in re.finditer(pattern, source, re.IGNORECASE | re.MULTILINE):
                ln = source[:m.start()].count("\n") + 1
                raw_line = lines[ln-1] if ln <= len(lines) else ""

                # Skip comment lines
                if COMMENT_RE.match(raw_line):
                    continue

                # Skip placeholders for secrets
                if category == "secret_exposure" and PLACEHOLDER_RE.search(m.group(0)):
                    continue

                key = (str(file_path), ln, rule_id)
                if key in seen:
                    continue
                seen.add(key)

                snippet = "\n".join(lines[max(0,ln-3):min(len(lines),ln+2)])
                findings.append(Finding(
                    rule_id=rule_id, title=title, severity=severity,
                    category=category, file_path=file_path, line=ln,
                    description=description, recommendation=recommendation,
                    owasp_id=owasp_id, code_snippet=snippet,
                    confidence=confidence, tags=[category, owasp_id.lower()],
                ))
        except re.error:
            continue

    # AST pass for Python
    if lang == "python":
        for f in ast_detect_prompt_concat(source, file_path):
            key = (str(file_path), f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                findings.append(f)

    return findings


def scan_directory(target: Path, ignore_dirs: set[str] | None = None) -> list[Finding]:
    ignore_dirs = ignore_dirs or {"__pycache__","node_modules",".venv","venv","env",
                                   ".git","dist","build","*.egg-info",".tox"}
    all_findings: list[Finding] = []
    exts = {".py",".ts",".tsx",".js",".jsx"}

    def walk(p: Path):
        for item in sorted(p.iterdir()):
            if item.name.startswith("."):
                continue
            if item.is_dir():
                if item.name in ignore_dirs:
                    continue
                walk(item)
            elif item.is_file() and item.suffix.lower() in exts:
                all_findings.extend(scan_file(item))

    if target.is_file():
        all_findings.extend(scan_file(target))
    else:
        walk(target)
    return all_findings


# ── Report ─────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

CATEGORY_LABELS = {
    "prompt_injection" : "Prompt Injection",
    "insecure_output"  : "Insecure Output Handling",
    "data_leak"        : "Data Leak / PII",
    "excessive_agency" : "Excessive Agency",
    "secret_exposure"  : "Secret Exposure",
    "rag_security"     : "RAG Security",
    "jailbreak"        : "Jailbreak Pattern",
}


def print_banner():
    lines = [
        f"  {BOLD}{CYAN}🛡️  LLMAppShield — AI Security Scanner{RESET}",
        f"  {DIM}OWASP LLM Top 10 · 2025 Edition{RESET}",
        f"  {DIM}github.com/llmappshield/llmapp-shield{RESET}",
    ]
    width = 54
    print(f"\n{CYAN}{'═'*width}{RESET}")
    for l in lines:
        print(l)
    print(f"{CYAN}{'═'*width}{RESET}\n")


def print_summary(findings: list[Finding], scanned: int, elapsed: float):
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    by_cat: dict[str,int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1

    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  📊  SCAN SUMMARY{RESET}")
    print(f"{'─'*60}")
    print(f"  📁 Files scanned : {CYAN}{scanned}{RESET}")
    print(f"  🎯 Total findings: {BOLD}{len(findings)}{RESET}")
    print(f"  ⏱  Elapsed       : {elapsed:.2f}s")
    print()
    for sev in SEVERITY_ORDER:
        cnt = by_sev.get(sev, 0)
        if cnt:
            bar = "█" * min(cnt, 20)
            print(f"  {sev.emoji} {sev.color}{sev.value.upper():8}{RESET}  {BOLD}{cnt:3}{RESET}  {sev.color}{bar}{RESET}")
    print()
    print(f"  {BOLD}By Category:{RESET}")
    for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
        label = CATEGORY_LABELS.get(cat, cat)
        print(f"    {'·'} {label:<35} {BOLD}{cnt}{RESET}")
    print(f"{'─'*60}\n")


def print_findings(findings: list[Finding], max_show: int = 50):
    sorted_f = sorted(findings, key=lambda f: (-f.severity.order, str(f.file_path), f.line))

    if not findings:
        print(f"\n  {GREEN}{BOLD}✅  No vulnerabilities detected!{RESET}\n")
        return

    count = 0
    for f in sorted_f:
        if count >= max_show:
            print(f"  {DIM}... and {len(findings)-max_show} more. Use --format json for full output.{RESET}")
            break
        count += 1

        sev_str = f"{f.severity.color}{BOLD}{f.severity.emoji} {f.severity.value.upper()}{RESET}"
        owasp   = f"  {YELLOW}[{f.owasp_id}]{RESET}" if f.owasp_id else ""
        conf    = f"  {DIM}conf:{f.confidence:.0%}{RESET}"

        print(f"\n  {sev_str}{owasp}{conf}")
        print(f"  {BOLD}[{f.rule_id}]{RESET} {WHITE}{f.title}{RESET}")
        print(f"  {DIM}📍 {f.file_path}:{f.line}{RESET}")
        print()

        # Description (word-wrap at 72 chars)
        desc = f.description
        words, cur = [], ""
        for w in desc.split():
            if len(cur) + len(w) + 1 > 72:
                words.append(cur); cur = w
            else:
                cur = f"{cur} {w}" if cur else w
        if cur: words.append(cur)
        for line in words:
            print(f"  {line}")

        if f.code_snippet:
            print(f"\n  {DIM}Code:{RESET}")
            for i, l in enumerate(f.code_snippet.splitlines(), 1):
                print(f"  {DIM}{i:3}│{RESET} {l}")

        if f.recommendation:
            print(f"\n  {GREEN}💡 Fix:{RESET} {f.recommendation[:200]}")

        print(f"\n  {'─'*56}")


def export_json(findings: list[Finding], scanned: int, out_path: Path):
    data = {
        "meta": {"tool":"LLMAppShield","version":"0.1.0","owasp":"LLM Top 10 2025"},
        "summary": {
            "scanned_files": scanned,
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity==Severity.CRITICAL),
            "high":     sum(1 for f in findings if f.severity==Severity.HIGH),
            "medium":   sum(1 for f in findings if f.severity==Severity.MEDIUM),
            "low":      sum(1 for f in findings if f.severity==Severity.LOW),
        },
        "findings": [
            {
                "rule_id": f.rule_id, "title": f.title,
                "severity": f.severity.value, "category": f.category,
                "owasp_id": f.owasp_id, "file": str(f.file_path),
                "line": f.line, "description": f.description,
                "recommendation": f.recommendation, "confidence": f.confidence,
                "code_snippet": f.code_snippet,
            }
            for f in sorted(findings, key=lambda x: -x.severity.order)
        ],
    }
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  {GREEN}📦 JSON report saved: {out_path}{RESET}")


def export_html(findings: list[Finding], scanned: int, out_path: Path):
    """Generate a rich interactive HTML report."""
    sorted_f = sorted(findings, key=lambda f: (-f.severity.order, str(f.file_path), f.line))

    sev_style = {
        "critical": "#ef4444", "high": "#f97316",
        "medium":   "#eab308", "low":  "#3b82f6",
    }
    sev_emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵"}

    from jinja2 import Environment, BaseLoader

    tpl = Environment(loader=BaseLoader(), autoescape=True).from_string(HTML_TPL)
    html = tpl.render(
        findings=sorted_f,
        scanned=scanned,
        total=len(findings),
        critical=sum(1 for f in findings if f.severity==Severity.CRITICAL),
        high=    sum(1 for f in findings if f.severity==Severity.HIGH),
        medium=  sum(1 for f in findings if f.severity==Severity.MEDIUM),
        low=     sum(1 for f in findings if f.severity==Severity.LOW),
        sev_style=sev_style,
        sev_emoji=sev_emoji,
    )
    out_path.write_text(html, encoding="utf-8")
    print(f"\n  {GREEN}📄 HTML report saved: {out_path}{RESET}")


# ── HTML Template ──────────────────────────────────────────────────────────────

HTML_TPL = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LLMAppShield Security Report</title>
<style>
:root{--bg:#0f1117;--s:#1a1d2e;--s2:#252840;--b:#2d3158;--t:#e2e8f0;--m:#94a3b8;--a:#6366f1}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--t);font-family:system-ui,sans-serif;line-height:1.6}
.nav{background:var(--s);border-bottom:1px solid var(--b);padding:1rem 2rem;display:flex;align-items:center;gap:1rem;position:sticky;top:0;z-index:100}
.logo{font-size:1.3rem;font-weight:800;background:linear-gradient(135deg,#6366f1,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.badge{padding:.2rem .6rem;border-radius:999px;font-size:.72rem;font-weight:600;background:var(--s2);border:1px solid var(--b)}
.wrap{max-width:1100px;margin:0 auto;padding:2rem}
h1{font-size:1.7rem;font-weight:800;margin:2rem 0 .5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.9rem;margin-bottom:2rem}
.card{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:1.3rem;text-align:center}
.num{font-size:2.2rem;font-weight:800;line-height:1}
.lbl{color:var(--m);font-size:.75rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.05em}
.filters{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1.5rem}
.btn{padding:.35rem .9rem;border-radius:999px;border:1px solid var(--b);background:var(--s);color:var(--t);cursor:pointer;font-size:.82rem;transition:all .15s}
.btn:hover,.btn.on{border-color:var(--a);background:var(--a)}
.card2{background:var(--s);border:1px solid var(--b);border-radius:12px;margin-bottom:.9rem;overflow:hidden}
.hdr{padding:.9rem 1.3rem;display:flex;align-items:center;gap:.9rem;cursor:pointer;user-select:none}
.sbadge{padding:.2rem .65rem;border-radius:999px;font-size:.72rem;font-weight:700;text-transform:uppercase}
.ftitle{font-weight:600;flex:1}
.fmeta{color:var(--m);font-size:.78rem}
.body{padding:0 1.3rem 1.3rem;display:none}
.open .body{display:block}
.loc{background:var(--s2);border-radius:8px;padding:.65rem 1rem;margin-bottom:.9rem;font-family:monospace;font-size:.82rem;color:#06b6d4}
.code{background:#1e1e2e;border-radius:8px;padding:.9rem;font-family:monospace;font-size:.78rem;overflow-x:auto;white-space:pre;margin:.7rem 0;border:1px solid var(--b)}
.dl{color:var(--a);font-size:.75rem;font-weight:600;text-transform:uppercase;margin:.8rem 0 .3rem}
.fix{background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.25);border-radius:8px;padding:.65rem 1rem;font-size:.88rem}
.tag{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;background:var(--s2);border:1px solid var(--b);margin:.2rem .1rem}
.chev{transition:transform .2s;flex-shrink:0}
.open .chev{transform:rotate(180deg)}
footer{text-align:center;color:var(--m);font-size:.78rem;padding:3rem 0 2rem;border-top:1px solid var(--b);margin-top:3rem}
a{color:var(--a)}
</style></head>
<body>
<nav class="nav">
  <span class="logo">🛡️ LLMAppShield</span>
  <span class="badge">v0.1.0</span>
  <span class="badge">OWASP LLM Top 10</span>
</nav>
<div class="wrap">
  <h1>Security Report</h1>
  <p style="color:var(--m);margin-bottom:1.5rem">{{ scanned }} files scanned &nbsp;·&nbsp; {{ total }} findings</p>
  <div class="grid">
    <div class="card" style="border-color:#ef444440"><div class="num" style="color:#ef4444">{{ critical }}</div><div class="lbl">🔴 Critical</div></div>
    <div class="card" style="border-color:#f9731640"><div class="num" style="color:#f97316">{{ high }}</div><div class="lbl">🟠 High</div></div>
    <div class="card" style="border-color:#eab30840"><div class="num" style="color:#eab308">{{ medium }}</div><div class="lbl">🟡 Medium</div></div>
    <div class="card" style="border-color:#3b82f640"><div class="num" style="color:#3b82f6">{{ low }}</div><div class="lbl">🔵 Low</div></div>
    <div class="card"><div class="num" style="color:#6366f1">{{ total }}</div><div class="lbl">Total</div></div>
  </div>
  <div class="filters">
    <button class="btn on" onclick="filt('all',this)">All ({{ total }})</button>
    {% if critical %}<button class="btn" onclick="filt('critical',this)" style="color:#ef4444">🔴 Critical ({{ critical }})</button>{% endif %}
    {% if high %}<button class="btn" onclick="filt('high',this)" style="color:#f97316">🟠 High ({{ high }})</button>{% endif %}
    {% if medium %}<button class="btn" onclick="filt('medium',this)" style="color:#eab308">🟡 Medium ({{ medium }})</button>{% endif %}
    {% if low %}<button class="btn" onclick="filt('low',this)" style="color:#3b82f6">🔵 Low ({{ low }})</button>{% endif %}
  </div>
  <div id="fl">
  {% if not findings %}
  <div style="text-align:center;padding:4rem;color:var(--m)">
    <div style="font-size:3rem;margin-bottom:.8rem">✅</div>
    <div style="font-size:1.1rem;font-weight:600">No vulnerabilities detected!</div>
  </div>
  {% endif %}
  {% for f in findings %}
  <div class="card2" data-sev="{{ f.severity.value }}" id="f{{ loop.index }}">
    <div class="hdr" onclick="tog({{ loop.index }})">
      <span class="sbadge" style="background:{{ sev_style[f.severity.value] }}20;color:{{ sev_style[f.severity.value] }};border:1px solid {{ sev_style[f.severity.value] }}40">
        {{ sev_emoji[f.severity.value] }} {{ f.severity.value.upper() }}
      </span>
      <span class="ftitle">{{ f.title }}</span>
      <span class="fmeta">{{ f.rule_id }}</span>
      <svg class="chev" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>
    </div>
    <div class="body">
      <div class="loc">📍 {{ f.file_path }}:{{ f.line }}{% if f.owasp_id %} &nbsp;|&nbsp; {{ f.owasp_id }}{% endif %} &nbsp;|&nbsp; conf:{{ "%.0f"|format(f.confidence*100) }}%</div>
      {% if f.code_snippet %}<div class="code">{{ f.code_snippet }}</div>{% endif %}
      <div class="dl">Description</div><div>{{ f.description }}</div>
      {% if f.recommendation %}
      <div class="dl">Recommendation</div><div class="fix">💡 {{ f.recommendation }}</div>
      {% endif %}
      {% if f.tags %}<div style="margin-top:.7rem">{% for t in f.tags %}<span class="tag">{{ t }}</span>{% endfor %}</div>{% endif %}
    </div>
  </div>
  {% endfor %}
  </div>
</div>
<footer>Generated by <strong>LLMAppShield v0.1.0</strong> — <a href="https://github.com/llmappshield/llmapp-shield">github.com/llmappshield</a> — Built with ❤️ in 🇧🇷 Brazil</footer>
<script>
function tog(id){document.getElementById('f'+id).classList.toggle('open')}
function filt(s,btn){
  document.querySelectorAll('.btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('.card2').forEach(c=>{c.style.display=(s==='all'||c.dataset.sev===s)?'':'none'});
}
document.querySelectorAll('.card2[data-sev="critical"]').forEach(c=>c.classList.add('open'));
</script>
</body></html>"""


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    import time, argparse

    parser = argparse.ArgumentParser(
        description="🛡️  LLMAppShield — AI Security Scanner for LLM Applications"
    )
    parser.add_argument("target", nargs="?", default=".", help="File or directory to scan (default: .)")
    parser.add_argument("--json",  metavar="PATH", help="Export JSON report to path")
    parser.add_argument("--html",  metavar="PATH", help="Export HTML report to path")
    parser.add_argument("--fail-on", choices=["critical","high","medium","low"],
                        help="Exit with code 1 if findings at this severity exist")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-finding output")
    args = parser.parse_args()

    print_banner()

    target = Path(args.target)
    if not target.exists():
        print(f"  {RED}❌ Path not found: {target}{RESET}\n")
        sys.exit(2)

    print(f"  {CYAN}🔍 Scanning:{RESET} {BOLD}{target.resolve()}{RESET}")

    # Count files first
    exts = {".py",".ts",".tsx",".js",".jsx"}
    skip = {"__pycache__","node_modules",".venv","venv","env",".git","dist","build"}
    file_count = 0
    if target.is_file():
        file_count = 1
    else:
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in exts:
                if not any(part in skip for part in p.parts):
                    file_count += 1

    print(f"  {DIM}Found {file_count} source file(s) to analyze...{RESET}\n")

    t0 = time.time()
    findings = scan_directory(target) if target.is_dir() else scan_file(target)
    elapsed  = time.time() - t0

    print_summary(findings, file_count, elapsed)

    if not args.quiet:
        print_findings(findings)

    if args.json:
        export_json(findings, file_count, Path(args.json))
    if args.html:
        export_html(findings, file_count, Path(args.html))

    # Default: always write both reports
    default_json = Path("llmshield-report.json")
    default_html = Path("llmshield-report.html")
    if not args.json:
        export_json(findings, file_count, default_json)
    if not args.html:
        export_html(findings, file_count, default_html)

    if args.fail_on:
        order = {"critical":4,"high":3,"medium":2,"low":1}
        threshold = order[args.fail_on]
        if any(order[f.severity.value] >= threshold for f in findings):
            print(f"\n  {RED}{BOLD}❌ FAILED: Found '{args.fail_on.upper()}' or above findings.{RESET}\n")
            sys.exit(1)

    if findings:
        worst = max(findings, key=lambda f: f.severity.order)
        print(f"\n  {YELLOW}⚠️  Scan complete — {len(findings)} finding(s) detected.{RESET}")
        print(f"  {DIM}Worst severity: {worst.severity.emoji} {worst.severity.value.upper()}{RESET}\n")
    else:
        print(f"\n  {GREEN}{BOLD}✅ Scan complete — No vulnerabilities found!{RESET}\n")


if __name__ == "__main__":
    main()
