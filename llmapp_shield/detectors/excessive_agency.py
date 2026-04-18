# llmapp_shield/detectors/excessive_agency.py
"""
Excessive Agency Detector — OWASP LLM08.

Detects patterns where LLM agents are granted excessive permissions,
access to sensitive tools, or lack proper human oversight before
executing potentially dangerous actions.

Covers:
- LLM agents with unrestricted filesystem access
- Agents with database write access without confirmation
- Agents able to make external HTTP calls without restrictions
- LangChain agents with dangerous tools (shell, python_repl)
- Missing human-in-the-loop for critical operations
- Agents with email/Slack send capabilities without review
- Excessive API scope in tool definitions
"""

from __future__ import annotations

import re
from pathlib import Path

from llmapp_shield.detectors import BaseDetector
from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory


_OWASP_LLM08 = OWASPCategory(
    id="LLM08",
    name="Excessive Agency",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/llm08-excessive-agency",
)

# Dangerous tool names in LangChain/LlamaIndex
_DANGEROUS_TOOLS = [
    "ShellTool",
    "PythonREPLTool",
    "BashTool",
    "FileManagementToolkit",
    "WriteFileTool",
    "CopyFileTool",
    "DeleteFileTool",
    "MoveFileTool",
    "SqlDatabaseToolkit",
    "SQLDatabaseTool",
    "RequestsGetTool",
    "RequestsPostTool",
    "GmailSendMessage",
    "SlackSendMessage",
    "GmailCreateDraft",
    "E2BDataAnalysisTool",
    "HumanInputRun",  # Ironic: marks the absence of proper oversight
]

_DANGEROUS_TOOL_PATTERN = r"(?:" + "|".join(re.escape(t) for t in _DANGEROUS_TOOLS) + r")\s*\("

# Patterns for unrestricted agent creation
_AGENT_PATTERNS: list[tuple[str, str, str, Severity]] = [
    (
        "LLM08-SHELL-001",
        r"(?:ShellTool|BashTool|bash_tool)\s*\(",
        "LLM agent has access to Shell/Bash execution tool",
        Severity.CRITICAL,
    ),
    (
        "LLM08-REPL-001",
        r"(?:PythonREPLTool|python_repl|PythonAstREPLTool)\s*\(",
        "LLM agent has access to Python REPL — arbitrary code execution",
        Severity.CRITICAL,
    ),
    (
        "LLM08-FILE-WRITE-001",
        r"(?:WriteFileTool|DeleteFileTool|MoveFileTool|FileManagementToolkit)\s*\(",
        "LLM agent has unrestricted filesystem write/delete access",
        Severity.HIGH,
    ),
    (
        "LLM08-DB-WRITE-001",
        r"(?:SqlDatabaseToolkit|SQLDatabaseTool).*(?:write|insert|update|delete|DROP|CREATE)",
        "LLM agent appears to have database write permissions",
        Severity.HIGH,
    ),
    (
        "LLM08-EMAIL-001",
        r"(?:GmailSendMessage|send_email|smtp\.sendmail|email\.send)\s*(?:\(|=)",
        "LLM agent can send emails without human review",
        Severity.HIGH,
    ),
    (
        "LLM08-AGENT-VERBOSE-001",
        r"(?:initialize_agent|AgentExecutor)\s*\([^)]*verbose\s*=\s*False",
        "Agent initialized with verbose=False — reduces auditability",
        Severity.LOW,
    ),
    (
        "LLM08-MAX-ITER-001",
        r"(?:initialize_agent|AgentExecutor)\s*\([^)]*max_iterations\s*=\s*(?:[5-9][0-9]|[1-9][0-9]{2,})",
        "Agent configured with very high max_iterations (DoS/runaway agent risk)",
        Severity.MEDIUM,
    ),
    (
        "LLM08-HUMAN-LOOP-001",
        r"(?:ZERO_SHOT_REACT_DESCRIPTION|STRUCTURED_CHAT_ZERO_SHOT|CONVERSATIONAL_REACT_DESCRIPTION).*\n(?!.*(?:human_approval|confirm|review|hitl|human_in_the_loop))",
        "Zero-shot agent without apparent human-in-the-loop approval",
        Severity.MEDIUM,
    ),
]

# OpenAI function calling with dangerous permissions
_OPENAI_FUNCTION_PATTERNS = [
    (
        "LLM08-FUNC-EXEC-001",
        r'"function".*"name".*"(?:execute|run_code|shell|bash|system|exec|eval)"',
        "OpenAI function tool definition allows code/shell execution",
        Severity.CRITICAL,
    ),
    (
        "LLM08-FUNC-DB-001",
        r'"function".*"name".*"(?:query_db|execute_sql|run_query|delete_record|drop_table)"',
        "OpenAI function tool definition allows database operations",
        Severity.HIGH,
    ),
    (
        "LLM08-FUNC-HTTP-001",
        r'"function".*"name".*"(?:make_request|fetch_url|http_request|web_request)"',
        "OpenAI function allows arbitrary HTTP requests (SSRF risk)",
        Severity.HIGH,
    ),
]


class ExcessiveAgencyDetector(BaseDetector):
    """
    Detects Excessive Agency vulnerabilities (OWASP LLM08).

    Identifies LLM agents granted excessive permissions or dangerous
    tool access without adequate oversight controls.
    """

    CATEGORY = "excessive_agency"

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
        findings.extend(self._detect_dangerous_tools(source_code, file_path))
        findings.extend(self._detect_agent_patterns(source_code, file_path))

        return findings

    def _detect_dangerous_tools(self, source_code: str, file_path: Path) -> list[Finding]:
        """Detect use of dangerous LangChain/agent tools."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        try:
            compiled = re.compile(_DANGEROUS_TOOL_PATTERN, re.IGNORECASE | re.MULTILINE)
            for match in compiled.finditer(source_code):
                line_num = source_code[: match.start()].count("\n") + 1
                line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                if line_text.lstrip().startswith("#"):
                    continue

                tool_name = match.group(0).rstrip("(").strip()
                snippet = "\n".join(lines[max(0, line_num - 3): min(len(lines), line_num + 2)])

                severity = _tool_severity(tool_name)
                findings.append(
                    Finding(
                        rule_id="LLM08-TOOL-001",
                        title=f"Dangerous Agent Tool Detected: {tool_name}",
                        severity=severity,
                        category=self.CATEGORY,
                        owasp=_OWASP_LLM08,
                        file_path=file_path,
                        line=line_num,
                        column=0,
                        code_snippet=snippet,
                        description=(
                            f"The agent tool '{tool_name}' grants the LLM excessive permissions. "
                            "If the agent is compromised via prompt injection, an attacker could "
                            "use this tool to execute arbitrary code, delete files, or exfiltrate data."
                        ),
                        description_pt=(
                            f"A ferramenta de agente '{tool_name}' concede permissões excessivas ao LLM. "
                            "Se o agente for comprometido via prompt injection, um atacante poderia "
                            "usar esta ferramenta para executar código arbitrário, deletar arquivos "
                            "ou exfiltrar dados."
                        ),
                        recommendation=(
                            "Apply the principle of least privilege to agent tools. "
                            "Restrict tool permissions to only what is necessary. "
                            "Add human-in-the-loop approval for irreversible actions. "
                            "Consider using read-only versions of tools where possible."
                        ),
                        recommendation_pt=(
                            "Aplique o princípio de menor privilégio para ferramentas de agente. "
                            "Restrinja permissões de ferramentas ao mínimo necessário. "
                            "Adicione aprovação humana para ações irreversíveis. "
                            "Considere usar versões somente leitura das ferramentas quando possível."
                        ),
                        fix_example=_FIX_EXCESSIVE_AGENCY,
                        confidence=0.90,
                        references=[
                            "https://owasp.org/www-project-top-10-for-large-language-model-applications/llm08-excessive-agency",
                            "https://python.langchain.com/docs/concepts/tools/",
                        ],
                        tags=["excessive-agency", "llm08", "agent", tool_name.lower()],
                        detected_by="regex",
                    )
                )
        except re.error:
            pass

        return findings

    def _detect_agent_patterns(self, source_code: str, file_path: Path) -> list[Finding]:
        """Detect other excessive agency patterns."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        all_patterns = _AGENT_PATTERNS + _OPENAI_FUNCTION_PATTERNS

        for rule_id, pattern, description, severity in all_patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""

                    if line_text.lstrip().startswith("#"):
                        continue

                    snippet = "\n".join(lines[max(0, line_num - 3): min(len(lines), line_num + 2)])
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=f"Excessive Agency: {_short_desc(description)}",
                            severity=severity,
                            category=self.CATEGORY,
                            owasp=_OWASP_LLM08,
                            file_path=file_path,
                            line=line_num,
                            column=0,
                            code_snippet=snippet,
                            description=description + (
                                " — This violates the principle of least privilege for AI agents "
                                "(OWASP LLM08: Excessive Agency)."
                            ),
                            description_pt=(
                                f"{description} — Isso viola o princípio de menor privilégio "
                                "para agentes de IA (OWASP LLM08: Excessive Agency)."
                            ),
                            recommendation=(
                                "Limit agent capabilities. Add human approval steps for critical actions. "
                                "Use read-only tools where possible. Implement rate limiting and audit logging."
                            ),
                            fix_example=_FIX_EXCESSIVE_AGENCY,
                            confidence=0.80,
                            tags=["excessive-agency", "llm08", "agent"],
                            detected_by="regex",
                        )
                    )
            except re.error:
                continue

        return findings


def _tool_severity(tool_name: str) -> Severity:
    critical_tools = {"ShellTool", "BashTool", "PythonREPLTool", "PythonAstREPLTool"}
    high_tools = {
        "WriteFileTool", "DeleteFileTool", "MoveFileTool",
        "GmailSendMessage", "SlackSendMessage", "SqlDatabaseToolkit",
    }
    if tool_name in critical_tools:
        return Severity.CRITICAL
    if tool_name in high_tools:
        return Severity.HIGH
    return Severity.MEDIUM


def _short_desc(description: str) -> str:
    return description.split("—")[0].strip()


_FIX_EXCESSIVE_AGENCY = '''
# ❌ VULNERABLE — Agent with dangerous tools and no oversight
from langchain.agents import initialize_agent, AgentType
from langchain_community.tools import ShellTool, WriteFileTool

tools = [ShellTool(), WriteFileTool()]  # CRITICAL: LLM can execute any shell command!
agent = initialize_agent(tools, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)

# ✅ SECURE — Principle of Least Privilege + Human-in-the-Loop

from langchain.tools import tool
from langchain.callbacks.base import BaseCallbackHandler

# 1. Create restricted, specific tools instead of generic shell access
@tool
def get_weather(city: str) -> str:
    """Get weather for a specific city. Only this operation is allowed."""
    if not city.replace(" ", "").isalpha():
        raise ValueError("Invalid city name")
    # Call specific, whitelisted weather API
    return weather_api.get(city)

# 2. Add human approval for dangerous operations
class HumanApprovalHandler(BaseCallbackHandler):
    def on_tool_start(self, tool_name: str, tool_input: str, **kwargs):
        if tool_name in DANGEROUS_TOOLS:
            approved = input(f"Approve {tool_name}({tool_input})? [y/N]: ")
            if approved.lower() != "y":
                raise PermissionError("Action not approved by human operator")

# 3. Limit iterations and set timeouts
agent = initialize_agent(
    tools=[get_weather],  # Only specific, safe tools
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    max_iterations=5,       # Prevent runaway agents
    verbose=True,           # Always audit
    callbacks=[HumanApprovalHandler()],  # Human oversight
)
'''
