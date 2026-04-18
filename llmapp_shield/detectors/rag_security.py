# llmapp_shield/detectors/rag_security.py
"""
RAG (Retrieval-Augmented Generation) Security Detector.

Detects insecure retrieval patterns in RAG pipelines that could lead to
unauthorized document access, prompt injection via retrieved content, or
data exfiltration through retrieval manipulation.
"""

from __future__ import annotations

import re
from pathlib import Path

from llmapp_shield.detectors import BaseDetector
from llmapp_shield.models import Finding, Rule, Severity, OWASPCategory

_OWASP_LLM06 = OWASPCategory(
    id="LLM06",
    name="Sensitive Information Disclosure (RAG)",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
)

_RAG_PATTERNS: list[tuple[str, str, str, Severity]] = [
    (
        "RAG-ACCESS-001",
        r"(?:retriever|vector_store|vectorstore)\.(?:get_relevant_documents|similarity_search|retrieve)\s*\(\s*(?:user_input|query|request|user_query)",
        "RAG retriever called with raw user input — no access control on retrieved documents",
        Severity.HIGH,
    ),
    (
        "RAG-INJECT-001",
        r"(?:Document|chunk|passage|retrieved_doc).*(?:page_content|text)\s*\+\s*(?:user_input|query)",
        "Retrieved RAG document content concatenated with user input — injection risk",
        Severity.HIGH,
    ),
    (
        "RAG-NOFILTER-001",
        r"(?:FAISS|Chroma|Pinecone|Weaviate|Qdrant|Milvus)\.(?:from_documents|from_texts)\s*\([^)]*\)\s*\n(?!.*(?:filter|where|metadata_filter|user_id|tenant))",
        "Vector store created without apparent multi-tenancy or access control filters",
        Severity.MEDIUM,
    ),
    (
        "RAG-EXPOSE-001",
        r"(?:source_documents|retrieved_docs|context_docs)\s*=.*\n.*(?:return|send|json|response).*\1",
        "Retrieved RAG source documents may be exposed in API response",
        Severity.MEDIUM,
    ),
]


class RAGSecurityDetector(BaseDetector):
    CATEGORY = "rag_security"

    def _detect(self, source_code: str, file_path: Path, language: str, rules: list[Rule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if rule.pattern_type == "regex":
                findings.extend(self._regex_scan(source_code, file_path, rule))

        lines = source_code.splitlines()
        for rule_id, pattern, description, severity in _RAG_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for match in compiled.finditer(source_code):
                    line_num = source_code[: match.start()].count("\n") + 1
                    snippet = "\n".join(lines[max(0, line_num - 3): min(len(lines), line_num + 2)])
                    findings.append(Finding(
                        rule_id=rule_id,
                        title=f"RAG Security Issue: {description.split('—')[0].strip()}",
                        severity=severity,
                        category=self.CATEGORY,
                        owasp=_OWASP_LLM06,
                        file_path=file_path,
                        line=line_num,
                        column=0,
                        code_snippet=snippet,
                        description=description,
                        description_pt=f"Problema de segurança no pipeline RAG: {description}",
                        recommendation=(
                            "Implement document-level access control in RAG pipelines. "
                            "Filter retrieved documents based on user permissions before including in context. "
                            "Validate and sanitize user queries before retrieval. "
                            "Never expose source documents directly in API responses without access checks."
                        ),
                        recommendation_pt=(
                            "Implemente controle de acesso a nível de documento em pipelines RAG. "
                            "Filtre documentos recuperados com base nas permissões do usuário antes de incluir no contexto."
                        ),
                        fix_example=_FIX_RAG,
                        confidence=0.75,
                        tags=["rag", "retrieval", "access-control", "llm06"],
                        detected_by="regex",
                    ))
            except re.error:
                continue
        return findings


_FIX_RAG = '''
# ❌ VULNERABLE — No access control on RAG retrieval
docs = retriever.get_relevant_documents(user_input)
context = "\\n".join([d.page_content for d in docs])
response = llm.invoke(f"Answer based on: {context}\\n\\nQuestion: {user_input}")

# ✅ SECURE — Access-controlled RAG
def secure_retrieve(user_input: str, user_id: str, user_roles: list[str]) -> list[Document]:
    # 1. Sanitize query
    sanitized_query = sanitize_input(user_input)

    # 2. Retrieve with metadata filter (tenant isolation)
    docs = vectorstore.similarity_search(
        sanitized_query,
        filter={"allowed_roles": {"$in": user_roles}, "tenant_id": user_tenant},
        k=5,
    )

    # 3. Post-retrieval access check
    return [d for d in docs if user_can_access(user_id, d.metadata.get("doc_id"))]

# 4. Don't expose source documents in API response
def answer_question(user_input: str, user_id: str, user_roles: list[str]) -> dict:
    docs = secure_retrieve(user_input, user_id, user_roles)
    context = "\\n".join([d.page_content for d in docs])
    answer = llm.invoke(build_rag_prompt(context, user_input))
    return {
        "answer": answer,
        # "sources": docs  # ❌ Don't expose raw docs
        "source_count": len(docs),  # ✅ Only metadata is safe
    }
'''
