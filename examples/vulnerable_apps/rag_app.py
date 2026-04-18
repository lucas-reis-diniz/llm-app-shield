# examples/vulnerable_apps/rag_app.py
"""
⚠️  INTENTIONALLY VULNERABLE RAG APP — FOR DEMONSTRATION PURPOSES ONLY ⚠️

Vulnerabilities:
1. [RAG-ACCESS-001]  No access control on document retrieval
2. [LLM01-001]       Prompt injection in RAG context
3. [LLM06-LOG-001]   Logging sensitive retrieved documents
4. [SEC-ANTHROPIC]   Hardcoded Anthropic API key
5. [LLM08-FILE]      Agent with unrestricted file writing
"""

import logging
from anthropic import Anthropic
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.document_loaders import DirectoryLoader
from langchain.tools import WriteFileTool

logger = logging.getLogger(__name__)

# ❌ Hardcoded Anthropic API key (SEC-ANTHROPIC - CRITICAL)
client = Anthropic(api_key="sk-ant-api03-realexposedkey12345678")

# Global vector store (shared across all users — no tenant isolation)
embeddings = OpenAIEmbeddings()
vectorstore = FAISS.from_texts(
    ["confidential: Q3 revenue $50M", "internal: employee salaries 2024"],
    embeddings,
    # ❌ No metadata filtering or tenant isolation
)
retriever = vectorstore.as_retriever(search_kwargs={"k": 5})


def answer_question(user_input: str) -> dict:
    """
    Answer user question using RAG.
    Multiple vulnerabilities present.
    """

    # ❌ RAG retrieval with raw user input (no sanitization, no access control)
    retrieved_docs = retriever.get_relevant_documents(user_input)

    # ❌ Logging retrieved documents (may contain confidential data)
    logger.info(f"Retrieved docs for prompt: {retrieved_docs}")

    # Build context (all users get all documents — no RBAC)
    context = "\n".join([doc.page_content for doc in retrieved_docs])

    # ❌ Prompt injection: user_input goes directly into RAG prompt
    prompt = f"""
    Context: {context}
    
    User question: {user_input}
    
    Based on the context, answer the question.
    """

    response = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    answer = response.content[0].text

    return {
        "answer": answer,
        "source_documents": retrieved_docs,  # ❌ Exposing raw docs in API response
    }


def index_documents(directory: str) -> None:
    """Index documents from a directory."""
    loader = DirectoryLoader(directory)
    docs = loader.load()

    # ❌ All documents indexed together, no per-document ACL
    global vectorstore
    vectorstore = FAISS.from_documents(docs, embeddings)


def create_rag_agent_with_file_write():
    """
    RAG agent that can write files.
    ❌ Excessive agency: agent can write arbitrary files (LLM08)
    """
    from langchain.agents import initialize_agent, AgentType
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(model="gpt-4")
    tools = [WriteFileTool()]  # ❌ Agent can write any file!

    return initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT,
    )
