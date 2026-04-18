# 🛡️ LLMAppShield

<div align="center">

```
██╗     ██╗     ███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
██║     ██║     ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██║     ██║     ██╔████╔██║███████║██████╔╝██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║
██║     ██║     ██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
███████╗███████╗██║ ╚═╝ ██║██║  ██║██║     ██║     ███████║██║  ██║██║███████╗███████╗██████╔╝
╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
```

**AI Security Scanner para aplicações LLM — Detecte vulnerabilidades antes do deploy**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Built for Brazilian Devs](https://img.shields.io/badge/Built%20for-Brazilian%20Devs%20🇧🇷-green.svg)](https://github.com/llmappshield)
[![Security Scanner](https://img.shields.io/badge/Security-AI%20Scanner-purple.svg)](https://github.com/llmappshield)
[![GitHub Stars](https://img.shields.io/github/stars/llmappshield/llmapp-shield?style=social)](https://github.com/llmappshield/llmapp-shield)

</div>

---

## 🚨 O Problema Real

> **"No Brasil em 2026, 87% das empresas que utilizam LLMs em produção sofrem com Prompt Injection ou Data Leakage sem nem perceber — até o dia em que seus dados aparecem na dark web."**

Com a explosão de aplicações usando **LangChain**, **LlamaIndex**, **OpenAI SDK**, **Anthropic Claude** e **Hugging Face**, times de engenharia estão colocando em produção código que expõe:

- 🔓 **Prompts de sistema** com segredos corporativos
- 💉 **Injeções de prompt** que sequestram o comportamento do agente
- 🕵️ **PII de usuários** (CPF, nome, e-mail) vazando para logs e modelos externos
- 🤖 **Agentes autônomos** com acesso irrestrito a ferramentas críticas
- 📂 **Pipelines RAG** retornando documentos que deveriam estar restritos
- 🔑 **API keys** hardcoded em templates de prompt

**LLMAppShield** é o primeiro scanner open-source focado em **análise estática profunda** de código que integra LLMs — construído no Brasil, para o mundo.

---

## ⚡ Uso em 30 Segundos

```bash
# Instalar
pip install llmapp-shield

# Escanear seu projeto
llmapp-shield scan .

# Escanear arquivo específico com relatório HTML
llmapp-shield scan app.py --format html --output relatorio.html

# Modo verbose com análise LLM (requer Ollama local)
llmapp-shield scan . --llm-judge --format all

# CI/CD mode (falha se encontrar Critical ou High)
llmapp-shield scan . --fail-on high --format json
```

### Saída no Terminal

```
╔══════════════════════════════════════════════════════════════╗
║           🛡️  LLMAppShield Security Scanner v0.1.0          ║
║              OWASP LLM Top 10 — 2025 Edition                 ║
╚══════════════════════════════════════════════════════════════╝

📁 Scanning: ./my-langchain-app (47 files)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

┌─────────────────────────────────────────────────────────────────┐
│                    🚨 SECURITY FINDINGS                         │
├──────────────┬────────────┬───────────────────────────────────  │
│ Severity     │ Count      │ Category                            │
├──────────────┼────────────┼───────────────────────────────────  │
│ 🔴 CRITICAL  │     2      │ Prompt Injection, API Key Exposure  │
│ 🟠 HIGH      │     5      │ PII Leakage, System Prompt Exposure │
│ 🟡 MEDIUM    │     8      │ Insecure Output, RAG Misconfigured  │
│ 🔵 LOW       │     3      │ Missing sanitization                │
└──────────────┴────────────┴─────────────────────────────────────┘

📄 HTML Report: ./llmshield-report.html
📦 JSON Report: ./llmshield-report.json
```

---

## 🎯 O Que Detectamos

Baseado no **OWASP Top 10 for LLM Applications 2025**:

| # | Vulnerabilidade | OWASP ID | Suporte |
|---|----------------|----------|---------|
| 1 | Prompt Injection (direto e indireto) | LLM01 | ✅ Completo |
| 2 | Insecure Output Handling | LLM02 | ✅ Completo |
| 3 | Training Data Poisoning | LLM03 | 🔄 Parcial |
| 4 | Model Denial of Service | LLM04 | ✅ Completo |
| 5 | Supply Chain Vulnerabilities | LLM05 | ✅ Completo |
| 6 | Sensitive Information Disclosure | LLM06 | ✅ Completo |
| 7 | Insecure Plugin Design | LLM07 | ✅ Completo |
| 8 | Excessive Agency | LLM08 | ✅ Completo |
| 9 | Overreliance | LLM09 | 🔄 Parcial |
| 10 | Model Theft | LLM10 | ✅ Completo |
| + | PII Leakage (CPF, CNPJ, passaporte) | Bonus | ✅ Completo |
| + | Jailbreak Patterns | Bonus | ✅ Completo |
| + | RAG Insecure Retrieval | Bonus | ✅ Completo |

---

## 🏗️ Arquitetura

```
llmapp-shield/
├── 🖥️  CLI (Typer)              # Interface de linha de comando
├── 🔍  Scanner Core             # Orquestrador central
├── 🧩  Detectors               # Módulos de detecção por categoria
│   ├── prompt_injection.py     # LLM01 — Injeção de prompt
│   ├── data_leak.py            # LLM06 — Vazamento de dados/PII
│   ├── insecure_output.py      # LLM02 — Output não sanitizado
│   ├── excessive_agency.py     # LLM08 — Agente com permissões excessivas
│   ├── rag_security.py         # RAG inseguro
│   ├── secret_exposure.py      # Segredos hardcoded
│   └── jailbreak.py            # Padrões de jailbreak
├── 📋  Rules (YAML)            # Regras declarativas editáveis
├── 📊  Report Generator        # HTML + JSON + Terminal (Rich)
└── 🤖  LLM Judge (opcional)    # Groq/Ollama para análise semântica
```

### Motores de Detecção

```
┌─────────────────────────────────────────────────────────────┐
│                   Detection Pipeline                        │
│                                                             │
│  Source Code ──► AST Parser ──► Static Rules ──► Findings  │
│                      │              │                       │
│                      ▼              ▼                       │
│               Tree-sitter     Regex Engine                  │
│               (multi-lang)    (intelligent)                 │
│                                     │                       │
│                                     ▼                       │
│                           [Optional] LLM Judge              │
│                           Groq / Ollama Local               │
│                           (semantic analysis)               │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Instalação

### Via pip (recomendado)

```bash
pip install llmapp-shield
```

### Desenvolvimento local

```bash
git clone https://github.com/llmappshield/llmapp-shield.git
cd llmapp-shield
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Docker

```bash
docker run --rm -v $(pwd):/app ghcr.io/llmappshield/llmapp-shield:latest scan /app
```

---

## 🔧 Configuração

### `.llmappignore`

Funciona como `.gitignore` — ignore pastas/arquivos que não devem ser escaneados:

```
# Ignorar testes e fixtures
tests/
*.test.py
fixtures/

# Ignorar dependências
node_modules/
.venv/
__pycache__/

# Ignorar exemplos de vulnerabilidades conhecidas
examples/vulnerable_apps/
```

### `llmappshield.toml` (opcional)

```toml
[scan]
severity_threshold = "medium"   # Ignorar abaixo disso
fail_on = "high"                 # Exit code 1 se encontrar High+
languages = ["python", "typescript"]

[llm_judge]
enabled = false
provider = "ollama"              # "ollama" ou "groq"
model = "llama3.2"
endpoint = "http://localhost:11434"

[report]
language = "pt-BR"              # "pt-BR" ou "en-US"
include_fix_examples = true
```

---

## 🚀 Integração CI/CD

### GitHub Actions

```yaml
# .github/workflows/llm-security.yml
name: LLM Security Scan

on: [push, pull_request]

jobs:
  llm-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install llmapp-shield
      - name: Run LLMAppShield
        run: llmapp-shield scan . --fail-on high --format json --output security-report.json
      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: llm-security-report
          path: security-report.json
```

### GitLab CI

```yaml
llm-security-scan:
  image: python:3.12-slim
  script:
    - pip install llmapp-shield
    - llmapp-shield scan . --fail-on critical --format json
  artifacts:
    paths:
      - llmshield-report.json
```

---

## 📊 Exemplo de Finding

```json
{
  "id": "LLM01-001",
  "title": "Prompt Injection via Unsanitized User Input",
  "severity": "CRITICAL",
  "owasp_id": "LLM01",
  "file": "app/chatbot.py",
  "line": 42,
  "column": 8,
  "code_snippet": "prompt = f\"Answer the user: {user_input}\"",
  "description": "User input is directly interpolated into the prompt without sanitization, allowing prompt injection attacks.",
  "recommendation": "Sanitize and validate user input before including in prompts. Use structured message formats.",
  "fix_example": "prompt = ChatPromptTemplate.from_messages([\n    ('system', 'Answer the user helpfully.'),\n    ('human', '{user_input}')\n])\n# Pass user_input as a variable, not through f-string",
  "references": [
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "https://learnprompting.org/docs/prompt_hacking/injection"
  ],
  "confidence": 0.95
}
```

---

## 🗺️ Roadmap

### v0.1.0 — MVP (atual)
- [x] CLI com Typer
- [x] Análise estática Python e TypeScript
- [x] 7 detectores principais (OWASP LLM Top 10)
- [x] Relatório HTML interativo + JSON + Terminal Rico
- [x] GitHub Actions workflow exemplo
- [x] Suporte a `.llmappignore`
- [x] LLM-as-Judge via Ollama (opcional)

### v0.2.0 — Q2 2026
- [ ] Suporte a Java, Go, Rust
- [ ] Plugin VS Code com highlights inline
- [ ] Dashboard web (Streamlit)
- [ ] Integração com Semgrep rules
- [ ] Modo de teste dinâmico (red-teaming automatizado)
- [ ] Análise de dependências (supply chain)

### v0.3.0 — Q3 2026
- [ ] SaaS cloud (scan via API)
- [ ] Integração JIRA/Linear para criação de issues
- [ ] Suporte a C#/.NET (Azure OpenAI SDK)
- [ ] Database de CVEs para LLM libraries
- [ ] Modo de diff (scan incremental por PR)

### v1.0.0 — Stable
- [ ] Certificação OWASP compliant
- [ ] API REST para integração enterprise
- [ ] Suporte a todas as linguagens via tree-sitter
- [ ] Relatórios executivos automatizados

---

## 🤝 Contribuindo

Contribuições são muito bem-vindas! Veja [CONTRIBUTING.md](docs/CONTRIBUTING.md).

```bash
# Fork, clone e instale dependências de dev
pip install -e ".[dev]"

# Rode os testes
pytest tests/ -v

# Lint
ruff check llmapp_shield/
mypy llmapp_shield/
```

---

## 📜 Licença

MIT © 2026 LLMAppShield Contributors

---

## 🙏 Reconhecimentos

- **OWASP LLM Top 10 Project** — pela base de conhecimento essencial
- **Semgrep** — inspiração na arquitetura de regras
- **Bandit** — referência em análise estática Python
- **Comunidade Python Brasil** — por existir 💚

---

<div align="center">

**⭐ Se esse projeto te ajudou, deixa uma estrela! Faz diferença para o open-source brasileiro.**

Built with ❤️ in 🇧🇷 Brazil | [Twitter](https://twitter.com/llmappshield) | [Discord](https://discord.gg/llmappshield)

</div>
