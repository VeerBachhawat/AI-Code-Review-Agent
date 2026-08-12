# SentinelAI — AI Code Review & Security Analysis Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-009688)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB)](https://react.dev/)
[![Ollama](https://img.shields.io/badge/Ollama-Qwen3%3A8b-black)](https://ollama.ai/)

> An autonomous, multi-agent AI application security auditing and code review platform powered by static AST analysis, hybrid RAG context retrieval, local LLM inference (Ollama Qwen3:8b), and enterprise one-page PDF/HTML report generation.

---

## Project Overview

**SentinelAI** bridges the gap between static application security testing (SAST) and AI-driven automated remediation. Traditional SAST tools generate overwhelming lists of raw warnings without actionable code context, while basic LLM chatbots frequently generate generic code advice containing invalid syntax or security anti-patterns.

SentinelAI solves this by deploying a **Multi-Agent Pipeline**:
1. **Static AST & Pattern Analysis**: Detects security vulnerabilities and code quality flaws deterministically.
2. **Context Enrichment & RAG**: Grounds findings in OWASP Top 10 guidelines, CWE definitions, and PEP 8 standards using ChromaDB vector store embeddings.
3. **Local LLM Remediation & PR Summaries**: Generates code-specific, zero-placeholder remediations and developer-facing mentor PR summaries via Ollama (`qwen3:8b`).
4. **Enterprise Reporting**: Produces single-page A4 PDF and responsive HTML security reports.

---

## Problem Statement

Modern software engineering teams face three critical code review challenges:
1. **High False Positive Rates & Noise**: Traditional static analysis tools lack code context and actionable refactoring instructions.
2. **Generic AI Hallucinations**: Standard LLMs often produce generic placeholders (`# Example code`, `# Refactored implementation`) rather than addressing actual variable names and logic in the developer's source code.
3. **Data Privacy Concerns**: Transmitting proprietary codebase files to external cloud LLMs violates corporate security compliance policies.

---

## Key Objectives

- **100% Local & Privacy-First**: Execute all AI inference locally via Ollama (`qwen3:8b`), requiring zero external API keys or cloud transmissions.
- **AST & Pattern Grounding**: Combine Python AST parsing and Java pattern matching for precise line-level detection.
- **Actionable Remediation**: Produce code replacements that directly reference actual submitted variables and syntax.
- **Severity Count Fidelity**: Ensure PR summaries and reports strictly reflect calculated severity counts (`Critical`, `High`, `Medium`, `Low`).
- **Single-Page Enterprise Reporting**: Export executive PDF reports formatted precisely to fit a single A4 page.

---

## Key Features

- **Automatic Language Detection**: Auto-detects Python (`.py`) and Java (`.java`) code submissions.
- **AST & Security Analysis**: Detects code smells (cyclomatic complexity, Halstead metrics, unused variables/imports) and vulnerabilities (`eval()`, hardcoded secrets, SQL injection, XSS).
- **Automated Score System**: Calculates **Security Score** (0–100) and **Code Quality Score** (0–100) using weighted penalty algorithms.
- **Ollama Batch Remediations**: Generates code replacements in single batch LLM calls for minimal latency.
- **PR Summary Generator**: Generates mentor-style PR summaries with actionable next steps and effort estimations.
- **Interactive Conversational Assistant**: Grounded hybrid RAG assistant capable of explaining findings, providing OWASP guidance, and rewriting complete corrected source code.
- **Offline Fallback Guarantee**: Retains deterministic rule-based remediations and summaries if Ollama is unavailable or times out.
- **Exportable PDF & HTML Reports**: One-click download of executive reports.

---

## System Architecture

```
[ User Code Submission / File Upload ]
                 │
                 ▼
     [ Language Detector & Validator ]
                 │
        ┌────────┴────────┐
        ▼                 ▼
[ CodeAnalysisAgent ] [ SecurityAgent ]
 (AST & Metrics)     (Vulnerabilities)
        └────────┬────────┘
                 ▼
           [ Orchestrator ]
  (Scores, Deduplication, Findings)
                 │
        ┌────────┴────────┐
        ▼                 ▼
[ RemediationAgent ] [ PRSummaryAgent ]
 (Ollama / Fallback) (Ollama / Fallback)
        └────────┬────────┘
                 ▼
 ┌───────────────┴───────────────┐
 ▼                               ▼
[ PDF / HTML Report Generator ] [ Conversational AI Assistant ]
                                  (Hybrid RAG / ChromaDB)
```

---

## Technology Stack

- **Backend Framework**: Python 3.10+ / FastAPI / Pydantic
- **Frontend Framework**: React 19 / TypeScript / Vite / Tailwind CSS / Lucide Icons
- **Static Code Analysis**: Python `ast` module, Radon (complexity & metrics), Java regex pattern matching
- **AI / LLM Service**: Ollama (`qwen3:8b`) via OpenAI-compatible REST API
- **RAG & Vector Storage**: ChromaDB (`chromadb`), `sentence-transformers` (`all-MiniLM-L6-v2`)
- **PDF & Report Engine**: ReportLab (PDF), Custom CSS HTML Generator
- **Testing**: Python `unittest` suite, `TestClient` (HTTPX)

---

## Multi-Agent Architecture

1. **`CodeAnalysisAgent`**: Evaluates cyclomatic complexity, Halstead volume, maintainability index, dead code, unused imports, and style violations.
2. **`SecurityAgent`**: Scans for OWASP Top 10 vulnerabilities including dynamic code evaluation (`eval()`), hardcoded credentials, command injection, weak cryptography, SQL injection, and XSS.
3. **`Orchestrator`**: Coordinates execution flow, deduplicates findings, calculates weighted quality and security scores, and attaches line snippets.
4. **`RemediationAgent`**: Batches findings to Ollama to generate code replacements using exact variable names.
5. **`PRSummaryAgent`**: Synthesizes findings into developer-facing PR review comments, status labels, and effort estimates.
6. **`ConversationalCodeAssistant`**: Provides chat-based follow-up assistance grounded in source code, findings, and RAG knowledge.

---

## RAG Pipeline & LLM Integration

- **Vector Database**: ChromaDB vector store persisted at `backend/vector_db/`.
- **Knowledge Ingestion**: Security knowledge base covering OWASP Top 10 2021, CWE definitions, and PEP 8 standards.
- **LLM Integration**: Interfaced via `OllamaService` (`http://localhost:11434/v1/`) with configurable max token limits and timeout protection.
- **Local Fallback Engine**: If ChromaDB or Ollama is unreachable, `assistant_knowledge.py` provides local deterministic answers.

---

## FastAPI API Endpoints

- `POST /submit-code`: Validates syntax and detects language.
- `POST /upload-file`: Accepts `.py` or `.java` file uploads.
- `POST /review-code`: Triggers the complete multi-agent review pipeline.
- `POST /chat`: Interacts with the hybrid RAG assistant.
- `POST /explain-finding`: Explains a specific line finding.
- `POST /ask-remediation`: Generates targeted remediation advice.
- `GET /download-report/{report_id}.pdf`: Downloads executive single-page A4 PDF report.
- `GET /download-report/{report_id}.html`: Downloads responsive HTML report.
- `GET /health`: Returns system status and Ollama availability.
- `GET /history`: Returns review history logs.

---

## Project Folder Structure

```
AI-Code-Review-Agent/
├── backend/
│   ├── agents/
│   │   ├── code_analysis_agent.py
│   │   ├── conversational_code_assistant.py
│   │   ├── orchestrator.py
│   │   ├── pr_summary_agent.py
│   │   ├── remediation_agent.py
│   │   └── security_agent.py
│   ├── knowledge/
│   │   └── assistant_knowledge.py
│   ├── llm/
│   │   └── ollama_service.py
│   ├── rag/
│   │   └── rag_engine.py
│   ├── reporting/
│   │   ├── html_generator.py
│   │   └── pdf_generator.py
│   ├── storage/
│   │   └── history_manager.py
│   ├── vector_db/
│   │   └── vector_store.py
│   ├── main.py
│   └── requirements.txt
├── docs/
│   ├── API_DOCUMENTATION.md
│   ├── FINAL_DEMONSTRATION.md
│   ├── FINAL_PROJECT_REPORT_OUTLINE.md
│   ├── MILESTONE_COMPLETION.md
│   ├── PRESENTATION_CONTENT.md
│   ├── SECURITY_CHECKLIST.md
│   ├── TECHNICAL_DOCUMENTATION.md
│   └── TESTING_DOCUMENTATION.md
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── services/
│   │   └── App.tsx
│   ├── package.json
│   └── vite.config.ts
├── tests/
│   ├── samples/
│   ├── test_api.py
│   ├── test_code_analysis.py
│   ├── test_orchestrator.py
│   ├── test_pr_summary.py
│   ├── test_prompt_quality.py
│   ├── test_rag_assistant.py
│   ├── test_remediation.py
│   ├── test_reports.py
│   └── test_security.py
├── .env.example
├── .gitignore
└── README.md
```

---

## Installation & Setup

### Prerequisites
- **Python 3.10+**
- **Node.js 18+ & npm**
- **Ollama** installed locally (`ollama run qwen3:8b`)

### 1. Environment Setup

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Example `.env` configuration:
```env
OLLAMA_BASE_URL=http://localhost:11434/v1/
OLLAMA_MODEL=qwen3:8b
OLLAMA_TIMEOUT=300.0
LLM_MAX_REVIEW_TOKENS=2000
LLM_MAX_SUMMARY_TOKENS=1000
LLM_MAX_CHAT_TOKENS=1000
```

### 2. Backend Installation & Startup

```bash
# Create and activate virtual environment
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r backend/requirements.txt

# Start FastAPI server
python -m uvicorn backend.main:app --port 8001 --reload
```

Backend will run at: `http://localhost:8001`  
Swagger API Docs available at: `http://localhost:8001/docs`

### 3. Frontend Installation & Startup

```bash
cd frontend
npm install
npm run dev
```

Frontend will run at: `http://localhost:5173`

---

## Testing Instructions

Run the backend unit and end-to-end test suite:

```bash
$env:PYTHONPATH="."
python -m unittest discover -s tests -p "test_*.py"
```

Verify frontend production build:
```bash
cd frontend
npm run build
```

---

## Security Considerations

- **No Remote Data Exposure**: Code submissions remain entirely on the local system.
- **Input Validation**: Source code input is strictly sanitized and passed as DATA blocks.
- **Prompt Injection Defense**: Untrusted user code inside `<submitted_source_code>` blocks cannot override system prompt safety instructions.
- **Zero Credentials Saved**: No hardcoded API keys or sensitive credentials exist in the codebase.

---

## Limitations

- **Java Static Analysis**: Java code analysis uses regex pattern matching rather than Java AST compilation.
- **LLM Hardware Dependencies**: Local inference speed depends on host CPU/GPU performance (approx. 15–60 seconds per review).

---

## Future Scope

- **Java AST Parser**: Integrate ANTLR or Spoon for AST-level Java analysis.
- **CI/CD Integration**: Develop GitHub Actions and GitLab CI plugins for automated PR gating.
- **Multi-File Project Analysis**: Extend repository scanning across multi-file directories.

---

## License

This project is licensed under the MIT License.