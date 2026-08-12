# SentinelAI — Technical Documentation

## 1. System Architecture

SentinelAI is an enterprise-grade multi-agent AI code review and security analysis platform. The architecture separates static code analysis, AI-driven remediation, retrieval-augmented generation (RAG), and user interface concerns into a modular pipeline.

```
┌────────────────────────────────────────────────────────────────────────┐
│                          REACT 19 FRONTEND                             │
│       (Dashboard | Code Editor | Findings | PR Summary | Assistant)    │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ HTTP / REST
┌──────────────────────────────────▼─────────────────────────────────────┐
│                           FASTAPI BACKEND                              │
│         (Endpoints: /submit-code, /review-code, /chat, /reports)       │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│                          ORCHESTRATOR PIPELINE                         │
│  1. Language Detection & Syntax Validation                             │
│  2. Parallel Static Scanning (CodeAnalysisAgent + SecurityAgent)       │
│  3. Score Calculation & Finding Deduplication                          │
│  4. Batch LLM Remediation & PR Summary Generation                      │
└──────┬───────────────────────────┬───────────────────────────────┬─────┘
       │                           │                               │
       ▼                           ▼                               ▼
┌──────────────┐          ┌─────────────────┐           ┌────────────────────┐
│ OLLAMA LLM   │          │ CHROMADB VECTOR │           │ REPORT GENERATOR   │
│  (Qwen3:8b)  │          │   STORE (RAG)   │           │ (ReportLab / HTML) │
└──────────────┘          └─────────────────┘           └────────────────────┘
```

---

## 2. Data Flow

1. **Submission Phase**: User submits code via text entry or file upload (`POST /submit-code` or `POST /upload-file`).
2. **Validation Phase**: Code syntax is validated. Language auto-detector determines Python vs Java.
3. **Static Analysis Phase**: `CodeAnalysisAgent` and `SecurityAgent` execute static AST visits or pattern regex matches concurrently.
4. **Scoring & Aggregation Phase**: `Orchestrator` deduplicates findings, attaches line snippets, and calculates Security Score (0–100) and Code Quality Score (0–100).
5. **Remediation Phase**: `RemediationAgent` batches enriched findings to Ollama (`qwen3:8b`) with full source code context. Fallback triggers if Ollama is unreachable.
6. **PR Summary Phase**: `PRSummaryAgent` generates developer-facing PR review comments and action items matching severity metrics.
7. **Reporting Phase**: `PdfReportGenerator` and `HtmlReportGenerator` compile a single-page A4 PDF or responsive HTML document.
8. **Assistant Phase**: `ConversationalCodeAssistant` processes user follow-up questions using hybrid RAG context hierarchy.

---

## 3. Multi-Agent Architecture

The core review process is divided among specialized agents coordinated by the `Orchestrator`:

```
[ Orchestrator ]
    │
    ├──▶ [ CodeAnalysisAgent ] ────▶ AST Metrics & Code Smells
    ├──▶ [ SecurityAgent ]     ────▶ Vulnerabilities & Hardcoded Credentials
    ├──▶ [ RemediationAgent ]  ────▶ Code-Specific Fixes (Ollama / Fallback)
    └──▶ [ PRSummaryAgent ]    ────▶ Executive PR Summary (Ollama / Fallback)
```

---

## 4. Code Analysis Agent (`backend/agents/code_analysis_agent.py`)

- **Purpose**: Scans source code for maintainability issues, code smells, dead code, unused imports/variables, and complexity metrics.
- **Input**: `code` (str), `language` (str).
- **Processing**:
  - *Python*: Parses AST using `ast.parse()`. Calculates Cyclomatic Complexity, Halstead Volume, and Maintainability Index. Inspects AST nodes for unused imports, unused variable assignments, and unreachable code.
  - *Java*: Applies regex pattern matchers for class complexity, unused imports, empty catch blocks, and naming convention style rules.
- **Output**: List of code quality finding dictionaries containing `id`, `line`, `issue`, `severity`, `agent`, `explanation`, and `offending_code_snippet`.

---

## 5. Security Agent (`backend/agents/security_agent.py`)

- **Purpose**: Identifies security vulnerabilities, OWASP Top 10 flaws, and hardcoded secrets.
- **Input**: `code` (str), `language` (str).
- **Processing**:
  - *Python*: Walks AST nodes (`ast.NodeVisitor`). Scans for dynamic code execution (`eval()`, `exec()`), hardcoded credentials (`CWE-798`), weak hashing algorithms (`md5`, `sha1`), dangerous process execution (`subprocess.Popen(..., shell=True)`), and insecure temporary file creation.
  - *Java*: Scans regex rules for SQL injection (`Statement.executeQuery(concat)`), hardcoded passwords/keys, weak crypto (`Cipher.getInstance("DES")`), and unescaped HTML outputs (XSS).
- **Output**: List of security finding dictionaries containing `id`, `line`, `issue`, `severity`, `agent`, `explanation`, and `offending_code_snippet`.

---

## 6. Orchestrator (`backend/agents/orchestrator.py`)

- **Purpose**: Pipeline driver managing workflow sequence, score calculation, finding enrichment, and error handling.
- **Input**: `code` (str), optional `language` (str).
- **Processing**:
  - Runs language detection if unassigned.
  - Executes `CodeAnalysisAgent` and `SecurityAgent`.
  - Deduplicates overlapping line findings.
  - Calculates weighted Security Score: $100 - (25 \times \text{Critical} + 15 \times \text{High} + 8 \times \text{Medium} + 3 \times \text{Low})$.
  - Calculates weighted Code Quality Score: $100 - (10 \times \text{High} + 5 \times \text{Medium} + 2 \times \text{Low})$.
  - Invokes `RemediationAgent` and `PRSummaryAgent`.
  - Persists session review to `HistoryManager`.
- **Output**: Comprehensive dictionary containing `language`, `security_score`, `code_quality_score`, `findings`, `remediations`, `pr_summary`, and `report_ids`.

---

## 7. Remediation Agent (`backend/agents/remediation_agent.py`)

- **Purpose**: Generates accurate, code-specific fixes with real variable names and zero generic placeholders.
- **Input**: `findings` (list), `source_code` (str), `language` (str).
- **Processing**:
  - Formats enriched findings into a single batch JSON payload.
  - Passes full source code wrapped in `<submitted_source_code>` DATA tags to Ollama (`qwen3:8b`).
  - Instructs LLM to generate `problem`, `why_it_matters`, `what_to_change`, `improved_code`, `best_practice`, and `references`.
  - Triggers rule-based fallback if Ollama returns unparseable output or encounters a timeout error.
- **Output**: Array of remediation object dictionaries matching finding IDs.

---

## 8. PR Summary Agent (`backend/agents/pr_summary_agent.py`)

- **Purpose**: Creates developer-facing PR review comments, overall status badge, top risks, positive observations, and recommended next steps.
- **Input**: `findings` (list), `remediations` (list), `security_score` (float), `code_quality_score` (float).
- **Processing**:
  - Calculates exact severity counts (`Critical`, `High`, `Medium`, `Low`).
  - Constructs prompt instructing Ollama to generate qualitative PR summary while strictly respecting numerical count limits.
  - Activates rule-based fallback handler if LLM response fails or times out.
- **Output**: PR summary dictionary containing `overall_status`, `executive_summary`, `top_risks`, `code_quality_summary`, `security_summary`, `positive_observations`, `recommended_next_steps`, `estimated_remediation_effort`, and `developer_comment`.

---

## 9. RAG Architecture (`backend/rag/rag_engine.py`)

- **Purpose**: Augments AI responses with verified application security guidelines and PEP 8 standards.
- **Components**:
  - `SentenceTransformer` (`all-MiniLM-L6-v2`) for generating 384-dimensional vector embeddings.
  - ChromaDB persistent store for similarity search.
- **Ingestion**: Documents covering OWASP Top 10 2021, CWE definitions, and Python PEP 8 guidelines stored under `backend/documents/`.

---

## 10. ChromaDB & Vector Store (`backend/vector_db/vector_store.py`)

- Persistent local vector store located at `backend/vector_db/`.
- Performs cosine similarity queries to retrieve top-$k$ relevant security documentation chunks given user queries or finding descriptions.

---

## 11. Embeddings Engine

- Uses HuggingFace `sentence-transformers/all-MiniLM-L6-v2` running on CPU.
- Converts queries into dense float vectors for semantic retrieval without external API calls.

---

## 12. LLM Integration (`backend/llm/ollama_service.py`)

- Centralized service communicating with Ollama (`http://localhost:11434/v1/`).
- Employs OpenAI-compatible client interface (`OpenAI(base_url=..., api_key="ollama")`).
- Uses `extra_body={"think": False}` to streamline Qwen3 token generation.
- Enforces configurable token limits (`LLM_MAX_REVIEW_TOKENS=2000`, `LLM_MAX_SUMMARY_TOKENS=1000`, `LLM_MAX_CHAT_TOKENS=1000`).

---

## 13. Conversational Code Assistant (`backend/agents/conversational_code_assistant.py`)

- **Purpose**: Interactive assistant answering developer follow-up questions.
- **Context Priority Hierarchy**:
  1. Submitted Source Code (`<submitted_source_code>`)
  2. Active Review Findings
  3. Generated Remediations
  4. PR Summary Data
  5. RAG Retrieved Knowledge
  6. General LLM Knowledge
- **Features**:
  - Full code rewrite engine (`_build_complete_corrected_code()`).
  - Strict line inquiry matching (returns explicit "finding not found on line X" when query line does not match).
  - Beginner-friendly explanations.

---

## 14. FastAPI Backend (`backend/main.py`)

- Exposes RESTful API routes with CORS configuration allowing frontend origin `http://localhost:5173`.
- Validates request payloads with Pydantic models (`CodeSubmissionRequest`, `ChatRequest`, `ExplainFindingRequest`).
- Handles file downloads for generated PDF and HTML reports.

---

## 15. React Frontend (`frontend/`)

- Built with React 19, TypeScript, Vite, and Tailwind CSS.
- **Key Views**:
  - `CodeEditor`: Syntax-highlighted input editor with language auto-detect toggle.
  - `ResultsDashboard`: Visual security gauge, score breakdown, and finding list.
  - `CodeDiffViewer`: Side-by-side original vs refactored code view.
  - `PRSummaryView`: Pull request review card with status badges.
  - `ChatAssistant`: Interactive AI chat sidebar with RAG source citations.
  - `HistoryDrawer`: Access past review logs.

---

## 16. Report Generator (`backend/reporting/`)

- **`pdf_generator.py`**: Uses ReportLab to compile a single-page A4 executive PDF containing summary metrics, security gauge, score card, finding table, and remediation roadmap.
- **`html_generator.py`**: Generates a self-contained, responsive HTML report with modern CSS variables, visual cards, and print styling.

---

## 17. Error Handling

- **Syntax Errors**: Invalid code syntax yields structured HTTP 422 errors detailing line and column errors.
- **File Upload Errors**: Non-supported file extensions yield HTTP 400 bad request error responses.
- **Missing Resources**: Invalid report IDs yield HTTP 404 not found responses.

---

## 18. LLM Fallback Mechanism

When Ollama is offline or experiences a timeout:
1. `RemediationAgent` catches `RuntimeError` / `Exception` and executes `_generate_rule_based_remediations()`.
2. Rule-based engine matches finding issues against pre-defined secure code templates (e.g. replacing `eval()` with `ast.literal_eval()`).
3. `PRSummaryAgent` catches LLM errors and executes `_generate_rule_based_summary()`, generating accurate summaries based on actual severity counts.

---

## 19. RAG Fallback Engine (`backend/knowledge/assistant_knowledge.py`)

If ChromaDB vector retrieval fails or is empty, `AssistantKnowledgeEngine` queries static local knowledge tables covering OWASP Top 10, CWE definitions, and PEP 8 guidelines, guaranteeing zero runtime downtime for the assistant.

---

## 20. Security Configuration

- **Zero Cloud Transmission**: All LLM and embedding operations run locally.
- **Data Isolation**: User source code is treated as immutable DATA input.
- **Environment Exclusions**: `.env` and sensitive artifacts are excluded via `.gitignore`.
- **CORS Restricted**: Allowed origins explicitly defined for local web server interfaces.
