# SentinelAI — B.Tech Final Project Presentation Slides

---

## Slide 1: Title Slide
- **Project Title**: SentinelAI — AI Code Review & Security Analysis Agent
- **Subtitle**: An Autonomous Multi-Agent Platform for Local Code Quality & Security Auditing
- **Domain**: Artificial Intelligence / Application Security / Software Engineering
- **Presenter**: Major Project Final Defense

---

## Slide 2: Problem Statement
- **High False Positive Rates**: Legacy static analysis tools generate overwhelming lists of warnings without code-specific fix guidance.
- **Generic AI Advice**: Standard cloud chatbots hallucinate generic placeholders (`# Example code`) rather than addressing exact developer variable names.
- **Privacy & Compliance Risks**: Transmitting proprietary codebases to external cloud LLM APIs violates enterprise security policies.

---

## Slide 3: Project Objectives
- **100% Privacy-First**: Execute all AI inference locally via Ollama (`qwen3:8b`) with zero cloud data transmission.
- **Hybrid AST & Pattern Analysis**: Combine Python AST parsing and Java pattern matching for precise line-level bug detection.
- **Code-Specific Remediations**: Generate code replacements directly referencing submitted variables and logic.
- **Enterprise Reporting**: Produce single-page A4 PDF and responsive HTML security reports.

---

## Slide 4: Existing Systems & Limitations
- **SonarQube / Bandit / PMD**: Good at static detection, but lack automated code refactoring and natural language PR summaries.
- **General Cloud LLMs (ChatGPT / Claude)**: High-quality language generation, but prone to prompt injection, generic placeholders, and privacy compliance violations.

---

## Slide 5: Proposed Solution — SentinelAI
- **Multi-Agent Pipeline**: Specialized agents for AST analysis, security scanning, remediation generation, and PR summaries.
- **Hybrid RAG Grounding**: Combines ChromaDB vector database embeddings (OWASP Top 10, CWE) with source code context.
- **Deterministic Offline Fallbacks**: Rule-based fallback handlers guarantee 100% system uptime if the local LLM is unreachable.

---

## Slide 6: System Architecture
- **Frontend Layer**: React 19 + TypeScript + Vite + Tailwind CSS dashboard.
- **Backend Layer**: FastAPI (Python 3.14) REST API service.
- **AI Subsystem**: Ollama Qwen3:8b local LLM service.
- **RAG Subsystem**: ChromaDB vector store + `SentenceTransformer` embeddings (`all-MiniLM-L6-v2`).
- **Reporting Engine**: ReportLab single-page A4 PDF generator.

---

## Slide 7: Multi-Agent Architecture
- **`CodeAnalysisAgent`**: AST cyclomatic complexity, Halstead metrics, maintainability index, dead code, unused imports.
- **`SecurityAgent`**: OWASP Top 10, CWE-798 secrets, dynamic `eval()` execution, SQL injection, XSS.
- **`Orchestrator`**: Sequence manager, finding deduplication, and score calculation engine.
- **`RemediationAgent`**: Code-specific batch remediation generator.
- **`PRSummaryAgent`**: Qualitative PR review summary generator.
- **`ConversationalCodeAssistant`**: Hybrid RAG follow-up assistant.

---

## Slide 8: Code & Security Analysis Engine
- **AST Parsing (Python)**: `ast.NodeVisitor` inspection guarantees exact line-level accuracy.
- **Pattern Matching (Java)**: Regex pattern scanners for SQL injection, hardcoded credentials, and weak cryptography.
- **Dual Score Algorithm**:
  - Security Score ($0 - 100$) weighted by vulnerability severity.
  - Code Quality Score ($0 - 100$) weighted by code complexity and maintainability.

---

## Slide 9: LLM & Hybrid RAG Pipeline
- **Vector Database**: ChromaDB storing OWASP Top 10 and PEP 8 guidelines.
- **Context Priority Hierarchy**:
  1. Submitted Source Code (DATA only)
  2. Active Review Findings
  3. Generated Remediations
  4. RAG Knowledge
  5. General LLM Knowledge

---

## Slide 10: Remediation & PR Summary Generation
- **Zero-Placeholder Guarantee**: All code fixes directly incorporate original submitted function signatures and variables.
- **Severity Count Parity**: PR summaries strictly reflect calculated severity counts (`Critical`, `High`, `Medium`, `Low`).
- **Deterministic Rule-Based Fallbacks**: Activated automatically if Ollama experiences token or latency timeouts.

---

## Slide 11: Developer Portal & Interactive Interface
- **Modern Web Interface**: Built with React 19 and Tailwind CSS.
- **Key Features**:
  - Interactive code editor with auto-language detection.
  - Side-by-side original vs refactored code diff viewer.
  - Pull Request review summary card.
  - Embedded AI Assistant drawer with clickable RAG citations.

---

## Slide 12: Enterprise Report Generation
- **Single-Page A4 PDF**: Executive summary report built with ReportLab fitting strictly onto 1 page.
- **Responsive HTML**: Interactive web report featuring styled CSS metric badges and printable layout.
- **One-Click Export**: Downloads served directly from FastAPI REST endpoints.

---

## Slide 13: Testing & Results
- **Unit & Integration Suite**: 49 tests executed with 100% pass rate.
- **Performance**: Static analysis completes in $\sim 0.01\text{s}$; report generation in $\sim 0.15\text{s}$.
- **Accuracy**: Verified 100% detection rate across Python and Java test samples.

---

## Slide 14: System Demonstration
- **Sample 1**: Python Code Quality & Unused Variable Cleanup.
- **Sample 2**: Python Application Security (`eval()` injection & OWASP RAG response).
- **Sample 3**: Enterprise Java Security (SQL Injection & Single-Page PDF Report Export).

---

## Slide 15: Conclusion & Future Scope
- **Conclusion**: SentinelAI successfully delivers an autonomous, privacy-first, multi-agent AI code review platform.
- **Future Scope**:
  - Integrate ANTLR Java AST compiler for advanced Java analysis.
  - Develop GitHub Actions & GitLab CI/CD workflow plugins.
  - Expand multi-file project workspace analysis.
