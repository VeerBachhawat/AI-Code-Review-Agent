# SentinelAI — Final Project Report Outline

Recommended academic project report structure for Major Project / Thesis submission.

---

## Table of Contents

1. **Chapter 1: Introduction**
   - 1.1 Background & Context of Application Security
   - 1.2 Motivation for Automated AI Code Review
   - 1.3 Scope of the Project

2. **Chapter 2: Problem Statement**
   - 2.1 Limitations of Static Application Security Testing (SAST)
   - 2.2 Noise and False Positives in Legacy Analyzers
   - 2.3 Privacy Challenges with Cloud-Based LLMs

3. **Chapter 3: Project Objectives**
   - 3.1 Primary Technical Objectives
   - 3.2 Design Requirements & Performance Criteria

4. **Chapter 4: Literature Review & Existing Systems**
   - 4.1 Overview of Existing SAST Tools (SonarQube, Bandit, PMD)
   - 4.2 Overview of General-Purpose LLM Coding Assistants

5. **Chapter 5: Limitations of Existing Systems**
   - 5.1 Lack of Context in Rule-Based Tools
   - 5.2 Hallucination & Generic Placeholders in Cloud LLMs

6. **Chapter 6: Proposed System — SentinelAI**
   - 6.1 System Overview & Value Proposition
   - 6.2 Key Architectural Innovations

7. **Chapter 7: System Architecture**
   - 7.1 High-Level System Architecture Diagram
   - 7.2 Component Breakdown & Data Flow

8. **Chapter 8: Technologies Used**
   - 8.1 Backend Framework (FastAPI, Python 3.14)
   - 8.2 Frontend Framework (React 19, TypeScript, Vite, Tailwind CSS)
   - 8.3 Local LLM Inference Engine (Ollama Qwen3:8b)
   - 8.4 Vector Store & Embedding Engine (ChromaDB, SentenceTransformers)

9. **Chapter 9: Multi-Agent Architecture**
   - 9.1 Multi-Agent Orchestration Design
   - 9.2 Agent Specialization & Communication Rules

10. **Chapter 10: Static Code Analysis Module**
    - 10.1 Python Abstract Syntax Tree (AST) Inspection
    - 10.2 Software Quality Metrics (Cyclomatic Complexity, Halstead, Maintainability Index)
    - 10.3 Java Pattern Matcher Implementation

11. **Chapter 11: Security Analysis Module**
    - 11.1 OWASP Top 10 Mapping
    - 11.2 Hardcoded Credentials & Secret Scanning (CWE-798)
    - 11.3 Dynamic Code Evaluation & Injection Scans

12. **Chapter 12: LLM Integration Subsystem**
    - 12.1 Ollama REST API Integration
    - 12.2 Prompt Safety Directives & Untrusted Input Isolation

13. **Chapter 13: Retrieval-Augmented Generation (RAG) Pipeline**
    - 13.1 Vector Database Schema & Document Indexing
    - 13.2 Context Priority Hierarchy Implementation

14. **Chapter 14: Automated Remediation Engine**
    - 14.1 Code-Specific Fix Generation
    - 14.2 Deterministic Rule-Based Fallback Handler

15. **Chapter 15: PR Summary Generation Engine**
    - 15.1 Qualitative Assessment & Severity Metrics Alignment
    - 15.2 Rule-Based Fallback Summary Generator

16. **Chapter 16: Conversational Code Assistant**
    - 16.1 Assistant Intent Recognition & Context Assembly
    - 16.2 Full Code Rewrite Engine

17. **Chapter 17: User Interface & Developer Portal**
    - 17.1 Dashboard Design & Interactive Code Editor
    - 17.2 Side-by-Side Diff Viewer & Assistant Integration

18. **Chapter 18: Report Generation Engine**
    - 18.1 Single-Page A4 Executive PDF Architecture (ReportLab)
    - 18.2 Styled HTML Report Generator

19. **Chapter 19: Testing & Quality Assurance**
    - 19.1 Testing Strategy & Environment
    - 19.2 Unit, Integration, and Prompt Quality Test Suites

20. **Chapter 20: Results & Discussion**
    - 20.1 Vulnerability Detection Performance
    - 20.2 Remediation Grounding & Zero-Placeholder Verification
    - 20.3 Latency & System Performance Metrics

21. **Chapter 21: System Limitations**
    - 21.1 Single-File Scope
    - 21.2 Java Regex Limitations
    - 21.3 Local CPU Hardware Dependencies

22. **Chapter 22: Future Scope & Roadmap**
    - 22.1 ANTLR Java AST Compiler Integration
    - 22.2 CI/CD Pipeline Plugins (GitHub Actions)

23. **Chapter 23: Conclusion**
    - 23.1 Summary of Contributions
    - 23.2 Final Remarks

24. **Chapter 24: References**
    - Academic papers, OWASP documentation, Python AST specifications, and framework documentation.
