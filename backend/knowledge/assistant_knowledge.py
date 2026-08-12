"""
SentinelAI Deterministic & Vector RAG Knowledge Engine
======================================================
Combines local ChromaDB vector store retrieval with deterministic groundings in:
1. Indexed Security PDFs & Quick Reference Guides
2. OWASP Top 10 Security Standards (2021)
3. PEP 8 Guidelines & Python Style Rules
4. AST Analysis Rules & Code Quality Metrics
5. SentinelAI Security Agent Detection Rules
6. Semantic Developer/Security Domain Relevance Evaluation
"""

import os
import re
import time
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("ConversationalCodeAssistant")
logger.setLevel(logging.INFO)


class AssistantKnowledgeEngine:
    """
    RAG Knowledge Engine for SentinelAI AI Assistant.
    Provides vector DB (ChromaDB) document retrieval, deterministic local rules,
    and semantic domain classification.
    """

    def __init__(self) -> None:
        # Cache knowledge once in memory at initialization
        self.owasp_knowledge = self._build_owasp_knowledge()
        self.pep8_knowledge = self._build_pep8_knowledge()
        self.ast_knowledge = self._build_ast_knowledge()
        self.security_rules_knowledge = self._build_security_rules_knowledge()
        self.sentinelai_knowledge = self._build_sentinelai_knowledge()

        # Initialize ChromaDB vector DB if available
        self.embeddings_model = None
        self._domain_concept_emb = None
        self.vector_db = self._init_vector_db()

    def _init_vector_db(self):
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
            from langchain_community.vectorstores import Chroma

            possible_paths = [
                os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vector_db")),
                os.path.abspath("backend/vector_db"),
                os.path.abspath("vector_db")
            ]
            vec_dir = next((p for p in possible_paths if os.path.exists(p)), None)
            if vec_dir:
                self.embeddings_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
                vdb = Chroma(persist_directory=vec_dir, embedding_function=self.embeddings_model)
                logger.info(f"[RAG] Successfully loaded ChromaDB vector store from {vec_dir}")
                return vdb
            else:
                logger.warning("[RAG] Vector database directory not found.")
                return None
        except Exception as e:
            logger.warning(f"[RAG] ChromaDB vector DB initialization skipped/failed: {e}")
            return None

    def _query_vector_db(self, question: str) -> Optional[Dict[str, Any]]:
        if not self.vector_db:
            return None

        try:
            results = self.vector_db.similarity_search_with_relevance_scores(question, k=3)
            # Filter for positive/meaningful relevance scores (score >= 0.05)
            valid_results = [(doc, score) for doc, score in results if score is not None and score >= 0.05]

            if not valid_results:
                return None

            context_snippets = []
            sources = []
            seen_sources = set()

            for doc, score in valid_results:
                raw_source = doc.metadata.get("source", "Security Guidelines")
                source_name = os.path.basename(raw_source)
                if source_name.endswith(".pdf.pdf"):
                    source_name = source_name[:-4]

                context_snippets.append(doc.page_content.strip())
                norm_score = round(max(0.0, min(1.0, float(score))), 2)

                if source_name not in seen_sources:
                    seen_sources.add(source_name)
                    sources.append({"document": source_name, "score": norm_score})

            retrieved_text = "\n\n---\n\n".join(context_snippets)
            related_topics = self._derive_related_topics(question)

            return {
                "relevant_context_found": True,
                "category": "RAG_RETRIEVAL",
                "request_code_needed": False,
                "retrieved_context": retrieved_text,
                "sources": sources,
                "related_topics": related_topics,
                "question": question
            }
        except Exception as e:
            logger.warning(f"[RAG] ChromaDB retrieval error: {e}")
            return None

    def _is_semantic_domain_relevant(self, question: str) -> bool:
        """
        Determines whether a question is within the developer/security domain
        without using a brittle hardcoded keyword whitelist.
        Uses vector embedding similarity against core developer/security concepts.
        """
        q_clean = (question or "").strip().lower()
        if not q_clean:
            return False

        if self.embeddings_model:
            try:
                import numpy as np
                domain_concept = (
                    "software engineering cybersecurity application security code review "
                    "programming languages databases python java sql vulnerabilities web security "
                    "code quality maintainability refactoring bugs errors software testing"
                )
                if self._domain_concept_emb is None:
                    self._domain_concept_emb = self.embeddings_model.embed_query(domain_concept)

                q_emb = self.embeddings_model.embed_query(q_clean)
                norm_domain = np.linalg.norm(self._domain_concept_emb)
                norm_q = np.linalg.norm(q_emb)
                if norm_domain > 0 and norm_q > 0:
                    similarity = float(np.dot(self._domain_concept_emb, q_emb) / (norm_domain * norm_q))
                    # Developer/security queries score >= 0.06; generic out-of-domain queries score < 0.05
                    return similarity >= 0.06
            except Exception as exc:
                logger.warning(f"[DOMAIN] Embedding similarity check failed ({exc}), falling back to pattern match.")

        domain_patterns = [
            r"\b(code|coding|software|developer|programming|function|variable|class|method|import|syntax|bug|error|refactor|test)\b",
            r"\b(security|vulnerability|attack|exploit|injection|xss|ssrf|csrf|rce|auth|token|key|password|crypto|encrypt|sanitize)\b",
            r"\b(sql|database|query|table|select|insert|update|delete|join|where|orm|prepared|parameterized)\b",
            r"\b(owasp|cwe|pep8|ast|cyclomatic|complexity|maintainability|clean|smell|finding|review|pr|pull request)\b",
            r"\b(python|java|javascript|typescript|c\+\+|c#|go|rust|php|ruby|html|css)\b"
        ]
        return any(re.search(pat, q_clean) for pat in domain_patterns)

    def _derive_related_topics(self, question: str) -> List[str]:
        q_lower = (question or "").lower()
        if "sql" in q_lower or "database" in q_lower or "query" in q_lower:
            return ["SQL Injection", "Parameterized Queries", "Database Input Validation"]
        elif "eval" in q_lower or "exec" in q_lower or "command" in q_lower:
            return ["Code Execution Risk", "AST Input Sanitization", "Safe Alternatives"]
        elif "pep" in q_lower or "style" in q_lower or "format" in q_lower:
            return ["PEP 8 Naming Conventions", "Python Formatting Rules", "Clean Code Best Practices"]
        elif "ast" in q_lower or "complexity" in q_lower or "metric" in q_lower:
            return ["Cyclomatic Complexity", "Maintainability Index", "AST Rule Engine"]
        elif "password" in q_lower or "credential" in q_lower or "secret" in q_lower or "hardcoded" in q_lower:
            return ["Secrets Management", "Environment Variables", "Hardcoded Credentials Risk"]
        elif "finding" in q_lower or "critical" in q_lower or "issue" in q_lower:
            return ["Finding Triaging", "Severity Classification", "Security Remediation"]
        else:
            return ["Secure Coding Best Practices", "OWASP Standards", "Code Analysis Rules"]

    # --------------------------------------------------------------------------
    # In-Memory Knowledge Base Builders
    # --------------------------------------------------------------------------

    def _build_owasp_knowledge(self) -> Dict[str, Dict[str, Any]]:
        return {
            "sqli": {
                "category": "SECURITY",
                "topic": "OWASP A03:2021 - SQL Injection",
                "patterns": [
                    r"\bsql injection\b", r"\bsqli\b", r"\ba03\b", r"database injection",
                    r"prevent sql", r"explain sql injection", r"what is sql injection"
                ],
                "answer": (
                    "### OWASP A03:2021 — SQL Injection (SQLi)\n\n"
                    "**What is SQL Injection?**\n"
                    "SQL Injection occurs when untrusted user input is directly concatenated or formatted into a database query string instead of being passed as a parameterized value. Attackers can manipulate query logic to bypass authentication, extract confidential data, alter database contents, or gain administrative access.\n\n"
                    "**Vulnerable Example:**\n"
                    "```python\n"
                    "# DANGEROUS: String concatenation in SQL query\n"
                    "cursor.execute(\"SELECT * FROM users WHERE username = '\" + user_input + \"'\")\n"
                    "```\n\n"
                    "**How to Prevent SQL Injection:**\n"
                    "1. **Use Parameterized Queries (Prepared Statements):**\n"
                    "```python\n"
                    "# SECURE: Using parameterized query placeholders (%s or ?)\n"
                    "cursor.execute(\"SELECT * FROM users WHERE username = %s\", (user_input,))\n"
                    "```\n"
                    "2. **Use an Object-Relational Mapper (ORM):** Libraries like SQLAlchemy or Django ORM automatically parameterize queries.\n"
                    "3. **Enforce Least Privilege:** Database accounts should only have permissions required for their task."
                ),
                "sources": [
                    {"document": "OWASP Top 10: A03:2021 - Injection", "score": 0.98}
                ],
                "related_topics": [
                    "Parameterized Queries in Python DB-API 2.0",
                    "Preventing SQL Injection with SQLAlchemy",
                    "CWE-89: Improper Neutralization of Special Elements"
                ]
            },
            "xss": {
                "category": "SECURITY",
                "topic": "OWASP A03:2021 - Cross-Site Scripting (XSS)",
                "patterns": [
                    r"\bxss\b", r"cross-site scripting", r"reflected xss", r"stored xss",
                    r"prevent xss", r"explain xss"
                ],
                "answer": (
                    "### OWASP A03:2021 — Cross-Site Scripting (XSS)\n\n"
                    "**What is XSS?**\n"
                    "Cross-Site Scripting occurs when an application includes untrusted data in a web page without proper validation or escaping, allowing attackers to execute malicious scripts in victims' browsers.\n\n"
                    "**Remediation:** Context-aware output encoding, Content Security Policy (CSP), and HTTP-only cookies."
                ),
                "sources": [{"document": "OWASP Top 10: A03:2021 - Injection", "score": 0.97}],
                "related_topics": ["Content Security Policy (CSP)", "Context-Aware HTML Escaping"]
            },
            "eval_rce": {
                "category": "SECURITY",
                "topic": "Code Injection & Arbitrary Code Execution (eval/exec)",
                "patterns": [
                    r"\beval\(\)\b", r"\bexec\(\)\b", r"why is eval dangerous", r"eval vulnerability",
                    r"dangerous eval", r"arbitrary code execution"
                ],
                "answer": (
                    "### Code Injection — Dangerous `eval()` & `exec()` Usage\n\n"
                    "**Why is `eval()` Dangerous?**\n"
                    "`eval()` evaluates an arbitrary string expression as live Python code. Passing untrusted user input into `eval()` allows attackers to execute arbitrary system commands, read sensitive files, or compromise the host environment (Remote Code Execution).\n\n"
                    "**Remediation:**\n"
                    "- Use `ast.literal_eval()` for safely parsing literal Python data structures (dicts, lists, numbers, strings).\n"
                    "- Use `json.loads()` for parsing structured JSON data."
                ),
                "sources": [{"document": "PEP 8 & Python Security Guidelines", "score": 0.98}],
                "related_topics": ["Safe Parsing with ast.literal_eval()", "Python RCE Vectors"]
            },
            "hardcoded_credentials": {
                "category": "SECURITY",
                "topic": "OWASP A07:2021 - Hardcoded Credentials & Secrets",
                "patterns": [
                    r"hardcoded password", r"hardcoded credential", r"hardcoded secret",
                    r"api key in code", r"fix hardcoded"
                ],
                "answer": (
                    "### OWASP A07:2021 — Hardcoded Credentials & Secrets Management\n\n"
                    "**Why is Hardcoding Secrets Dangerous?**\n"
                    "Embedding plain-text passwords, secret keys, or tokens in source code exposes credentials to anyone with read access to the repository, leading to unauthorized access and supply-chain compromise.\n\n"
                    "**Remediation:**\n"
                    "Store secrets in environment variables or external secret vaults (`os.getenv('DB_PASSWORD')`)."
                ),
                "sources": [{"document": "OWASP Top 10: A07:2021 - Identification & Auth", "score": 0.97}],
                "related_topics": ["Secrets Management with python-dotenv", "Environment Variable Injection"]
            },
            "deserialization": {
                "category": "SECURITY",
                "topic": "OWASP A08:2021 - Insecure Deserialization",
                "patterns": [r"insecure deserialization", r"\ba08\b", r"\bpickle\b", r"\bmarshal\b", r"yaml\.load"],
                "answer": (
                    "### OWASP A08:2021 — Insecure Deserialization\n\n"
                    "**What is Insecure Deserialization?**\n"
                    "Insecure deserialization occurs when untrusted data is parsed back into living memory objects. In Python, modules like `pickle` or `marshal` execute arbitrary Python bytecode during deserialization, causing Remote Code Execution (RCE).\n\n"
                    "**Remediation:**\n"
                    "Use safe JSON serialization or `yaml.safe_load()`."
                ),
                "sources": [{"document": "OWASP Top 10: A08:2021 - Software Integrity", "score": 0.97}],
                "related_topics": ["Python pickle RCE Risk", "Safe YAML Parsing"]
            },
            "ssrf": {
                "category": "SECURITY",
                "topic": "OWASP A10:2021 - Server-Side Request Forgery (SSRF)",
                "patterns": [r"\bssrf\b", r"server-side request forgery", r"\ba10\b"],
                "answer": (
                    "### OWASP A10:2021 — Server-Side Request Forgery (SSRF)\n\n"
                    "**What is SSRF?**\n"
                    "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL."
                ),
                "sources": [{"document": "OWASP Top 10: A10:2021 - SSRF", "score": 0.96}],
                "related_topics": ["URL Validation & Host Allowlisting"]
            },
            "owasp_top_10": {
                "category": "SECURITY",
                "topic": "OWASP Top 10 Overview",
                "patterns": [r"\bowasp\b", r"\bowasp top 10\b"],
                "answer": (
                    "### OWASP Top 10 Overview\n\n"
                    "The OWASP Top 10 is a standard awareness document for developers and web application security representing the broad consensus on the most critical security risks to web applications:\n"
                    "1. A01: Broken Access Control\n"
                    "2. A02: Cryptographic Failures\n"
                    "3. A03: Injection (SQLi, Command Injection)\n"
                    "4. A04: Insecure Design\n"
                    "5. A05: Security Misconfiguration\n"
                    "6. A06: Vulnerable and Outdated Components\n"
                    "7. A07: Identification and Authentication Failures\n"
                    "8. A08: Software and Data Integrity Failures\n"
                    "9. A09: Security Logging and Monitoring Failures\n"
                    "10. A10: Server-Side Request Forgery (SSRF)"
                ),
                "sources": [{"document": "OWASP Top 10 Standard", "score": 0.99}],
                "related_topics": ["OWASP Compliance Mapping in SentinelAI"]
            }
        }

    def _build_pep8_knowledge(self) -> Dict[str, Dict[str, Any]]:
        return {
            "pep8_overview": {
                "category": "PEP8",
                "topic": "PEP 8 — Style Guide for Python Code",
                "patterns": [r"\bpep\s*8\b", r"\bpep8\b", r"python style guide", r"python formatting rules", r"python style guidelines"],
                "answer": (
                    "### PEP 8 — Style Guide for Python Code\n\n"
                    "**What is PEP 8?**\n"
                    "PEP 8 is the official Python Enhancement Proposal that defines the standard coding style for Python code. Written by Guido van Rossum, Barry Warsaw, and Nick Coghlan, its primary goal is to maximize code readability and maintain consistency across codebases.\n\n"
                    "**Core PEP 8 Principles:**\n"
                    "1. **Indentation:** 4 spaces per level (never mix tabs and spaces).\n"
                    "2. **Line Length:** Maximum 79 characters for code.\n"
                    "3. **Naming Conventions:** `snake_case` for functions/variables, `CapWords` for classes, `UPPER_CASE` for constants.\n"
                    "4. **Imports:** Group standard library, 3rd party, and local imports separately at the top of the file.\n"
                    "5. **Whitespace:** Single spaces around operators (`=`, `+`), no trailing whitespace."
                ),
                "sources": [{"document": "PEP 8 Style Guide for Python Code", "score": 0.99}],
                "related_topics": ["PEP 8 Naming Conventions Guide", "Python Indentation & Line Length Rules"]
            },
            "naming": {
                "category": "PEP8",
                "topic": "PEP 8 — Naming Conventions",
                "patterns": [
                    r"naming convention", r"variable name", r"function name", r"class name",
                    r"snake_case", r"pascalcase", r"camelcase", r"how should python functions be named"
                ],
                "answer": (
                    "### PEP 8 — Naming Conventions Guide\n\n"
                    "PEP 8 establishes clear rules for naming identifiers in Python:\n\n"
                    "| Type | Convention | Example |\n"
                    "| :--- | :--- | :--- |\n"
                    "| **Variables & Functions** | `snake_case` | `total_count`, `calculate_score()` |\n"
                    "| **Classes** | `CapWords` / `PascalCase` | `SecurityAgent`, `CodeAnalyzer` |\n"
                    "| **Constants** | `UPPER_CASE_WITH_UNDERSCORES` | `MAX_RETRY_COUNT`, `DEFAULT_TIMEOUT` |\n"
                    "| **Protected Members** | Single leading underscore | `_internal_method()` |\n\n"
                    "Avoid non-descriptive single-letter variable names (`a`, `x`, `temp`) except for standard loop indices (`i`, `j`)."
                ),
                "sources": [{"document": "PEP 8 Naming Conventions Standard", "score": 0.98}],
                "related_topics": ["Single-Letter Variable Name Warning", "PEP 8 Constant Naming Rules"]
            }
        }

    def _build_ast_knowledge(self) -> Dict[str, Dict[str, Any]]:
        return {
            "ast_overview": {
                "category": "AST",
                "topic": "AST (Abstract Syntax Tree) Analysis",
                "patterns": [r"what is ast analysis", r"abstract syntax tree", r"how ast works", r"ast parser", r"\bast analysis\b"],
                "answer": (
                    "### AST (Abstract Syntax Tree) Analysis in SentinelAI\n\n"
                    "**What is AST Analysis?**\n"
                    "An Abstract Syntax Tree (AST) is a structural tree representation of source code generated by Python's native `ast` module. Each node represents a syntactic construct in the source code (functions, variables, loops, calls).\n\n"
                    "**Why SentinelAI Uses AST:**\n"
                    "- **Static Safety:** Analyzes code structure without executing it.\n"
                    "- **Precision:** Eliminates false positives common in string regex matching.\n"
                    "- **Metrics:** Calculates Cyclomatic Complexity, method lengths, and nesting depth."
                ),
                "sources": [{"document": "Python ast Module Documentation", "score": 0.98}],
                "related_topics": ["Code Smells Detected by SentinelAI AST Engine", "McCabe Cyclomatic Complexity"]
            },
            "complexity": {
                "category": "CODE_ANALYSIS",
                "topic": "AST Metric — Cyclomatic Complexity",
                "patterns": [r"cyclomatic complexity", r"complexity warning", r"mccabe", r"decision branches", r"maintainability index", r"maintainability", r"function complexity", r"explain cyclomatic complexity"],
                "answer": (
                    "### Cyclomatic Complexity & Maintainability Metric\n\n"
                    "**What is Cyclomatic Complexity?**\n"
                    "Cyclomatic Complexity measures the number of linearly independent decision paths through a function's code (`if`, `for`, `while`, `except`).\n\n"
                    "**Thresholds:**\n"
                    "- **1 to 5:** Low complexity.\n"
                    "- **6 to 10:** Moderate complexity.\n"
                    "- **> 10:** High Complexity Warning (refactoring recommended)."
                ),
                "sources": [{"document": "SentinelAI AST Code Analysis Engine", "score": 0.98}],
                "related_topics": ["Maintainability Index Metric Formula", "Refactoring High Complexity Functions"]
            }
        }

    def _build_security_rules_knowledge(self) -> Dict[str, Dict[str, Any]]:
        return {
            "sqli_rule": {
                "category": "SECURITY",
                "topic": "SentinelAI Rule — SQL Injection Detection",
                "patterns": [r"rule sqli", r"sentinelai sql rule"],
                "answer": "SentinelAI inspects AST string formatting nodes and string concatenations inside database execution calls to flag SQL injection risks.",
                "sources": [{"document": "SentinelAI Security Rules Specification", "score": 0.96}],
                "related_topics": ["Parameterized Query Enforcement"]
            }
        }

    def _build_sentinelai_knowledge(self) -> Dict[str, Dict[str, Any]]:
        return {
            "about": {
                "category": "SENTINELAI",
                "topic": "SentinelAI Overview",
                "patterns": [r"what is sentinelai", r"about sentinelai"],
                "answer": "SentinelAI is an AI-powered code review and application security analysis platform.",
                "sources": [{"document": "SentinelAI System Guide", "score": 0.99}],
                "related_topics": ["Security Analysis", "Code Quality Analysis"]
            }
        }

    # --------------------------------------------------------------------------
    # Main RAG Knowledge Engine Retrieval & Query Handlers
    # --------------------------------------------------------------------------

    def retrieve(
        self,
        question: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        code: Optional[str] = None,
        remediations: Optional[List[Dict[str, Any]]] = None,
        history: Optional[List[Dict[str, Any]]] = None,
        pr_summary: Optional[Dict[str, Any]] = None,
        code_quality_score: Optional[int] = None,
        security_score: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Retrieves relevant local SentinelAI knowledge context (RAG ChromaDB, OWASP, PEP8, AST, Rules, Findings, Remediation)
        for RAG grounding without generating the final conversational LLM answer.
        """
        q_clean = (question or "").strip()
        q_lower = q_clean.lower()

        # Helper function to evaluate retrieval for a single query string
        def _match_single_query(sq: str) -> Optional[Dict[str, Any]]:
            # 1. Remediation Intent Matching
            remediation_match = self._match_remediation_intent(sq, findings, code, remediations)
            if remediation_match:
                category_type, res_dict = remediation_match
                if category_type == "REQUEST_CODE":
                    return {
                        "relevant_context_found": True,
                        "category": "REQUEST_CODE",
                        "request_code_needed": True,
                        "retrieved_context": "User requested remediation or secure version, but no source code or code-review finding was provided.",
                        "sources": res_dict.get("sources", []),
                        "related_topics": res_dict.get("related_topics", ["Security Remediation", "Code Analysis"]),
                        "question": q_clean
                    }
                else:
                    return {
                        "relevant_context_found": True,
                        "category": "REMEDIATION",
                        "request_code_needed": False,
                        "retrieved_context": res_dict.get("answer", ""),
                        "sources": res_dict.get("sources", []),
                        "related_topics": res_dict.get("related_topics", ["Security Remediation", "OWASP Best Practices"]),
                        "question": q_clean
                    }

            # 2. Active Finding Context Matching
            finding_match = self._match_active_finding_context(sq, findings, code, remediations)
            if finding_match:
                return {
                    "relevant_context_found": True,
                    "category": "CURRENT_FINDING",
                    "request_code_needed": False,
                    "retrieved_context": finding_match.get("answer", ""),
                    "sources": finding_match.get("sources", []),
                    "related_topics": finding_match.get("related_topics", ["Finding Analysis"]),
                    "question": q_clean
                }

            # 3. Vector Database (ChromaDB) Retrieval
            vector_res = self._query_vector_db(sq)
            if vector_res:
                return vector_res

            # 4. Domain Knowledge Base Matching (OWASP, PEP8, AST, SecurityAgent, SentinelAI)
            knowledge_sources = [
                ("OWASP Standard", self.owasp_knowledge),
                ("PEP 8 Standard", self.pep8_knowledge),
                ("AST Rules", self.ast_knowledge),
                ("Security Rules", self.security_rules_knowledge),
                ("SentinelAI Rules", self.sentinelai_knowledge)
            ]

            for source_name, k_map in knowledge_sources:
                for item in k_map.values():
                    patterns = item.get("patterns", [])
                    if any(re.search(pat, sq) for pat in patterns):
                        category = item.get("category", "SECURITY")
                        retrieved_text = f"Topic: {item.get('topic', '')}\nContent:\n{item.get('answer', '')}"
                        return {
                            "relevant_context_found": True,
                            "category": category,
                            "request_code_needed": False,
                            "retrieved_context": retrieved_text,
                            "sources": item.get("sources", [{"document": source_name, "score": 0.95}]),
                            "related_topics": item.get("related_topics", []),
                            "question": q_clean
                        }
            return None

        # First try matching directly on current question
        direct_result = _match_single_query(q_lower)
        if direct_result:
            return direct_result

        # If findings exist and user asks about finding context
        if findings and any(k in q_lower for k in ["why", "explain", "finding", "marked", "high", "critical", "medium", "low", "issue"]):
            finding = findings[0]
            context_text = (
                f"Finding Issue: {finding.get('issue', 'Code Finding')}\n"
                f"Severity: {finding.get('severity', 'High')}\n"
                f"Line Number: {finding.get('line', 1)}\n"
                f"Explanation: {finding.get('explanation', '')}\n"
                f"Recommendation: {finding.get('recommendation', '')}"
            )
            if code:
                context_text += f"\nOffending Code Context:\n{code}"
            return {
                "relevant_context_found": True,
                "category": "CURRENT_FINDING",
                "request_code_needed": False,
                "retrieved_context": context_text,
                "sources": [],
                "related_topics": ["SentinelAI Finding Analysis", "OWASP Security Best Practices"],
                "question": q_clean
            }

        # If direct match yielded no result, check if question is a follow-up using history
        followup_indicators = ["it", "this", "that", "why", "how", "explain", "dangerous", "risk", "fix"]
        if history and isinstance(history, list) and any(word in q_lower.split() for word in followup_indicators):
            past_user_msgs = [
                h.get("content", "") for h in history
                if isinstance(h, dict) and h.get("role") == "user" and h.get("content")
            ]
            if past_user_msgs:
                combined_sq = f"{past_user_msgs[-1].lower()} {q_lower}"
                history_result = _match_single_query(combined_sq)
                if history_result:
                    return history_result

        # 5. Semantic Domain Relevance Check for General In-Domain Questions
        if self._is_semantic_domain_relevant(q_lower):
            return {
                "relevant_context_found": True,
                "category": "GENERAL_DOMAIN",
                "request_code_needed": False,
                "retrieved_context": f"User asked a developer/security domain question: {q_clean}",
                "sources": [],  # Empty list for general domain questions without explicit vector docs
                "related_topics": self._derive_related_topics(q_lower),
                "question": q_clean
            }

        # 6. No Relevant Context Found (Out-of-Domain Question)
        return {
            "relevant_context_found": False,
            "category": "UNSUPPORTED",
            "request_code_needed": False,
            "retrieved_context": "",
            "sources": [],  # Empty list! Zero fake documents.
            "related_topics": [],  # Empty list! No unrelated topics.
            "question": q_clean
        }

    def query(
        self,
        question: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        code: Optional[str] = None,
        remediations: Optional[List[Dict[str, Any]]] = None,
        pr_summary: Optional[Dict[str, Any]] = None,
        code_quality_score: Optional[int] = None,
        security_score: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Alias/Legacy Query handler calling retrieve() for backward compatibility.
        """
        retrieved = self.retrieve(
            question=question,
            findings=findings,
            code=code,
            remediations=remediations,
            pr_summary=pr_summary,
            code_quality_score=code_quality_score,
            security_score=security_score
        )
        if not retrieved.get("relevant_context_found"):
            return {
                "question": question,
                "answer": "I can only answer questions related to SentinelAI's secure coding knowledge, including OWASP Top 10, PEP 8, AST analysis, security vulnerabilities, code analysis, and remediation rules.",
                "related_topics": [],
                "source": "local_knowledge",
                "sources": [],
                "generated_by": "local_knowledge_engine",
                "model": "local_knowledge_engine"
            }
        return {
            "question": question,
            "answer": retrieved.get("retrieved_context", ""),
            "source": "local_knowledge",
            "sources": retrieved.get("sources", []),
            "related_topics": retrieved.get("related_topics", []),
            "generated_by": "local_knowledge_engine",
            "model": "local_knowledge_engine"
        }

    def _match_remediation_intent(
        self,
        q_lower: str,
        findings: Optional[List[Dict[str, Any]]],
        code: Optional[str],
        remediations: Optional[List[Dict[str, Any]]]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        remediation_triggers = [
            r"secure version",
            r"how do i fix",
            r"how to fix",
            r"fix this",
            r"fix vulnerability",
            r"corrected code",
            r"give me secure code",
            r"how can i remediate",
            r"how should i fix",
            r"corrected version",
            r"remediate this",
            r"fix hardcoded",
            r"fix password",
            r"fix sql",
            r"show me corrected",
            r"show me secure"
        ]

        if not any(re.search(trig, q_lower) for trig in remediation_triggers):
            return None

        has_code = bool(code and code.strip())
        has_findings = bool(findings and len(findings) > 0)
        has_remediations = bool(remediations and len(remediations) > 0)

        if not has_code and not has_findings and not has_remediations:
            return ("REQUEST_CODE", {
                "question": q_lower,
                "answer": "Please provide the code you want me to secure, or select a code-review finding. I can then apply SentinelAI's existing security and remediation rules.",
                "related_topics": [
                    "Security Remediation",
                    "Code Analysis",
                    "OWASP Top 10"
                ],
                "source": "local_knowledge",
                "sources": [],
                "generated_by": "local_knowledge_engine",
                "model": "local_knowledge_engine"
            })

        matched_finding = findings[0] if has_findings else None
        matched_remediation = remediations[0] if has_remediations else None

        if matched_remediation or matched_finding:
            issue = (matched_remediation or matched_finding).get("issue", "Security Vulnerability")
            severity = (matched_remediation or matched_finding).get("severity", "High")
            explanation = matched_finding.get("explanation", "") if matched_finding else matched_remediation.get("why_it_is_problematic", "")
            rec_fix = matched_remediation.get("recommended_fix", "") if matched_remediation else matched_finding.get("recommendation", "Refactor code to parameterize user inputs and remove hardcoded values.")
            code_example = matched_remediation.get("corrected_code_example", "") if matched_remediation else matched_finding.get("secure_code", "")

            answer_md = (
                f"### Security Remediation: {issue}\n\n"
                f"**Severity Level:** `{severity}`\n\n"
                f"**Vulnerability Analysis:**\n"
                f"{explanation or 'SentinelAI static analysis detected a security defect in the provided code.'}\n\n"
                f"**Recommended Fix:**\n"
                f"{rec_fix}\n\n"
            )
            if code_example:
                answer_md += f"**Secure Corrected Code Example:**\n```python\n{code_example}\n```"

            return ("REMEDIATION", {
                "question": q_lower,
                "answer": answer_md,
                "related_topics": [
                    "Security Remediation",
                    "OWASP Best Practices",
                    f"Refactoring {issue}"
                ],
                "source": "OWASP/SecurityAgent/local_rules",
                "sources": [],
                "generated_by": "local_knowledge_engine",
                "model": "local_knowledge_engine"
            })

        code_str = code or ""
        answer_md = "### Security Remediation & Code Securing\n\n"
        rec_topics = ["Security Remediation", "OWASP Top 10"]

        if "eval(" in code_str or "exec(" in code_str:
            answer_md += (
                "**Detected Issue:** Dynamic Code Execution via `eval()` or `exec()`.\n\n"
                "**Secure Code Fix:** Replace `eval()` with `ast.literal_eval()` for safe expression parsing:\n"
                "```python\nimport ast\n# SECURE: Safe parsing of literal data structures\nresult = ast.literal_eval(user_input)\n```"
            )
        elif "password" in code_str.lower() or "secret" in code_str.lower() or "api_key" in code_str.lower():
            answer_md += (
                "**Detected Issue:** Hardcoded Password or Secret Credential.\n\n"
                "**Secure Code Fix:** Use environment variables to inject credentials securely:\n"
                "```python\nimport os\n# SECURE: Load secret from environment\napi_key = os.getenv(\"API_KEY\")\n```"
            )
        elif "select" in code_str.lower() or "where" in code_str.lower():
            answer_md += (
                "**Detected Issue:** Potential SQL Query String Formatting.\n\n"
                "**Secure Code Fix:** Use parameterized query placeholders instead of string formatting:\n"
                "```python\n# SECURE: Parameterized query\ncursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))\n```"
            )
        else:
            answer_md += (
                "**SentinelAI Remediation Guidance:**\n"
                "To secure your code, follow these standard SentinelAI principles:\n"
                "1. **Input Validation:** Never concatenate raw inputs into database queries or shell commands.\n"
                "2. **Secrets Management:** Extract all credentials into environment variables (`os.getenv`).\n"
                "3. **Safe APIs:** Replace dynamic execution (`eval`) with static parsing (`ast.literal_eval`).\n\n"
                "**Refactored Secure Code Example:**\n"
                "```python\nimport os\nimport ast\n\ndef process_secure_request(user_data: str):\n    # Validate and safely parse inputs\n    parsed_data = ast.literal_eval(user_data)\n    db_key = os.getenv('DB_KEY')\n    return parsed_data\n```"
            )

        return ("REMEDIATION", {
            "question": q_lower,
            "answer": answer_md,
            "related_topics": rec_topics,
            "source": "OWASP/SecurityAgent/local_rules",
            "sources": [],
            "generated_by": "local_knowledge_engine",
            "model": "local_knowledge_engine"
        })

    def _match_active_finding_context(
        self,
        q_lower: str,
        findings: Optional[List[Dict[str, Any]]],
        code: Optional[str],
        remediations: Optional[List[Dict[str, Any]]]
    ) -> Optional[Dict[str, Any]]:
        if not findings and not code and not remediations:
            return None

        explicit_triggers = [
            r"\bline\s*\d+\b",
            r"why was line",
            r"why was this issue",
            r"explain this finding",
            r"why was this flagged",
            r"why was this finding marked",
            r"why was this finding marked high",
            r"why was this finding marked critical",
            r"secure version of line"
        ]

        if not any(re.search(trig, q_lower) for trig in explicit_triggers):
            return None

        line_match = re.search(r"line\s*(\d+)", q_lower)
        target_line = int(line_match.group(1)) if line_match else None

        matched_finding = None
        matched_remediation = None

        if target_line:
            if findings:
                for f in findings:
                    if f.get("line") == target_line:
                        matched_finding = f
                        break
            if remediations:
                for r in remediations:
                    if r.get("line") == target_line:
                        matched_remediation = r
                        break

            if not matched_finding and not matched_remediation:
                return {
                    "question": q_lower,
                    "answer": f"I could not find a matching finding on line {target_line}.",
                    "source": "local_knowledge",
                    "sources": [],
                    "related_topics": ["Finding Analysis", "Code Review Summary"],
                    "generated_by": "local_knowledge_engine",
                    "model": "local_knowledge_engine"
                }
        else:
            if findings:
                matched_finding = findings[0]
            if remediations:
                matched_remediation = remediations[0]

        if matched_finding or matched_remediation:
            line_no = (matched_finding or matched_remediation).get("line", 1)
            issue = (matched_finding or matched_remediation).get("issue", "Code Finding")
            severity = str((matched_finding or matched_remediation).get("severity", "High")).capitalize()
            explanation = matched_finding.get("explanation", "") if matched_finding else matched_remediation.get("why_it_is_problematic", "")
            rec_fix = matched_remediation.get("recommended_fix", "") if matched_remediation else matched_finding.get("recommendation", "Refactor offending lines.")
            code_example = matched_remediation.get("corrected_code_example", "") if matched_remediation else matched_finding.get("secure_code", "")

            exact_line = (matched_finding or matched_remediation).get("exact_source_line", "")
            if not exact_line and code and isinstance(code, str):
                lines = code.split("\n")
                if 1 <= line_no <= len(lines):
                    exact_line = lines[line_no - 1].strip()

            answer_markdown = (
                f"### Finding Analysis: Line {line_no} — {issue}\n\n"
                f"**Severity Level:** `{severity}`\n\n"
            )
            if exact_line:
                answer_markdown += f"**Offending Source Code (Line {line_no}):**\n```python\n{exact_line}\n```\n\n"

            answer_markdown += (
                f"**WHAT is wrong & WHY it matters:**\n"
                f"{explanation or 'SentinelAI static analysis detected a security or quality rule violation on this line.'}\n\n"
                f"**WHAT should be changed & HOW to change it:**\n"
                f"{rec_fix}\n\n"
            )

            if code_example:
                answer_markdown += f"**Corrected Secure Code:**\n```python\n{code_example}\n```"

            return {
                "question": q_lower,
                "answer": answer_markdown,
                "source": "local_knowledge",
                "sources": [],
                "related_topics": [
                    f"Refactoring Line {line_no} Code",
                    "SentinelAI Automated Remediation Guidance",
                    "OWASP Security Best Practices"
                ],
                "generated_by": "local_knowledge_engine",
                "model": "local_knowledge_engine"
            }

        return None


# Global singleton instance loaded once at module import time
assistant_knowledge_engine = AssistantKnowledgeEngine()
