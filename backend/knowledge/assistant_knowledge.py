"""
SentinelAI Deterministic Local Knowledge Engine
================================================
Deterministic, LLM-free local knowledge assistant grounded strictly in:
1. OWASP Top 10 Security Standards (2021)
2. PEP 8 Guidelines & Python Style Rules
3. AST Analysis Rules & Code Quality Metrics
4. SentinelAI Security Agent Detection Rules
5. SentinelAI Code Analysis Agent Rules

Operates 100% offline with zero external API calls or LLM inference overhead.
Unsupported general knowledge questions are strictly rejected with a controlled response.
"""

import re
import time
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("ConversationalCodeAssistant")
logger.setLevel(logging.INFO)


class AssistantKnowledgeEngine:
    """
    Deterministic Local Knowledge Engine for SentinelAI AI Assistant.
    Provides instantaneous answers without calling any LLM.
    Strictly enforces local knowledge boundaries.
    """

    def __init__(self) -> None:
        # Cache knowledge once in memory at initialization
        self.owasp_knowledge = self._build_owasp_knowledge()
        self.pep8_knowledge = self._build_pep8_knowledge()
        self.ast_knowledge = self._build_ast_knowledge()
        self.security_rules_knowledge = self._build_security_rules_knowledge()
        self.sentinelai_knowledge = self._build_sentinelai_knowledge()

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
                    {"document": "OWASP Top 10: A03:2021 - Injection", "score": 0.98},
                    {"document": "SentinelAI Security Rules - SQLi Detector", "score": 0.95}
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
                "patterns": [r"\bxss\b", r"cross-site scripting", r"mark_safe", r"unescaped html"],
                "answer": (
                    "### Cross-Site Scripting (XSS)\n\n"
                    "**What is XSS?**\n"
                    "Cross-Site Scripting (XSS) occurs when untrusted user input is rendered directly into HTML web pages without sanitization or context-aware encoding. Attackers can execute malicious JavaScript in the victim's browser session, stealing session tokens, cookies, or hijacking user accounts.\n\n"
                    "**Remediation:**\n"
                    "- Context-encode all output rendered in templates.\n"
                    "- Avoid using raw HTML marks like Django's `mark_safe()` on unsanitized user inputs."
                ),
                "sources": [{"document": "OWASP Top 10: XSS", "score": 0.96}],
                "related_topics": ["Context-Aware HTML Encoding", "Content Security Policy (CSP)"]
            },
            "broken_access_control": {
                "category": "SECURITY",
                "topic": "OWASP A01:2021 - Broken Access Control",
                "patterns": [r"broken access control", r"\ba01\b", r"\bidor\b", r"unauthorized access", r"access control", r"authorization"],
                "answer": (
                    "### OWASP A01:2021 — Broken Access Control\n\n"
                    "**What is Broken Access Control?**\n"
                    "Access control enforces policies so that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of data, or performing a business function outside the user's limits.\n\n"
                    "**Common Access Control Vulnerabilities:**\n"
                    "- Insecure Direct Object References (IDOR): Accessing `/user/account?id=102` by changing the ID.\n"
                    "- Missing Function Level Access Control: Unprotected administrative APIs or HTTP methods.\n\n"
                    "**How to Fix:**\n"
                    "- Enforce access control in trusted server-side code or serverless API decorators.\n"
                    "- Implement role-based access control (RBAC)."
                ),
                "sources": [{"document": "OWASP Top 10: A01:2021 - Broken Access Control", "score": 0.96}],
                "related_topics": ["Role-Based Access Control (RBAC)", "Preventing IDOR Vulnerabilities"]
            },
            "crypto_failures": {
                "category": "SECURITY",
                "topic": "OWASP A02:2021 - Cryptographic Failures & Issues",
                "patterns": [r"cryptographic failure", r"cryptographic issue", r"weak cryptography", r"\ba02\b", r"\bmd5\b", r"\bsha1\b", r"weak hash", r"weak random"],
                "answer": (
                    "### OWASP A02:2021 — Cryptographic Failures & Weak Cryptography\n\n"
                    "**What is Cryptographic Failure?**\n"
                    "Failures related to cryptography (or lack thereof) lead to sensitive data exposure or compromise of system keys.\n\n"
                    "**Key Vulnerabilities Detected by SentinelAI:**\n"
                    "1. **Broken Hash Algorithms:** Using MD5 or SHA-1 for hashing (vulnerable to collision attacks).\n"
                    "2. **Weak Random Number Generators:** Using standard `random.Random()` for security tokens.\n\n"
                    "**Secure Remediation:**\n"
                    "Use strong SHA-256 / SHA-512 hashes and `secrets` module for tokens."
                ),
                "sources": [{"document": "OWASP Top 10: A02:2021 - Cryptographic Failures", "score": 0.95}],
                "related_topics": ["SHA-256 vs MD5 Collision Resistance", "Python secrets Module"]
            },
            "auth_failures": {
                "category": "SECURITY",
                "topic": "OWASP A07:2021 - Identification & Authentication Failures",
                "patterns": [r"authentication failure", r"broken auth", r"broken authentication", r"authentication security", r"\ba07\b", r"plaintext password"],
                "answer": (
                    "### OWASP A07:2021 — Identification and Authentication Failures\n\n"
                    "**What are Authentication Failures?**\n"
                    "Flaws in user authentication allow attackers to compromise passwords, keys, or session tokens, or exploit user identity impersonation.\n\n"
                    "**SentinelAI Checks:**\n"
                    "- Hardcoded credentials in source variables (`DB_PASSWORD = \"secret123\"`).\n"
                    "- Direct string comparisons for passwords (`if user.password == input_pass:`).\n\n"
                    "**Remediation:**\n"
                    "Use salted password hashing algorithms like `bcrypt` or `argon2`."
                ),
                "sources": [{"document": "OWASP Top 10: A07:2021 - Authentication Failures", "score": 0.96}],
                "related_topics": ["Password Hashing with Bcrypt & Argon2", "Environment Variables for Secrets"]
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
                    "2. **Line Length:** Maximum 79 characters for code (or 88 characters for Black standard).\n"
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
                    "| **Variables & Functions** | `snake_case` (lowercase with underscores) | `total_count`, `calculate_score()` |\n"
                    "| **Classes** | `CapWords` / `PascalCase` | `SecurityAgent`, `CodeAnalyzer` |\n"
                    "| **Constants** | `UPPER_CASE_WITH_UNDERSCORES` | `MAX_RETRY_COUNT`, `DEFAULT_TIMEOUT` |\n"
                    "| **Modules** | Short lowercase names | `orchestrator.py`, `reporting.py` |\n"
                    "| **Protected Members** | Single leading underscore | `_internal_method()` |\n"
                    "| **Private Members** | Double leading underscore | `__private_attr` |\n\n"
                    "**SentinelAI Rule:** Avoid non-descriptive single-letter variable names (`a`, `x`, `temp`) except for standard loop indices (`i`, `j`)."
                ),
                "sources": [{"document": "PEP 8 Naming Conventions Standard", "score": 0.98}],
                "related_topics": ["Single-Letter Variable Name Warning", "PEP 8 Constant Naming Rules"]
            },
            "indentation": {
                "category": "PEP8",
                "topic": "PEP 8 — Indentation & Line Length",
                "patterns": [r"indentation", r"line length", r"tabs vs spaces", r"recommended indentation"],
                "answer": (
                    "### PEP 8 — Indentation & Line Length\n\n"
                    "**Indentation:**\n"
                    "- Use strictly **4 spaces** per indentation level.\n"
                    "- Never mix tabs and spaces.\n\n"
                    "**Line Length:**\n"
                    "- Limit all lines to a maximum of **79 characters**."
                ),
                "sources": [{"document": "PEP 8 Indentation & Formatting", "score": 0.97}],
                "related_topics": ["PEP 8 Line Continuation Guidelines"]
            },
            "imports": {
                "category": "PEP8",
                "topic": "PEP 8 — Import Structure & Rules",
                "patterns": [r"how should imports be organized", r"import order", r"wildcard import", r"unused import"],
                "answer": (
                    "### PEP 8 — Import Structure & Best Practices\n\n"
                    "1. **Position:** Imports should always be placed at the top of the file.\n"
                    "2. **Order & Grouping:** Group imports into Standard library, Third-party, and Local imports.\n"
                    "3. **Avoid Wildcard Imports:** `from module import *` obscures names in namespace."
                ),
                "sources": [{"document": "PEP 8 Import Conventions", "score": 0.96}],
                "related_topics": ["Unused Import AST Detection"]
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
                    "**SentinelAI Thresholds:**\n"
                    "- **1 to 5:** Low complexity.\n"
                    "- **6 to 10:** Moderate complexity.\n"
                    "- **> 10:** High Complexity Warning (refactoring recommended).\n\n"
                    "**Maintainability Index:** Calculated based on Halstead volume, Cyclomatic Complexity, and lines of code. Scores below 50 indicate low maintainability."
                ),
                "sources": [{"document": "McCabe Cyclomatic Complexity Standard", "score": 0.97}],
                "related_topics": ["Refactoring Deep Conditionals", "Function Decomposition"]
            },
            "code_smells": {
                "category": "CODE_ANALYSIS",
                "topic": "AST Analysis — Code Smells & Quality Issues",
                "patterns": [
                    r"code smells", r"what code smells", r"code quality issues", r"code-quality issues",
                    r"long function", r"large class", r"too many parameters", r"deep nesting",
                    r"class/function size", r"function size", r"class size"
                ],
                "answer": (
                    "### Code Smells Detected by SentinelAI AST Analyzer\n\n"
                    "SentinelAI inspects code using AST visitors to catch the following code quality defects:\n\n"
                    "1. **Non-descriptive Variable Names:** Single-letter variables like `x` or `a` (except loop index `i`).\n"
                    "2. **Long Functions:** Functions spanning over 20 lines.\n"
                    "3. **Too Many Parameters:** Functions taking more than 5 parameters.\n"
                    "4. **Deep Control Structure Nesting:** Nested `if/for/while` blocks over 3 levels deep.\n"
                    "5. **Large Monolithic Classes:** Classes with more than 10 methods.\n"
                    "6. **High Cyclomatic Complexity:** Functions with CC > 10 decision paths.\n"
                    "7. **Duplicate Code Blocks:** Identical AST node sequences repeated in functions.\n"
                    "8. **Unused Variables & Imports:** Stored variables or imported modules never loaded in scope.\n"
                    "9. **Magic Numbers:** Hardcoded numeric literals outside named constants.\n"
                    "10. **Low Maintainability Index:** Score below 50 based on Halstead volume and complexity."
                ),
                "sources": [{"document": "CodeAnalysisAgent Specification", "score": 0.99}],
                "related_topics": ["Maintainability Index Score Formula", "Eliminating Magic Numbers"]
            }
        }

    def _build_security_rules_knowledge(self) -> Dict[str, Dict[str, Any]]:
        return {
            "eval_exec": {
                "category": "SECURITY",
                "topic": "Security Rule — eval() and exec() Dynamic Code Execution",
                "patterns": [r"\beval\b", r"\bexec\b", r"why is eval dangerous", r"eval\(\)", r"why is eval\(\) dangerous"],
                "answer": (
                    "### Security Warning: Dynamic Execution via eval() / exec()\n\n"
                    "**Why is eval() Dangerous?**\n"
                    "`eval()` and `exec()` parse and execute arbitrary text strings directly as live Python code. If the string contains any user-controlled input, an attacker can execute arbitrary system commands, read/delete files, or open reverse shells (Remote Code Execution / RCE).\n\n"
                    "**Vulnerable Example:**\n"
                    "```python\n"
                    "# DANGEROUS: Untrusted user string passed to eval()\n"
                    "result = eval(user_input)\n"
                    "```\n\n"
                    "**Secure Remediation:**\n"
                    "If you only need to evaluate literal data structures (strings, numbers, dicts, lists, tuples, booleans), use `ast.literal_eval()`:\n"
                    "```python\n"
                    "import ast\n"
                    "# SECURE: Safely parses literals without code execution risk\n"
                    "result = ast.literal_eval(user_input)\n"
                    "```"
                ),
                "sources": [{"document": "SentinelAI SecurityAgent Rule: sec_eval", "score": 0.99}],
                "related_topics": ["Safe Expression Parsing with ast.literal_eval()", "Understanding RCE Risks"]
            },
            "secrets": {
                "category": "SECURITY",
                "topic": "Security Rule — Hardcoded Credentials & Secrets",
                "patterns": [
                    r"hardcoded credential", r"hardcoded password", r"hardcoded private key", r"hardcoded aws key", r"hardcoded api key"
                ],
                "answer": (
                    "### Security Warning & Remediation: Hardcoded Credentials & Private Keys\n\n"
                    "**Why Hardcoded Secrets are Dangerous:**\n"
                    "Embedding credentials (database passwords, API keys, JWT secrets, AWS tokens, RSA private keys) in source code exposes them to anyone with repository access or version history.\n\n"
                    "**How to Fix Hardcoded Credentials:**\n"
                    "Store credentials in environment variables or key vaults:\n"
                    "```python\n"
                    "import os\n"
                    "# SECURE: Read credentials from environment variables\n"
                    "db_password = os.getenv(\"DB_PASSWORD\")\n"
                    "api_key = os.getenv(\"API_KEY\")\n"
                    "```"
                ),
                "sources": [{"document": "SentinelAI SecurityAgent Secrets Rule", "score": 0.99}],
                "related_topics": ["Managing Secrets with python-dotenv", "CWE-798 Hardcoded Secrets Prevention"]
            },
            "shell_true": {
                "category": "SECURITY",
                "topic": "Security Rule — Subprocess with shell=True / Command Injection",
                "patterns": [r"shell=true", r"command injection", r"what does shell=true mean", r"os\.system", r"os\.popen"],
                "answer": (
                    "### Security Warning: Command Injection via shell=True & os.system()\n\n"
                    "**What does shell=True mean?**\n"
                    "In Python's `subprocess` module, setting `shell=True` passes the command line string to the underlying operating system shell (`/bin/sh` or `cmd.exe`). If dynamic parameters are concatenated into the command string, attackers can execute arbitrary OS commands.\n\n"
                    "**Secure Remediation:**\n"
                    "Pass arguments as a **list of strings** and omit `shell=True` (default is `shell=False`):\n"
                    "```python\n"
                    "# SECURE: Command arguments passed as separate list elements\n"
                    "subprocess.run([\"ping\", \"-c\", \"4\", user_host], shell=False)\n"
                    "```"
                ),
                "sources": [{"document": "SentinelAI SecurityAgent Rule: sec_cmdi", "score": 0.99}],
                "related_topics": ["Safe OS Command Execution in Python", "CWE-78 Command Injection Safeguards"]
            },
            "path_traversal": {
                "category": "SECURITY",
                "topic": "Security Rule — Insecure File Access & Path Traversal",
                "patterns": [r"insecure file access", r"path traversal", r"directory traversal", r"file access"],
                "answer": (
                    "### Security Warning: Insecure File Access & Path Traversal\n\n"
                    "**What is Path Traversal?**\n"
                    "Path Traversal occurs when user input is concatenated into file system paths without sanitization (e.g. `../../etc/passwd`).\n\n"
                    "**Remediation:**\n"
                    "Use `os.path.abspath()` and `os.path.commonpath()` or Python 3 `pathlib` to verify the target path remains inside an allowed base directory."
                ),
                "sources": [{"document": "SentinelAI SecurityAgent Rule: sec_path", "score": 0.98}],
                "related_topics": ["Path Sanitization with pathlib", "CWE-22 Path Traversal Prevention"]
            },
            "security_misconfig": {
                "category": "SECURITY",
                "topic": "OWASP A05:2021 - Security Misconfiguration",
                "patterns": [r"security misconfiguration", r"misconfiguration", r"debug mode"],
                "answer": (
                    "### Security Misconfiguration\n\n"
                    "**What is Security Misconfiguration?**\n"
                    "Security misconfiguration occurs when application settings, framework debug flags, or server configurations are left in insecure default states (e.g. `DEBUG = True` in production Django/Flask applications)."
                ),
                "sources": [{"document": "OWASP Top 10: A05:2021 - Security Misconfiguration", "score": 0.96}],
                "related_topics": ["Hardening Production Framework Settings"]
            }
        }

    def _build_sentinelai_knowledge(self) -> Dict[str, Dict[str, Any]]:
        return {
            "capabilities": {
                "category": "SECURITY",
                "topic": "SentinelAI — Security Vulnerabilities Detected",
                "patterns": [
                    r"vulnerabilities does sentinelai detect", r"security issues does sentinelai detect",
                    r"supported security checks", r"security vulnerabilities detected by securityagent"
                ],
                "answer": (
                    "### Security Vulnerabilities Detected by SentinelAI\n\n"
                    "SentinelAI automatically audits source code for 11 core security vulnerability categories across Python, Java, JavaScript, C++, Go, and PHP:\n\n"
                    "1. **SQL Injection (SQLi):** Unsanitized string concatenation, f-strings, `.format()` in database queries.\n"
                    "2. **Command Injection:** `os.system()`, `os.popen()`, `Runtime.exec()`, and `subprocess(shell=True)`.\n"
                    "3. **Hardcoded Secrets:** Exposed passwords, private keys, AWS access tokens, and API credentials.\n"
                    "4. **Dynamic Code Execution:** Unsafe `eval()` and `exec()` calls.\n"
                    "5. **Insecure Deserialization:** Unsafe `pickle.loads()`, `marshal`, and `yaml.load()`.\n"
                    "6. **Cross-Site Scripting (XSS):** `mark_safe()`, `render_template_string()`, unescaped HTML responses.\n"
                    "7. **Broken Authentication:** Plaintext password comparisons and missing password hash verification.\n"
                    "8. **Broken Access Control:** Unprotected sensitive endpoints lacking authentication decorators.\n"
                    "9. **Path Traversal:** File system access using unvalidated path string formatting.\n"
                    "10. **Weak Cryptography:** Usage of MD5, SHA-1, DES, or non-cryptographic random generators.\n"
                    "11. **Server-Side Request Forgery (SSRF):** Dynamic unvalidated target URLs in HTTP clients."
                ),
                "sources": [{"document": "SentinelAI SecurityAgent Core Rules", "score": 0.99}],
                "related_topics": ["OWASP Top 10 Compliance Mapping", "SentinelAI Code Analysis Rules"]
            },
            "architecture": {
                "category": "CODE_ANALYSIS",
                "topic": "SentinelAI — Python Code Analysis Architecture",
                "patterns": [r"how does sentinelai analyze python code", r"how sentinelai works", r"sentinelai analysis architecture"],
                "answer": (
                    "### SentinelAI Analysis Architecture\n\n"
                    "SentinelAI combines deterministic static analysis with local AI models to deliver rapid, accurate code reviews:\n\n"
                    "1. **AST Static Code Analyzer (`code_analysis_agent.py`):** Parses source code into AST nodes to compute Cyclomatic Complexity, method lengths, nesting levels, unused imports, and code smells.\n"
                    "2. **Security Agent (`security_agent.py`):** Runs AST visitors and multi-language pattern matchers to detect OWASP vulnerabilities.\n"
                    "3. **Consolidated Finding Triaging:** Merges, deduplicates, and ranks security and quality issues by severity (Critical, High, Medium, Low).\n"
                    "4. **Deterministic Local Knowledge Engine:** Provides sub-second offline Q&A responses grounded in OWASP, PEP 8, and AST rules without external API calls.\n"
                    "5. **Local Ollama LLM (`qwen3:8b`):** Generates full refactored code fixes, remediations, and pull request summaries for code reviews."
                ),
                "sources": [{"document": "SentinelAI System Architecture Guide", "score": 0.99}],
                "related_topics": ["SentinelAI Security Rules Overview", "AST Analysis Rules Specification"]
            }
        }

    # --------------------------------------------------------------------------
    # Main Knowledge Engine Query Handler
    # --------------------------------------------------------------------------

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
        Processes developer questions deterministically using local in-memory knowledge bases.
        Only allowed categories produce an answer. Everything else is rejected with the controlled fallback.
        """
        start_time = time.perf_counter()
        q_clean = (question or "").strip()
        q_lower = q_clean.lower()

        # 1. First check if user is asking for CODE REMEDIATION / SECURE CODE FIX
        remediation_match = self._match_remediation_intent(q_lower, findings, code, remediations)
        if remediation_match:
            category_type, res_dict = remediation_match
            elapsed = time.perf_counter() - start_time
            logger.info(f"[ASSISTANT] Question: {q_lower}")
            logger.info(f"[ASSISTANT] Category: {category_type}")
            logger.info(f"[ASSISTANT] Source: {res_dict.get('source', 'local_knowledge')}")
            logger.info("[ASSISTANT] LLM: NONE")
            logger.info(f"  Local response generated in {elapsed:.4f}s")
            return res_dict

        # 2. Check if question EXPLICITLY asks about an ACTIVE FINDING or LINE NUMBER
        finding_match = self._match_active_finding_context(q_lower, findings, code, remediations)
        if finding_match:
            elapsed = time.perf_counter() - start_time
            logger.info(f"[ASSISTANT] Question: {q_lower}")
            logger.info("[ASSISTANT] Category: CURRENT FINDING")
            logger.info("  Source: OWASP/SecurityAgent/local_rules")
            logger.info("  LLM: NONE")
            logger.info(f"  Local response generated in {elapsed:.4f}s")
            return finding_match

        # 3. Check Knowledge Maps for supported categories (OWASP, PEP8, AST, SECURITY, CODE_ANALYSIS)
        knowledge_sources = [
            ("OWASP/SecurityAgent/local_rules", self.owasp_knowledge),
            ("PEP8/local_rules", self.pep8_knowledge),
            ("AST/local_rules", self.ast_knowledge),
            ("SecurityAgent/local_rules", self.security_rules_knowledge),
            ("SentinelAI/local_rules", self.sentinelai_knowledge)
        ]

        for source_name, k_map in knowledge_sources:
            for item in k_map.values():
                patterns = item.get("patterns", [])
                if any(re.search(pat, q_lower) for pat in patterns):
                    category = item.get("category", "SECURITY")
                    elapsed = time.perf_counter() - start_time
                    logger.info(f"[ASSISTANT] Question: {q_lower}")
                    logger.info(f"[ASSISTANT] Category: {category}")
                    logger.info(f"[ASSISTANT] Source: OWASP/SecurityAgent/local_rules")
                    logger.info("[ASSISTANT] LLM: NONE")
                    logger.info(f"  Local response generated in {elapsed:.4f}s")

                    return {
                        "question": q_clean,
                        "answer": item["answer"],
                        "source": "local_knowledge",
                        "sources": item["sources"],
                        "related_topics": item["related_topics"],
                        "generated_by": "local_knowledge_engine",
                        "model": "local_knowledge_engine"
                    }

        # 4. UNSUPPORTED QUESTION CLASSIFICATION & CONTROLLED REJECTION
        elapsed = time.perf_counter() - start_time
        logger.info(f"[ASSISTANT] Question: {q_lower}")
        logger.info("[ASSISTANT] Category: UNSUPPORTED")
        logger.info("[ASSISTANT] Source: local_knowledge")
        logger.info("[ASSISTANT] LLM: NONE")

        return {
            "question": q_clean,
            "answer": "I can only answer questions related to SentinelAI's secure coding knowledge, including OWASP Top 10, PEP 8, AST analysis, security vulnerabilities, code analysis, and remediation rules.",
            "related_topics": [
                "OWASP Top 10",
                "PEP 8",
                "AST Analysis",
                "Security Vulnerabilities"
            ],
            "source": "local_knowledge",
            "sources": [
                {"document": "local_knowledge", "score": 1.0}
            ],
            "generated_by": "local_knowledge_engine",
            "model": "local_knowledge_engine"
        }

    # --------------------------------------------------------------------------
    # Remediation Intent Handler
    # --------------------------------------------------------------------------

    def _match_remediation_intent(
        self,
        q_lower: str,
        findings: Optional[List[Dict[str, Any]]],
        code: Optional[str],
        remediations: Optional[List[Dict[str, Any]]]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Detects user requests to secure code or apply remediation rules.
        """
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

        # Case 1: Remediation requested BUT NO CODE/FINDINGS/REMEDIATION CONTEXT AVAILABLE
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
                "sources": [
                    {"document": "local_knowledge", "score": 1.0}
                ],
                "generated_by": "local_knowledge_engine",
                "model": "local_knowledge_engine"
            })

        # Case 2: Code / Findings / Remediation context IS available
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
                "sources": [
                    {"document": "SentinelAI Remediation Engine", "score": 1.0}
                ],
                "generated_by": "local_knowledge_engine",
                "model": "local_knowledge_engine"
            })

        # Case 3: Code string provided without finding objects
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
            "sources": [{"document": "SentinelAI Local Knowledge Engine", "score": 1.0}],
            "generated_by": "local_knowledge_engine",
            "model": "local_knowledge_engine"
        })

    # --------------------------------------------------------------------------
    # Active Finding & Context Question Handler (STRICT)
    # --------------------------------------------------------------------------

    def _match_active_finding_context(
        self,
        q_lower: str,
        findings: Optional[List[Dict[str, Any]]],
        code: Optional[str],
        remediations: Optional[List[Dict[str, Any]]]
    ) -> Optional[Dict[str, Any]]:
        """
        Only matches if user question explicitly asks about a finding or line number.
        Does NOT match general questions (e.g. 'What is phone?').
        """
        if not findings and not code and not remediations:
            return None

        # Explicit inquiry triggers
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
        if findings:
            if target_line:
                for f in findings:
                    if f.get("line") == target_line:
                        matched_finding = f
                        break
            if not matched_finding:
                matched_finding = findings[0]

        matched_remediation = None
        if remediations:
            if target_line:
                for r in remediations:
                    if r.get("line") == target_line:
                        matched_remediation = r
                        break
            if not matched_remediation:
                matched_remediation = remediations[0]

        if matched_finding or matched_remediation:
            line_no = (matched_finding or matched_remediation).get("line", 1)
            issue = (matched_finding or matched_remediation).get("issue", "Code Finding")
            severity = (matched_finding or matched_remediation).get("severity", "High")
            explanation = matched_finding.get("explanation", "") if matched_finding else matched_remediation.get("why_it_is_problematic", "")
            rec_fix = matched_remediation.get("recommended_fix", "") if matched_remediation else matched_finding.get("recommendation", "Refactor offending lines.")
            code_example = matched_remediation.get("corrected_code_example", "") if matched_remediation else matched_finding.get("secure_code", "")

            answer_markdown = (
                f"### Finding Analysis: Line {line_no} — {issue}\n\n"
                f"**Severity Level:** `{severity}`\n\n"
                f"**Why was this issue flagged?**\n"
                f"{explanation or 'SentinelAI static analysis detected a security or quality rule violation on this line.'}\n\n"
                f"**Recommended Remediation:**\n"
                f"{rec_fix}\n\n"
            )

            if code_example:
                answer_markdown += f"**Secure Code Example:**\n```python\n{code_example}\n```"

            return {
                "question": q_lower,
                "answer": answer_markdown,
                "source": "local_knowledge",
                "sources": [
                    {"document": f"SentinelAI Finding Context (Line {line_no})", "score": 1.0},
                    {"document": "SentinelAI Remediation Engine", "score": 0.95}
                ],
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
