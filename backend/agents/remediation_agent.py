import json
import re


class RemediationAgent:
    """
    Remediation Agent that receives findings from CodeAnalysisAgent and SecurityAgent
    and produces structured, actionable remediation guidance and secure code examples.
    """

    def __init__(self):
        # Register mapping-based rules (Pattern -> Handler)
        self._rules = [
            # Security Vulnerabilities
            (re.compile(r"sql injection", re.IGNORECASE), self._remediate_sql_injection),
            (re.compile(r"cross-site scripting|xss|mark_safe", re.IGNORECASE), self._remediate_xss),
            (re.compile(r"broken authentication|plaintext password|hardcoded authentication", re.IGNORECASE), self._remediate_broken_auth),
            (re.compile(r"missing access control|broken access control", re.IGNORECASE), self._remediate_broken_access_control),
            (re.compile(r"path traversal", re.IGNORECASE), self._remediate_path_traversal),
            (re.compile(r"command injection|os\.system|os\.popen|shell=True", re.IGNORECASE), self._remediate_command_injection),
            (re.compile(r"insecure deserialization|pickle|marshal|yaml\.load|shelve", re.IGNORECASE), self._remediate_insecure_deserialization),
            (re.compile(r"weak cryptographic|md5|sha1", re.IGNORECASE), self._remediate_weak_crypto),
            (re.compile(r"hardcoded credential|hardcoded private key|hardcoded aws|sensitive", re.IGNORECASE), self._remediate_sensitive_info),
            (re.compile(r"ssrf|server-side request forgery", re.IGNORECASE), self._remediate_ssrf),
            (re.compile(r"eval\(\)|exec\(\)", re.IGNORECASE), self._remediate_eval_exec),

            # Code Quality Issues
            (re.compile(r"not descriptive|variable '.*' is not descriptive|poor variable", re.IGNORECASE), self._remediate_poor_variables),
            (re.compile(r"too many parameters", re.IGNORECASE), self._remediate_too_many_parameters),
            (re.compile(r"large class", re.IGNORECASE), self._remediate_large_class),
            (re.compile(r"cyclomatic complexity", re.IGNORECASE), self._remediate_cyclomatic_complexity),
            (re.compile(r"too long|long method|function '.*' is too long", re.IGNORECASE), self._remediate_long_methods),
            (re.compile(r"deep nesting", re.IGNORECASE), self._remediate_deep_nesting),
            (re.compile(r"duplicate code|duplicate function body", re.IGNORECASE), self._remediate_duplicate_code),
            (re.compile(r"unused variable", re.IGNORECASE), self._remediate_unused_variable),
            (re.compile(r"unused import", re.IGNORECASE), self._remediate_unused_import),
            (re.compile(r"magic number", re.IGNORECASE), self._remediate_magic_number),
            (re.compile(r"maintainability score", re.IGNORECASE), self._remediate_maintainability),
        ]

    def generate_remediation(self, findings):
        """
        Receives a list (or JSON string) of findings and returns structured remediation guidance for each.
        """
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except Exception:
                findings = []

        if not isinstance(findings, list):
            return []

        remediations = []
        for finding in findings:
            if isinstance(finding, dict):
                remediations.append(self._process_finding(finding))

        return remediations

    def remediate(self, findings):
        """Alias for generate_remediation for orchestrator compatibility."""
        return self.generate_remediation(findings)

    def analyze(self, findings):
        """Alias for generate_remediation for orchestrator compatibility."""
        return self.generate_remediation(findings)

    def _process_finding(self, finding: dict) -> dict:
        issue_text = finding.get("issue", "")
        explanation_text = finding.get("explanation", "")
        combined_text = f"{issue_text} {explanation_text}"

        handler = self._find_handler(combined_text)
        details = handler(finding)

        return {
            "issue": issue_text,
            "severity": finding.get("severity", "Low"),
            "line": finding.get("line", 0),
            "why_it_is_problematic": details["why_it_is_problematic"],
            "recommended_fix": details["recommended_fix"],
            "corrected_code_example": details["corrected_code_example"],
            "best_practice": details["best_practice"],
            "references": details["references"]
        }

    def _find_handler(self, text: str):
        for pattern, handler in self._rules:
            if pattern.search(text):
                return handler
        return self._default_remediation

    # --------------------------------------------------------------------------
    # Helper Rule Handlers (Modular Mapping System)
    # --------------------------------------------------------------------------

    def _remediate_sql_injection(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Constructing SQL queries by concatenating strings or formatting variables directly allows attackers to inject malicious SQL commands, leading to unauthorized database access, data theft, or database alteration.",
            "recommended_fix": "Use parameterized queries (prepared statements) provided by your database library. Parameterized queries enforce strict separation between SQL code and user data.",
            "corrected_code_example": "# Secure parameterized query example:\ncursor.execute('SELECT * FROM users WHERE username = %s AND status = %s', (username, status))\n\n# Using SQLAlchemy ORM:\nuser = session.query(User).filter_by(username=username).first()",
            "best_practice": "Never format or concatenate variables directly into SQL statements. Always use parameterized placeholders (%s, ?, :val) or an Object-Relational Mapper (ORM).",
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "OWASP SQL Injection Prevention Cheat Sheet",
                "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "Python DB-API 2.0 Specification (PEP 249)"
            ]
        }

    def _remediate_xss(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Rendering dynamic input without escaping or marking untrusted strings as safe (e.g. mark_safe) allows attackers to execute arbitrary Client-Side JavaScript in the context of user sessions.",
            "recommended_fix": "Sanitize and escape dynamic content before rendering in HTML responses, and avoid using mark_safe() or raw HTML string injection on user-controlled inputs.",
            "corrected_code_example": "# Secure HTML escaping example:\nfrom markupsafe import escape\nsafe_input = escape(user_input)\nreturn HTMLResponse(content=f'<h1>Hello {safe_input}</h1>')\n\n# In Jinja2/Django templates, leverage default auto-escaping.",
            "best_practice": "Use modern template engines with auto-escaping enabled by default, implement a strong Content Security Policy (CSP), and sanitize rich text using libraries like Bleach.",
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet",
                "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "Python MarkupSafe Documentation"
            ]
        }

    def _remediate_broken_auth(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Hardcoded authentication values or plaintext password comparisons expose credentials to leaks and timing attacks, making application authentication trivial to bypass.",
            "recommended_fix": "Store user passwords as secure cryptographic hashes using Argon2id or bcrypt, and verify credentials using constant-time hash comparison functions.",
            "corrected_code_example": "# Secure password hashing and verification:\nfrom passlib.hash import pbkdf2_sha256\n\n# Password hashing during signup/change:\nhashed_password = pbkdf2_sha256.hash(raw_password)\n\n# Password verification during login:\nis_correct = pbkdf2_sha256.verify(provided_password, stored_password_hash)",
            "best_practice": "Use established password hashing algorithms (Argon2id, bcrypt, PBKDF2) with random salts. Never compare or store passwords in plaintext.",
            "references": [
                "OWASP Top 10: A07:2021 - Identification and Authentication Failures",
                "OWASP Password Storage Cheat Sheet",
                "CWE-256: Unprotected Storage of Credentials",
                "Python PassLib Documentation"
            ]
        }

    def _remediate_broken_access_control(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Endpoints or functions that execute sensitive operations (such as record deletion or administrative updates) without checking user authorization allow unauthorized users to perform privileged operations.",
            "recommended_fix": "Apply explicit authorization checks or role/permission dependencies (e.g. Depends(get_current_active_user)) to every sensitive endpoint.",
            "corrected_code_example": "# Secure endpoint with authentication dependency:\n@app.delete('/users/{user_id}')\ndef delete_user(user_id: int, current_user: User = Depends(get_current_active_user)):\n    if not current_user.is_admin:\n        raise HTTPException(status_code=403, detail='Permission denied')\n    db.delete_user(user_id)",
            "best_practice": "Deny access by default. Enforce Role-Based Access Control (RBAC) at both the routing layer and domain logic layer.",
            "references": [
                "OWASP Top 10: A01:2021 - Broken Access Control",
                "OWASP Authorization Cheat Sheet",
                "CWE-285: Improper Authorization",
                "FastAPI Security Dependencies Documentation"
            ]
        }

    def _remediate_path_traversal(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Building file system paths directly from dynamic inputs allows path traversal characters (such as '../') to escape base directories and read or write sensitive system files.",
            "recommended_fix": "Sanitize filenames using secure utilities like werkzeug.utils.secure_filename(), resolve absolute path targets, and verify targets remain within the allowed base directory.",
            "corrected_code_example": "# Secure path validation example:\nfrom pathlib import Path\nfrom werkzeug.utils import secure_filename\n\nbase_dir = Path('/var/uploads').resolve()\nsafe_name = secure_filename(user_filename)\ntarget_file = (base_dir / safe_name).resolve()\n\nif not target_file.is_relative_to(base_dir):\n    raise ValueError('Access Denied: Path traversal detected')\nwith open(target_file, 'r') as f:\n    data = f.read()",
            "best_practice": "Never allow unvalidated user inputs in file system paths. Validate path boundaries using pathlib or map file requests to internal generated UUIDs.",
            "references": [
                "OWASP Top 10: A01:2021 - Broken Access Control",
                "OWASP Path Traversal Prevention Cheat Sheet",
                "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                "Python pathlib Documentation"
            ]
        }

    def _remediate_command_injection(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Invoking system commands via os.system(), os.popen(), or subprocess with shell=True executes input strings inside a subshell. Attackers can inject command separators (e.g. ';', '&&') to execute arbitrary OS commands.",
            "recommended_fix": "Use subprocess.run() with shell=False (the default) and pass arguments as a list of strings rather than a raw command string.",
            "corrected_code_example": "# Secure subprocess execution:\nimport subprocess\n\n# Pass command and arguments as a list with shell=False:\nresult = subprocess.run(['ping', '-c', '4', host_ip], capture_output=True, text=True, check=True)",
            "best_practice": "Avoid shell command execution whenever native Python standard library modules (os, shutil, requests) can perform the operation directly.",
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "OWASP OS Command Injection Defense Cheat Sheet",
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                "Python subprocess Documentation"
            ]
        }

    def _remediate_insecure_deserialization(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Deserializing untrusted data using pickle, marshal, shelve, or yaml.load() allows arbitrary Python object reconstruction, leading directly to Remote Code Execution (RCE).",
            "recommended_fix": "Replace unsafe deserializers with standardized, safe serialization formats like JSON (json.loads) or use yaml.safe_load().",
            "corrected_code_example": "# Secure JSON deserialization:\nimport json\ndata = json.loads(user_json_str)\n\n# Secure YAML deserialization:\nimport yaml\nconfig = yaml.safe_load(user_yaml_str)",
            "best_practice": "Never deserialize untrusted data with pickle or marshal. Use safe, language-independent data exchange formats like JSON or Protocol Buffers.",
            "references": [
                "OWASP Top 10: A08:2021 - Software and Data Integrity Failures",
                "OWASP Deserialization Cheat Sheet",
                "CWE-502: Deserialization of Untrusted Data",
                "Python pickle Module Security Warning"
            ]
        }

    def _remediate_weak_crypto(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "MD5 and SHA-1 algorithms are cryptographically broken and susceptible to collision attacks, enabling attackers to forge data digests or certificates.",
            "recommended_fix": "Upgrade hash algorithms to SHA-256 or SHA-512 for data integrity checks, and use dedicated password key derivation algorithms (Argon2, PBKDF2) for authentication.",
            "corrected_code_example": "# Secure SHA-256 hashing:\nimport hashlib\nhash_digest = hashlib.sha256(data_bytes).hexdigest()",
            "best_practice": "Use modern cryptographic primitives recommended by NIST (SHA-256/512, AES-256-GCM). Discontinue MD5, SHA1, DES, and RC4.",
            "references": [
                "OWASP Top 10: A02:2021 - Cryptographic Failures",
                "OWASP Cryptographic Storage Cheat Sheet",
                "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                "Python hashlib Documentation"
            ]
        }

    def _remediate_sensitive_info(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Hardcoding API keys, passwords, private keys, AWS secrets, or JWT secrets in code files exposes credentials in version control systems and built packages.",
            "recommended_fix": "Extract secrets from source code files and load them dynamically from environment variables or a secret vault.",
            "corrected_code_example": "# Secure environment variable secret loading:\nimport os\napi_secret = os.getenv('API_SECRET')\nif not api_secret:\n    raise RuntimeError('API_SECRET environment variable is missing')",
            "best_practice": "Follow 12-Factor App principles. Keep secrets in environment variables or secret management services (AWS Secrets Manager, Vault) and include .env in .gitignore.",
            "references": [
                "OWASP Top 10: A02:2021 - Cryptographic Failures",
                "OWASP Secrets Management Cheat Sheet",
                "CWE-798: Use of Hard-coded Credentials",
                "The Twelve-Factor App: Config III"
            ]
        }

    def _remediate_ssrf(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Issuing HTTP requests to dynamic user-supplied URLs without domain/IP validation allows attackers to target internal microservices, loopback interfaces (127.0.0.1), or cloud metadata endpoints.",
            "recommended_fix": "Validate target URLs against an explicit domain allowlist, restrict outbound IP destinations, and disable HTTP redirect following for user-provided URLs.",
            "corrected_code_example": "# Secure URL domain validation:\nfrom urllib.parse import urlparse\nimport requests\n\nALLOWED_DOMAINS = {'api.trusted.com', 'services.trusted.com'}\nparsed = urlparse(target_url)\nif parsed.hostname not in ALLOWED_DOMAINS:\n    raise ValueError('Unauthorized target domain')\nresponse = requests.get(target_url, timeout=5.0)",
            "best_practice": "Validate and sanitize destination hostnames/IPs against an explicit allowlist, block requests to internal IP ranges (10.0.0.0/8, 127.0.0.0/8, 169.254.169.254), and enforce request timeouts.",
            "references": [
                "OWASP Top 10: A10:2021 - Server-Side Request Forgery (SSRF)",
                "OWASP Server-Side Request Forgery Prevention Cheat Sheet",
                "CWE-918: Server-Side Request Forgery (SSRF)",
                "Python urllib.parse Documentation"
            ]
        }

    def _remediate_eval_exec(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "eval() and exec() parse and execute arbitrary text strings as Python code, providing an immediate path for arbitrary Remote Code Execution (RCE).",
            "recommended_fix": "Remove eval()/exec() calls. Use safe data literal parsing with ast.literal_eval() or explicit dictionary mappings for operations.",
            "corrected_code_example": "# Secure literal parsing:\nimport ast\nsafe_data = ast.literal_eval(user_input_string)\n\n# Secure dynamic dispatch:\nACTIONS = {'start': start_service, 'stop': stop_service}\nif action in ACTIONS:\n    ACTIONS[action]()",
            "best_practice": "Avoid dynamic code execution. Parse structured data with standard serializers (JSON/YAML) or safe AST evaluation tools like ast.literal_eval().",
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
                "Python ast.literal_eval Documentation"
            ]
        }

    def _remediate_poor_variables(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Single-letter or cryptic variable names obscure code intent, making code maintenance, debugging, and code reviews difficult.",
            "recommended_fix": "Rename variables to descriptive, self-explanatory names matching Python PEP 8 conventions.",
            "corrected_code_example": "# Refactored descriptive variable names:\ntotal_users = len(user_list)\nfor user_index in range(total_users):\n    process_user(user_index)",
            "best_practice": "Use meaningful, intention-revealing names for variables, functions, and classes following PEP 8 naming style guidelines.",
            "references": [
                "PEP 8 - Style Guide for Python Code (Naming Conventions)",
                "Clean Code: Chapter 2 - Meaningful Names"
            ]
        }

    def _remediate_too_many_parameters(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Functions with excessive parameters (> 5) indicate high coupling, poor encapsulation, and make calls error-prone.",
            "recommended_fix": "Group related parameters into a dataclass, Pydantic model, or parameter object.",
            "corrected_code_example": "# Parameter Object Refactoring:\nfrom dataclasses import dataclass\n\n@dataclass\nclass FilterOptions:\n    category: str\n    min_price: float\n    max_price: float\n    is_active: bool\n\ndef search_products(options: FilterOptions):\n    # Logic using options object\n    pass",
            "best_practice": "Keep parameter lists short (<= 3-4 arguments). Pass cohesive data attributes wrapped in a typed dataclass.",
            "references": [
                "Refactoring by Martin Fowler (Introduce Parameter Object)",
                "Clean Code: Function Arguments"
            ]
        }

    def _remediate_large_class(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Classes defining too many methods (> 10) violate the Single Responsibility Principle (SRP) and turn into bloated, tightly-coupled 'God Objects'.",
            "recommended_fix": "Decompose the large class into smaller, single-purpose component classes using composition.",
            "corrected_code_example": "# Extracted modular classes:\nclass UserValidator:\n    def validate(self, user):\n        pass\n\nclass UserRepository:\n    def save(self, user):\n        pass\n\nclass UserService:\n    def __init__(self, validator: UserValidator, repo: UserRepository):\n        self.validator = validator\n        self.repo = repo",
            "best_practice": "Apply SOLID principles. Design focused, single-responsibility classes with high internal cohesion.",
            "references": [
                "SOLID Principles: Single Responsibility Principle",
                "Refactoring by Martin Fowler (Extract Class)"
            ]
        }

    def _remediate_cyclomatic_complexity(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "High cyclomatic complexity means functions contain extensive branching and decision paths, leading to high bug risk and complex testing requirements.",
            "recommended_fix": "Simplify decision trees by applying early guard clause returns or extracting decision branches into dedicated helper functions.",
            "corrected_code_example": "# Refactored with guard clauses:\ndef process_transaction(transaction):\n    if not transaction.is_valid:\n        return False\n    if transaction.is_processed:\n        return True\n    return execute_transaction(transaction)",
            "best_practice": "Maintain cyclomatic complexity <= 5 per function. Use guard clauses, lookup dictionaries, or polymorphic classes to replace complex nested conditionals.",
            "references": [
                "McCabe Cyclomatic Complexity Metric",
                "Refactoring: Replace Nested Conditional with Guard Clauses"
            ]
        }

    def _remediate_long_methods(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Long methods (> 20 lines) combine multiple concerns and abstraction levels into a single block, making code hard to reuse and test.",
            "recommended_fix": "Extract logical steps into smaller, well-named helper functions.",
            "corrected_code_example": "# Refactored with extracted methods:\ndef process_request(request):\n    data = parse_request(request)\n    validated = validate_request_data(data)\n    return generate_response(validated)",
            "best_practice": "Write short functions focused on a single responsibility and single level of abstraction (preferably < 20 lines).",
            "references": [
                "Refactoring by Martin Fowler (Extract Method)",
                "Clean Code: Small Functions"
            ]
        }

    def _remediate_deep_nesting(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Deep control flow nesting (> 3 levels) creates 'arrow code', drastically degrading code readability and increasing cognitive load.",
            "recommended_fix": "Flatten nested blocks using early returns, guard clauses, or list comprehensions.",
            "corrected_code_example": "# Flattened control flow:\ndef process_items(items):\n    for item in items:\n        if not item.is_valid:\n            continue\n        process_single_item(item)",
            "best_practice": "Keep nesting shallow (maximum 2-3 levels). 'Flat is better than nested' (The Zen of Python).",
            "references": [
                "PEP 20 - The Zen of Python ('Flat is better than nested')",
                "Refactoring: Replace Nested Conditional with Guard Clauses"
            ]
        }

    def _remediate_duplicate_code(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Duplicated code blocks violate the DRY principle. Bug fixes or updates applied in one location are easily missed in identical blocks elsewhere.",
            "recommended_fix": "Extract identical or near-identical code blocks into a single reusable helper function or class method.",
            "corrected_code_example": "# Refactored reusable function:\ndef calculate_total(subtotal, tax_rate):\n    return subtotal * (1 + tax_rate)\n\ntotal_a = calculate_total(subtotal_a, 0.05)\ntotal_b = calculate_total(subtotal_b, 0.05)",
            "best_practice": "Follow the DRY (Don't Repeat Yourself) principle. Centralize shared logic in reusable, single-source utility functions.",
            "references": [
                "The Pragmatic Programmer: DRY Principle",
                "Refactoring by Martin Fowler (Extract Function)"
            ]
        }

    def _remediate_unused_variable(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Unused variables create visual noise, confuse maintainers, and may indicate incomplete business logic or dead code.",
            "recommended_fix": "Remove unused variables, or prefix intentional unused loop variables with an underscore `_`.",
            "corrected_code_example": "# Clean variable usage:\nfor _ in range(retry_count):\n    attempt_connection()",
            "best_practice": "Regularly remove dead code and unused variables. Use linters (flake8, ruff) in local development and CI/CD pipelines.",
            "references": [
                "PEP 8 - Style Guide for Python Code",
                "Flake8 / Ruff Linter Rules"
            ]
        }

    def _remediate_unused_import(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Unused import statements clutter module namespaces, increase startup overhead, and create unnecessary package dependencies.",
            "recommended_fix": "Remove unused import statements from the top of the file.",
            "corrected_code_example": "# Clean module import header:\nimport os\n# Removed unused module imports",
            "best_practice": "Keep module imports clean and minimal. Use automated tools like autoflake, ruff, or black to automatically prune unused imports.",
            "references": [
                "PEP 8 - Imports section",
                "Ruff / Autoflake Linters"
            ]
        }

    def _remediate_magic_number(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Hardcoded numeric literals embedded in logic hide business meaning and make values difficult to update consistently.",
            "recommended_fix": "Replace numeric literals with uppercase named constants at module or class scope.",
            "corrected_code_example": "# Named constants example:\nMAX_RETRY_ATTEMPTS = 5\nTIMEOUT_SECONDS = 30\n\nif attempts > MAX_RETRY_ATTEMPTS:\n    raise TimeoutError('Max retries exceeded')",
            "best_practice": "Define descriptive, UPPERCASE named constants for numbers (other than standard 0, 1) to convey context and intent.",
            "references": [
                "Refactoring by Martin Fowler (Replace Magic Number with Symbolic Constant)",
                "PEP 8 - Constants naming convention"
            ]
        }

    def _remediate_maintainability(self, finding: dict) -> dict:
        return {
            "why_it_is_problematic": "Low maintainability score indicates high cognitive complexity, bloated functions, and accumulated technical debt.",
            "recommended_fix": "Refactor complex methods into smaller modular functions, eliminate dead code, and adhere to clean architecture design.",
            "corrected_code_example": "# Clean, modular class design:\nclass ProductService:\n    def process_order(self, order):\n        self._validate(order)\n        self._save(order)\n        self._notify(order)",
            "best_practice": "Strive for a Maintainability Index >= 75/100 by keeping functions small, reducing nesting, and maintaining high test coverage.",
            "references": [
                "SEI Maintainability Index Standard",
                "Radon Python Metrics Library Documentation"
            ]
        }

    def _default_remediation(self, finding: dict) -> dict:
        issue = finding.get("issue", "Code Quality / Security Issue")
        explanation = finding.get("explanation", "Potential code quality or security vulnerability detected.")
        return {
            "why_it_is_problematic": f"The issue '{issue}' introduces potential security or maintainability risks: {explanation}",
            "recommended_fix": "Refactor the affected code block according to secure coding standards and PEP 8 guidelines.",
            "corrected_code_example": "# Refactored code snippet:\n# Review and refactor code to adhere to secure coding guidelines.",
            "best_practice": "Follow established Python security standards and best practices (OWASP Top 10, PEP 8).",
            "references": [
                "OWASP Top 10 Security Guidelines",
                "PEP 8 - Style Guide for Python Code",
                "Python Official Documentation"
            ]
        }
