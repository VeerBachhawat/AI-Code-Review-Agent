import json
import re
import logging
from typing import List, Dict, Any, Union

try:
    from llm.grok_client import get_grok_client
except ImportError:
    try:
        from backend.llm.grok_client import get_grok_client
    except ImportError:
        get_grok_client = None

logger = logging.getLogger(__name__)


class RemediationAgent:
    """
    Remediation Agent that receives findings from CodeAnalysisAgent and SecurityAgent
    and produces structured, beginner-friendly remediation guidance and secure code examples.
    Uses xAI Grok for dynamic, contextual remediations with automatic fallback to rule-based templates.
    """

    def __init__(self):
        # Register mapping-based rules (Pattern -> Handler) for rule-based fallback
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

    def generate_remediation(self, findings: Union[str, List[Dict[str, Any]]], source_code: str = "") -> List[Dict[str, Any]]:
        """
        Receives a list (or JSON string) of findings and optional source_code string,
        and returns structured remediation guidance for each using Grok LLM (with fallback to rules).
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
                remediations.append(self._process_finding(finding, source_code=source_code))

        return remediations

    def remediate(self, findings, source_code: str = "") -> List[Dict[str, Any]]:
        """Alias for generate_remediation for orchestrator compatibility."""
        return self.generate_remediation(findings, source_code=source_code)

    def analyze(self, findings, source_code: str = "") -> List[Dict[str, Any]]:
        """Alias for generate_remediation for orchestrator compatibility."""
        return self.generate_remediation(findings, source_code=source_code)

    def _enrich_finding_with_code(self, finding: dict, source_code: str = "") -> dict:
        f_copy = dict(finding)
        raw_line = f_copy.get("line", 1)

        lines = source_code.split("\n") if source_code else []
        total_lines = len(lines)

        if not isinstance(raw_line, int) or raw_line <= 0:
            line_no = 1 if total_lines > 0 else 0
        else:
            line_no = raw_line

        if total_lines > 0 and line_no > total_lines:
            line_no = total_lines

        f_copy["line"] = line_no

        if total_lines > 0 and 1 <= line_no <= total_lines:
            exact_line = lines[line_no - 1]
            prev_line = lines[line_no - 2] if line_no > 1 else ""
            next_line = lines[line_no] if line_no < total_lines else ""

            snippet_parts = []
            if prev_line:
                snippet_parts.append(f"Line {line_no - 1:3d} | {prev_line}")
            snippet_parts.append(f"Line {line_no:3d} | {exact_line}  <-- OFFENDING LINE ({f_copy.get('issue', 'Issue')})")
            if next_line:
                snippet_parts.append(f"Line {line_no + 1:3d} | {next_line}")

            f_copy["exact_source_line"] = exact_line
            f_copy["previous_line"] = prev_line
            f_copy["next_line"] = next_line
            f_copy["offending_code_snippet"] = "\n".join(snippet_parts)
        else:
            f_copy["exact_source_line"] = ""
            f_copy["previous_line"] = ""
            f_copy["next_line"] = ""
            f_copy["offending_code_snippet"] = ""

        return f_copy

    def _process_finding(self, finding: dict, source_code: str = "") -> dict:
        issue_text = finding.get("issue", "")
        explanation_text = finding.get("explanation", "")

        enriched = self._enrich_finding_with_code(finding, source_code)

        # 1. Attempt Grok LLM Remediation
        try:
            details = self._grok_remediate(enriched, source_code=source_code)
        except Exception as e:
            logger.warning(f"Grok LLM remediation failed ({str(e)}). Falling back to rule-based templates.")
            combined_text = f"{issue_text} {explanation_text}"
            handler = self._find_handler(combined_text)
            details = handler(enriched)

        return {
            "issue": issue_text,
            "severity": finding.get("severity", "Low"),
            "line": enriched.get("line", 1),
            "exact_source_line": enriched.get("exact_source_line", ""),
            "previous_line": enriched.get("previous_line", ""),
            "next_line": enriched.get("next_line", ""),
            "offending_code_snippet": enriched.get("offending_code_snippet", ""),
            "why_it_is_problematic": details["why_it_is_problematic"],
            "recommended_fix": details["recommended_fix"],
            "corrected_code_example": details["corrected_code_example"],
            "best_practice": details["best_practice"],
            "references": details["references"]
        }

    def _grok_remediate(self, finding: dict, source_code: str = "") -> dict:
        """
        Calls xAI Grok LLM to generate clear, mentor-style remediation guidance.
        """
        if get_grok_client is None:
            raise RuntimeError("Grok client module unavailable.")

        client = get_grok_client()

        issue_text = finding.get("issue", "")
        explanation_text = finding.get("explanation", "")
        severity = finding.get("severity", "Medium")
        line = finding.get("line", 1)

        code_lines = source_code.split("\n") if source_code else []
        numbered_code = "\n".join([f"{i+1:3d} | {l}" for i, l in enumerate(code_lines)]) if source_code else "None provided."

        snippet = finding.get("offending_code_snippet", "")
        exact_line = finding.get("exact_source_line", "")
        current_display = exact_line if exact_line else "# Offending source line"

        prompt = f"""You are a friendly senior software engineer and mentor reviewing code submitted by a student or junior developer.

CRITICAL REQUIREMENT:
DO NOT output generic placeholders such as `# Fixed python snippet`, `# Example code line`, `# Refactored secure implementation`, or generic placeholders.
When providing 'corrected_code_example', output the REAL, fully working code replacement for the exact source line below.

Finding Details:
- Issue: {issue_text}
- Severity: {severity}
- Line Number: {line}
- Explanation: {explanation_text}

Submitted Source Code Context:
```python
{numbered_code}
```

Offending Code Snippet Window:
```python
{snippet}
```

Exact Source Line (Line {line}):
`{exact_line}`

Please structure your response fields carefully:

1. "why_it_is_problematic": Formatted markdown containing:
## Problem
[Explain the issue in ONE simple sentence]

## Why it Matters
[Explain why this issue is dangerous or bad practice using simple English]

## Severity
[Explain in plain terms why this issue is rated as {severity} severity]

2. "recommended_fix": Formatted markdown containing:
## How to Fix
[Provide clear, step-by-step instructions on how to solve the issue]

3. "corrected_code_example": Formatted code containing:
## Corrected Code
Current Code (Line {line}):
```python
{current_display}
```
↓
Improved Code:
```python
[Actual corrected line or snippet for this finding]
```

4. "best_practice": Formatted markdown containing:
## Best Practice
[State the recommended rule or best practice developers should remember]

5. "references": Array of strings with relevant OWASP, CWE, or official documentation links.

Return ONLY a valid JSON object matching this exact structure:
{{
  "why_it_is_problematic": "## Problem\\n...\\n\\n## Why it Matters\\n...\\n\\n## Severity\\n...",
  "recommended_fix": "## How to Fix\\nStep 1: ...\\nStep 2: ...",
  "corrected_code_example": "## Corrected Code\\n...",
  "best_practice": "## Best Practice\\n...",
  "references": ["OWASP Top 10 ...", "CWE-...", "Python Documentation"]
}}
"""

        system_prompt = "You are a supportive code reviewer and mentor. NEVER use placeholders. Output valid JSON only."
        result = client.generate_json(prompt=prompt, system_prompt=system_prompt, temperature=0.2)

        required_keys = ["why_it_is_problematic", "recommended_fix", "corrected_code_example", "best_practice", "references"]
        for key in required_keys:
            if key not in result or not result[key]:
                raise ValueError(f"Missing or empty required key '{key}' in LLM response.")

        if not isinstance(result["references"], list):
            result["references"] = [str(result["references"])]

        return result

    def _find_handler(self, text: str):
        for pattern, handler in self._rules:
            if pattern.search(text):
                return handler
        return self._default_remediation

    # --------------------------------------------------------------------------
    # Rule-Based Fallback Handlers (Structured for Students & Mentors, Zero Placeholders)
    # --------------------------------------------------------------------------

    def _remediate_sql_injection(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)

        if "+" in exact:
            parts = exact.split("+")
            query_part = parts[0].strip()
            var_part = parts[-1].strip().rstrip(")")
            fix_line = f"{query_part} %s\", ({var_part},))"
        else:
            fix_line = "cursor.execute('SELECT * FROM users WHERE username = %s', (user_input,))"

        current_display = exact if exact else 'cursor.execute("SELECT * FROM users WHERE name = " + name)'

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "User input is directly combined into a database query string.\n\n"
                "## Why it Matters\n"
                "Attackers can send special characters to manipulate database queries, allowing them to steal passwords, view private user records, or wipe database tables.\n\n"
                "## Severity\n"
                "Critical. SQL Injection can lead to total database compromise and unauthorized data access."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Stop concatenating user input directly into SQL strings.\n"
                "2. Use parameterized queries (%s placeholders) or an ORM like SQLAlchemy."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Never merge dynamic variables directly into SQL queries. Always use parameterized placeholders (%s, ?) or an ORM."
            ),
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "CWE-89: SQL Injection",
                "Python DB-API 2.0 Specification (PEP 249)"
            ]
        }

    def _remediate_xss(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "from markupsafe import escape\nsafe_text = escape(user_input)"
        current_display = exact if exact else "return f'<h1>{user_input}</h1>'"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Untrusted user input is rendered directly on a web page without escaping.\n\n"
                "## Why it Matters\n"
                "Attackers can inject malicious JavaScript code that runs in user browsers, potentially stealing session tokens or redirecting users to phishing sites.\n\n"
                "## Severity\n"
                "High. Cross-Site Scripting (XSS) compromises client-side browser security."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Sanitize dynamic variables before inserting them into HTML.\n"
                "2. Avoid using functions like mark_safe() on unvalidated user text."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Always escape dynamic user input before rendering it in web browsers."
            ),
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "CWE-79: Cross-Site Scripting (XSS)",
                "MarkupSafe Library Documentation"
            ]
        }

    def _remediate_broken_auth(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "from passlib.hash import pbkdf2_sha256\nhashed_password = pbkdf2_sha256.hash(raw_password)"
        current_display = exact if exact else "if user.password == input_password:"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Passwords are being handled or compared in plain text.\n\n"
                "## Why it Matters\n"
                "Plaintext passwords can be leaked through log files or database breaches, allowing accounts to be easily taken over.\n\n"
                "## Severity\n"
                "Critical. Insecure password handling compromises user account identity."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Never store raw passwords in database tables or variables.\n"
                "2. Use strong password hashing algorithms like argon2 or passlib (pbkdf2)."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Always store passwords using strong, salted password hashes like Argon2id or PBKDF2."
            ),
            "references": [
                "OWASP Top 10: A07:2021 - Authentication Failures",
                "CWE-256: Unprotected Credentials",
                "PassLib Documentation"
            ]
        }

    def _remediate_broken_access_control(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "@app.delete('/users/{user_id}')\ndef delete_user(user_id: int, current_user: User = Depends(get_current_user)):\n    if not current_user.is_admin:\n        raise HTTPException(status_code=403, detail='Forbidden')\n    db.delete_user(user_id)"
        current_display = exact if exact else "def delete_user(user_id):"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Sensitive operations are accessible without checking user permissions.\n\n"
                "## Why it Matters\n"
                "Regular users can perform administrative actions like deleting data or modifying system settings.\n\n"
                "## Severity\n"
                "High. Missing authorization checks allow unauthorized access to sensitive endpoints."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Add authentication and authorization checks to sensitive functions.\n"
                "2. Verify user roles before completing sensitive operations."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Deny access by default and check permissions explicitly on every endpoint."
            ),
            "references": [
                "OWASP Top 10: A01:2021 - Broken Access Control",
                "CWE-285: Improper Authorization",
                "FastAPI Security Documentation"
            ]
        }

    def _remediate_path_traversal(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "from pathlib import Path\nbase = Path('/uploads').resolve()\ntarget = (base / filename).resolve()\nif not target.is_relative_to(base):\n    raise ValueError('Invalid path')"
        current_display = exact if exact else "open('/uploads/' + filename)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "File paths are built directly using unvalidated user input.\n\n"
                "## Why it Matters\n"
                "Attackers can pass path sequences like '../' to read or overwrite system files outside the intended folder.\n\n"
                "## Severity\n"
                "High. Path traversal can expose internal system files or configuration files."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Sanitize file names using secure tools like werkzeug.utils.secure_filename.\n"
                "2. Use pathlib to check that resolved file paths stay inside your safe folder."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Never trust user-supplied file names directly. Always sanitize names and verify folder boundaries."
            ),
            "references": [
                "OWASP Top 10: A01:2021 - Broken Access Control",
                "CWE-22: Path Traversal",
                "Python pathlib Documentation"
            ]
        }

    def _remediate_command_injection(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "import subprocess\nsubprocess.run(['ping', '-c', '4', host_ip], check=True)"
        current_display = exact if exact else "os.system('ping ' + user_input)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "User input is passed directly into a system shell command.\n\n"
                "## Why it Matters\n"
                "Attackers can inject shell command separators (like ';' or '&&') to execute arbitrary operating system commands.\n\n"
                "## Severity\n"
                "Critical. Command injection grants attackers remote shell access to the host server."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Avoid running shell commands directly.\n"
                "2. If necessary, use subprocess.run with arguments passed as a list and shell=False."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Avoid shell=True when calling operating system processes."
            ),
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "CWE-78: OS Command Injection",
                "Python subprocess Documentation"
            ]
        }

    def _remediate_insecure_deserialization(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "import json\ndata = json.loads(user_json_string)"
        current_display = exact if exact else "pickle.loads(user_data)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Untrusted data is parsed using unsafe serializers like pickle or yaml.load.\n\n"
                "## Why it Matters\n"
                "Unsafe deserializers execute code hidden inside payload objects, leading to arbitrary code execution.\n\n"
                "## Severity\n"
                "Critical. Insecure deserialization can result in full server compromise."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Replace pickle with standard JSON parsing (json.loads).\n"
                "2. Use yaml.safe_load instead of yaml.load."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Use safe serialization formats like JSON instead of pickle for external data."
            ),
            "references": [
                "OWASP Top 10: A08:2021 - Data Integrity Failures",
                "CWE-502: Deserialization of Untrusted Data",
                "Python pickle Security Warning"
            ]
        }

    def _remediate_weak_crypto(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "import hashlib\nsecure_hash = hashlib.sha256(data_bytes).hexdigest()"
        current_display = exact if exact else "hashlib.md5(data)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Outdated cryptographic hash functions like MD5 or SHA-1 are being used.\n\n"
                "## Why it Matters\n"
                "MD5 and SHA-1 have known security flaws that allow attackers to forge hash values.\n\n"
                "## Severity\n"
                "Medium. Weak cryptography degrades data verification confidence."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Replace MD5 and SHA-1 with modern hash algorithms like SHA-256."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Use SHA-256 or SHA-512 for cryptographic hashing."
            ),
            "references": [
                "OWASP Top 10: A02:2021 - Cryptographic Failures",
                "CWE-327: Risky Cryptographic Algorithm",
                "Python hashlib Documentation"
            ]
        }

    def _remediate_sensitive_info(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)

        if "=" in exact:
            var_name = exact.split("=")[0].strip()
            fix_line = f"import os\n{var_name} = os.getenv('{var_name.upper()}')"
        else:
            fix_line = "import os\nAPI_KEY = os.getenv('API_KEY')"

        current_display = exact if exact else 'API_KEY = "secret_key_12345"'

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "API keys, passwords, or secret tokens are hardcoded in the source file.\n\n"
                "## Why it Matters\n"
                "Anyone with access to the code repository can steal credentials and access cloud services.\n\n"
                "## Severity\n"
                "High. Exposing secret keys leads to unauthorized service access and cloud abuse."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Move secrets out of source code files.\n"
                "2. Load secrets dynamically using environment variables or a .env file."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Keep secrets in environment variables and add .env to .gitignore."
            ),
            "references": [
                "OWASP Top 10: A02:2021 - Cryptographic Failures",
                "CWE-798: Hardcoded Credentials",
                "Python os Module Documentation"
            ]
        }

    def _remediate_ssrf(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "from urllib.parse import urlparse\nimport requests\nparsed = urlparse(target_url)\nif parsed.hostname not in {'api.trusted.com'}:\n    raise ValueError('Domain not allowed')\nres = requests.get(target_url, timeout=5.0)"
        current_display = exact if exact else "requests.get(user_url)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "HTTP requests are sent directly to user-supplied URLs without domain checks.\n\n"
                "## Why it Matters\n"
                "Attackers can force the server to connect to internal services or metadata services (like 169.254.169.254).\n\n"
                "## Severity\n"
                "High. SSRF allows attackers to probe internal cloud networks."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Validate destination hostnames against a list of approved domains.\n"
                "2. Block connections to internal IP addresses (like 127.0.0.1 or 10.0.0.0/8)."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Validate target hostnames against an explicit allowlist before sending HTTP requests."
            ),
            "references": [
                "OWASP Top 10: A10:2021 - SSRF",
                "CWE-918: Server-Side Request Forgery",
                "Python urllib.parse Documentation"
            ]
        }

    def _remediate_eval_exec(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)

        if "eval(" in exact:
            fix_line = exact.replace("eval(", "ast.literal_eval(")
        elif "exec(" in exact:
            fix_line = exact.replace("exec(", "ast.literal_eval(")
        else:
            fix_line = "import ast\nsafe_data = ast.literal_eval(user_input_string)"

        current_display = exact if exact else "eval(user_input)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "The code uses eval() or exec() to evaluate arbitrary text strings.\n\n"
                "## Why it Matters\n"
                "eval() runs any Python code passed to it. If user input reaches eval(), attackers get full Remote Code Execution.\n\n"
                "## Severity\n"
                "Critical. Dynamic code evaluation allows immediate arbitrary code execution."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Remove eval() and exec() from your code.\n"
                "2. Use ast.literal_eval() to parse safe text data like dictionaries or numbers."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Never use eval() on dynamic strings. Use ast.literal_eval() for safe literal parsing."
            ),
            "references": [
                "OWASP Top 10: A03:2021 - Injection",
                "CWE-95: Eval Injection",
                "Python ast.literal_eval Documentation"
            ]
        }

    def _remediate_poor_variables(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "x = len(u)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Variable names are short, vague, or single letters.\n\n"
                "## Why it Matters\n"
                "Unclear names make code difficult to read, understand, and maintain for team members.\n\n"
                "## Severity\n"
                "Low. Poor naming affects code readability and maintainability."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Choose descriptive names that describe the variable's purpose."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\ntotal_users = len(user_list)\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Use meaningful, self-explanatory variable names following Python PEP 8 conventions."
            ),
            "references": [
                "PEP 8 - Naming Conventions",
                "Clean Code Guidelines"
            ]
        }

    def _remediate_too_many_parameters(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        fix_line = "@dataclass\nclass FilterOptions:\n    category: str\n    price: float"
        current_display = exact if exact else "def search(a, b, c, d, e, f):"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "A function takes too many individual parameters.\n\n"
                "## Why it Matters\n"
                "Functions with long parameter lists are confusing to call and hard to test.\n\n"
                "## Severity\n"
                "Low. Excessive parameters reduce code maintainability."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Group related parameters into a dataclass or dictionary."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n{fix_line}\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Keep function parameters under 4 arguments by bundling related options into objects."
            ),
            "references": [
                "Refactoring: Introduce Parameter Object",
                "Clean Code - Functions"
            ]
        }

    def _remediate_large_class(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "class SystemManager:"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "A class contains too many methods and responsibilities.\n\n"
                "## Why it Matters\n"
                "Large classes are difficult to test and maintain because they handle too many jobs at once.\n\n"
                "## Severity\n"
                "Medium. Large classes violate clean design principles."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Split the class into smaller, single-purpose classes."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\nclass UserValidator:\n    def validate(self, user): pass\nclass UserRepository:\n    def save(self, user): pass\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Follow the Single Responsibility Principle: each class should do one thing well."
            ),
            "references": [
                "SOLID Principles: Single Responsibility",
                "Refactoring: Extract Class"
            ]
        }

    def _remediate_cyclomatic_complexity(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "if a: if b: if c:"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "A function has too many nested conditional paths (if/elif/else).\n\n"
                "## Why it Matters\n"
                "Complex decision trees make code hard to read and increase the likelihood of bugs.\n\n"
                "## Severity\n"
                "Medium. High complexity makes testing difficult."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Use early returns (guard clauses) to handle edge cases first.\n"
                "2. Break complex logic into smaller helper functions."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\nif not order.is_valid:\n    return False\nreturn execute(order)\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Keep function decision complexity low by returning early with guard clauses."
            ),
            "references": [
                "McCabe Cyclomatic Complexity",
                "Refactoring: Replace Nested Conditionals with Guard Clauses"
            ]
        }

    def _remediate_long_methods(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "def process_all():"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "A function is too long and performs multiple tasks.\n\n"
                "## Why it Matters\n"
                "Long functions are hard to comprehend and reuse across the codebase.\n\n"
                "## Severity\n"
                "Low. Long methods reduce maintainability."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Extract distinct steps into smaller helper functions."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\ndef handle_request(request):\n    data = parse_request(request)\n    return process_data(data)\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Keep functions short and focused on a single step."
            ),
            "references": [
                "Refactoring: Extract Function",
                "Clean Code Guidelines"
            ]
        }

    def _remediate_deep_nesting(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "for i in list: if i: if i.valid:"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Control flow blocks are nested too deeply (3+ levels).\n\n"
                "## Why it Matters\n"
                "Deep indentation makes code hard to follow and hides edge cases.\n\n"
                "## Severity\n"
                "Low. Deep nesting increases cognitive complexity."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Use guard clauses with 'continue' or 'return' to flatten nesting."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\nfor item in items:\n    if not item.is_valid:\n        continue\n    process_item(item)\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Keep control flow flat. 'Flat is better than nested' (Zen of Python)."
            ),
            "references": [
                "PEP 20 - The Zen of Python",
                "Clean Code Refactoring"
            ]
        }

    def _remediate_duplicate_code(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "total1 = p1 * (1 + tax)\ntotal2 = p2 * (1 + tax)"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Identical code blocks are repeated in multiple places.\n\n"
                "## Why it Matters\n"
                "If you fix a bug in one copy, you might forget to update the other copies.\n\n"
                "## Severity\n"
                "Low. Duplicate code increases maintenance effort."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Move the shared code into a reusable helper function."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\ndef calculate_total(price, tax):\n    return price * (1 + tax)\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Follow the DRY (Don't Repeat Yourself) principle."
            ),
            "references": [
                "Pragmatic Programmer: DRY Principle",
                "Refactoring Guidelines"
            ]
        }

    def _remediate_unused_variable(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "unused_var = 10"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "A variable is created but never used in code.\n\n"
                "## Why it Matters\n"
                "Unused variables create confusion and clutter."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Remove the unused variable or prefix loop variables with '_'."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\nfor _ in range(5):\n    do_something()\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Clean up unused variables and dead code."
            ),
            "references": [
                "PEP 8 Guidelines",
                "Python Linters"
            ]
        }

    def _remediate_unused_import(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "import unused_module"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "An import statement is declared but never used in the file.\n\n"
                "## Why it Matters\n"
                "Unused imports slow down module loading and clutter code headers."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Remove unused import lines."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n# Clean header imports\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Keep module imports clean and minimal."
            ),
            "references": [
                "PEP 8 Imports Guide",
                "Flake8 / Ruff Linters"
            ]
        }

    def _remediate_magic_number(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "if attempts > 3:"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Raw numbers are hardcoded directly inside business logic.\n\n"
                "## Why it Matters\n"
                "Raw numbers hide meaning and are difficult to update across multiple files."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Define UPPERCASE named constants at the top of the file."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\nMAX_ATTEMPTS = 3\nif attempts > MAX_ATTEMPTS:\n    pass\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Use named constants for raw numeric values."
            ),
            "references": [
                "Refactoring: Replace Magic Number with Constant",
                "PEP 8 Style Guide"
            ]
        }

    def _remediate_maintainability(self, finding: dict) -> dict:
        exact = finding.get("exact_source_line", "").strip()
        line = finding.get("line", 1)
        current_display = exact if exact else "def complex_func(): pass"

        return {
            "why_it_is_problematic": (
                "## Problem\n"
                "Code complexity is high and maintainability score is low.\n\n"
                "## Why it Matters\n"
                "Complex code accumulates technical debt and makes future changes risky."
            ),
            "recommended_fix": (
                "## How to Fix\n"
                "1. Break complex methods into simple, modular functions."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\ndef process(item):\n    validate(item)\n    save(item)\n```"
            ),
            "best_practice": (
                "## Best Practice\n"
                "Maintain clean modular structure and low complexity."
            ),
            "references": [
                "Maintainability Index Standard",
                "Clean Code Principles"
            ]
        }

    def _default_remediation(self, finding: dict) -> dict:
        issue = finding.get("issue", "Code Issue")
        severity = finding.get("severity", "Low")
        line = finding.get("line", 1)
        exact = finding.get("exact_source_line", "").strip()
        current_display = exact if exact else "pass"

        return {
            "why_it_is_problematic": (
                f"## Problem\n{issue}\n\n"
                f"## Why it Matters\nThis issue introduces potential maintainability or security concerns.\n\n"
                f"## Severity\n{severity} severity issue."
            ),
            "recommended_fix": (
                "## How to Fix\nReview the flagged code block and apply standard refactoring guidelines."
            ),
            "corrected_code_example": (
                f"## Corrected Code\n"
                f"Current Code (Line {line}):\n```python\n{current_display}\n```\n↓\n"
                f"Improved Code:\n```python\n# Clean refactored implementation\n```"
            ),
            "best_practice": "## Best Practice\nFollow PEP 8 guidelines and secure coding standards.",
            "references": [
                "OWASP Security Guidelines",
                "PEP 8 Style Guide"
            ]
        }
