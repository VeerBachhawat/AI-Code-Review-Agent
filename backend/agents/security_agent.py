import ast
import re
from typing import List, Dict, Any


class SecurityAgent:

    def analyze(self, code: str) -> List[Dict[str, Any]]:
        findings = []

        # 1. Attempt Python AST parsing if applicable
        try:
            tree = ast.parse(code)
            findings.extend(self._detect_eval_and_exec(tree))
            findings.extend(self._detect_hardcoded_secrets(tree))
            findings.extend(self._detect_sql_injection(tree))
            findings.extend(self._detect_xss(tree))
            findings.extend(self._detect_broken_auth(tree))
            findings.extend(self._detect_broken_access_control(tree))
            findings.extend(self._detect_path_traversal(tree))
            findings.extend(self._detect_command_injection(tree))
            findings.extend(self._detect_insecure_deserialization(tree))
            findings.extend(self._detect_weak_cryptography(tree))
            findings.extend(self._detect_ssrf(tree))
        except SyntaxError:
            pass

        # 2. Run Multi-Language Pattern Detectors (Java, JS, C++, Go, PHP, Python)
        pattern_findings = self._detect_pattern_security_vulnerabilities(code)
        findings.extend(pattern_findings)

        # Standardize and deduplicate findings
        unique_findings = []
        seen = set()
        for idx, finding in enumerate(findings, start=1):
            key = (finding.get("line", 1), finding.get("issue", ""))
            if key not in seen:
                seen.add(key)
                item = dict(finding)
                item.setdefault("id", f"sec_{idx}")
                item.setdefault("title", item.get("issue", "Security Vulnerability"))
                item.setdefault("category", "Security")
                item.setdefault("agent", "SecurityAgent")
                item.setdefault("severity", "High")
                item.setdefault("confidence", 0.95)
                item.setdefault("line", 1)
                item.setdefault("references", ["OWASP Top 10 Security Guidance"])
                unique_findings.append(item)

        return unique_findings

    def _detect_pattern_security_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code.split("\n")

        for i, line in enumerate(lines, start=1):
            line_str = line.strip()

            # --- 1. SQL Injection ---
            if (
                ("Statement" in line_str and "conn.createStatement" in line_str) or
                ("executeQuery(" in line_str and "+" in line_str) or
                ("executeUpdate(" in line_str and "+" in line_str) or
                (re.search(r'SELECT\s+.*FROM\s+.*\+', line_str, re.IGNORECASE)) or
                (re.search(r'INSERT\s+INTO\s+.*\+', line_str, re.IGNORECASE)) or
                (re.search(r'UPDATE\s+.*SET\s+.*\+', line_str, re.IGNORECASE)) or
                (re.search(r'DELETE\s+FROM\s+.*\+', line_str, re.IGNORECASE))
            ):
                findings.append({
                    "id": f"sec_sqli_{i}",
                    "title": "SQL Injection Vulnerability",
                    "issue": "SQL Injection",
                    "category": "Security",
                    "agent": "SecurityAgent",
                    "severity": "Critical",
                    "confidence": 0.95,
                    "line": i,
                    "explanation": f"SQL query string dynamically concatenated on line {i}. Attackers can alter query logic to bypass authentication or extract sensitive data.",
                    "why_it_matters": "SQL injection permits unauthorized database queries, data leakage, data destruction, or complete database administrative override.",
                    "recommendation": "Use parameterized queries (e.g. PreparedStatement in Java, parameterized tuples in Python/Node) instead of string concatenation.",
                    "secure_code": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE username = ?\");\nps.setString(1, username);",
                    "references": ["OWASP Top 10: A03:2021 - Injection", "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]
                })

            # --- 2. Command Injection ---
            if (
                "Runtime.getRuntime().exec(" in line_str or
                "ProcessBuilder(" in line_str or
                ("exec(" in line_str and "child_process" in line_str) or
                "execSync(" in line_str or
                re.search(r'system\s*\(\s*["\'].*\+', line_str)
            ):
                findings.append({
                    "id": f"sec_cmdi_{i}",
                    "title": "Command Injection Risk",
                    "issue": "Command Injection",
                    "category": "Security",
                    "agent": "SecurityAgent",
                    "severity": "Critical",
                    "confidence": 0.95,
                    "line": i,
                    "explanation": f"Executing operating system commands dynamically on line {i} exposes the application to Command Injection.",
                    "why_it_matters": "Attackers can supply command separators (e.g., ';' or '&&') to execute arbitrary operating system commands with server privileges.",
                    "recommendation": "Avoid direct system command calls or pass strictly validated argument lists without subshell invocation.",
                    "secure_code": "ProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"4\", safeHost);\nProcess p = pb.start();",
                    "references": ["OWASP Top 10: A03:2021 - Injection", "CWE-78: OS Command Injection"]
                })

            # --- 3. Unsafe Deserialization ---
            if (
                "ObjectInputStream" in line_str and "readObject" in line_str or
                "XMLDecoder" in line_str or
                "unserialize(" in line_str
            ):
                findings.append({
                    "id": f"sec_deser_{i}",
                    "title": "Unsafe Object Deserialization",
                    "issue": "Unsafe Deserialization",
                    "category": "Security",
                    "agent": "SecurityAgent",
                    "severity": "Critical",
                    "confidence": 0.95,
                    "line": i,
                    "explanation": f"Unsafe object deserialization detected on line {i}. Deserializing untrusted binary streams allows Remote Code Execution (RCE).",
                    "why_it_matters": "Malicious serialized payloads execute object constructor/readObject methods automatically upon deserialization.",
                    "recommendation": "Use safe data exchange formats like JSON/Protocol Buffers or implement object filtering (e.g. ValidatingObjectInputStream).",
                    "secure_code": "ObjectMapper mapper = new ObjectMapper();\nMyClass obj = mapper.readValue(jsonString, MyClass.class);",
                    "references": ["OWASP Top 10: A08:2021 - Software and Data Integrity Failures", "CWE-502: Deserialization of Untrusted Data"]
                })

            # --- 4. Hardcoded Credentials / Passwords ---
            if (
                re.search(r'(DB_PASSWORD|DB_PASS|PASSWORD|SECRET_KEY|API_KEY|AUTH_TOKEN)\s*=\s*["\'][^"\']+["\']', line_str, re.IGNORECASE) or
                re.search(r'private\s+static\s+final\s+String\s+.*PASSWORD.*\s*=\s*["\'][^"\']+["\']', line_str, re.IGNORECASE)
            ):
                findings.append({
                    "id": f"sec_secret_{i}",
                    "title": "Hardcoded Credential Exposure",
                    "issue": "Hardcoded Database Credentials",
                    "category": "Security",
                    "agent": "SecurityAgent",
                    "severity": "High",
                    "confidence": 0.90,
                    "line": i,
                    "explanation": f"Hardcoded password or secret key detected on line {i}. Credentials should never be embedded in source code.",
                    "why_it_matters": "Source code repository leaks expose credentials to all developers, CI/CD systems, and potential external breach vectors.",
                    "recommendation": "Fetch credentials at runtime from environment variables or a secure key management system.",
                    "secure_code": "String dbPassword = System.getenv(\"DB_PASSWORD\");",
                    "references": ["OWASP Top 10: A07:2021 - Identification and Authentication Failures", "CWE-798: Use of Hard-coded Credentials"]
                })

            # --- 5. Path Traversal ---
            if (
                re.search(r'new\s+File\s*\([^)]*\+', line_str) or
                re.search(r'new\s+FileInputStream\s*\([^)]*\+', line_str) or
                re.search(r'Paths\.get\s*\([^)]*\+', line_str)
            ):
                findings.append({
                    "id": f"sec_path_{i}",
                    "title": "Path Traversal Vulnerability",
                    "issue": "Path Traversal",
                    "category": "Security",
                    "agent": "SecurityAgent",
                    "severity": "High",
                    "confidence": 0.90,
                    "line": i,
                    "explanation": f"Dynamic file path construction detected on line {i} using unvalidated parameters.",
                    "why_it_matters": "Attackers can inject directory traversal sequences ('../') to read or overwrite system files outside the target directory.",
                    "recommendation": "Normalize paths and verify target files stay strictly within permitted base directories.",
                    "secure_code": "Path basePath = Paths.get(\"/safe/dir\");\nPath targetPath = basePath.resolve(userInput).normalize();\nif (!targetPath.startsWith(basePath)) throw new SecurityException();",
                    "references": ["OWASP Top 10: A01:2021 - Broken Access Control", "CWE-22: Path Traversal"]
                })

            # --- 6. Insecure Cryptography / Weak Random ---
            if (
                re.search(r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1)["\']\)', line_str, re.IGNORECASE) or
                re.search(r'Cipher\.getInstance\s*\(\s*["\']DES["\']\)', line_str, re.IGNORECASE) or
                re.search(r'new\s+Random\s*\(', line_str)
            ):
                findings.append({
                    "id": f"sec_crypto_{i}",
                    "title": "Insecure Cryptography / Weak Randomness",
                    "issue": "Weak Cryptography",
                    "category": "Security",
                    "agent": "SecurityAgent",
                    "severity": "Medium",
                    "confidence": 0.85,
                    "line": i,
                    "explanation": f"Insecure cryptographic algorithm or pseudo-random generator on line {i}.",
                    "why_it_matters": "Weak algorithms (MD5, SHA-1, DES) or java.util.Random are vulnerable to collision attacks and predictability in security tokens.",
                    "recommendation": "Use SHA-256/SHA-512 for hashes and java.security.SecureRandom for cryptographic token generation.",
                    "secure_code": "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\nSecureRandom random = new SecureRandom();",
                    "references": ["OWASP Top 10: A02:2021 - Cryptographic Failures", "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"]
                })

        return findings

    # --------------------------------------------------------------------------
    # Detection Rules Implementation
    # --------------------------------------------------------------------------

    def _detect_eval_and_exec(self, tree):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec"):
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": f"Use of {node.func.id}()",
                        "explanation": f"The dynamic code execution function '{node.func.id}()' evaluates arbitrary strings as code, leading to arbitrary code execution.",
                        "line": getattr(node, "lineno", 0)
                    })
        return findings

    def _detect_hardcoded_secrets(self, tree):
        findings = []
        secret_keywords = {
            "password", "secret", "api_key", "apikey", "token", "bearer",
            "access_token", "auth_token", "aws_key", "aws_secret", "private_key",
            "jwt_secret", "client_secret"
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(kw in name for kw in secret_keywords):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                val = node.value.value
                                if val and not val.startswith("ENV") and val not in ("placeholder", "your_key_here"):
                                    findings.append({
                                        "agent": "Security",
                                        "severity": "High",
                                        "issue": f"Hardcoded credential: {target.id}",
                                        "explanation": f"Hardcoded secret or credential stored in variable '{target.id}'. Move sensitive values to environment variables or key vaults.",
                                        "line": getattr(node, "lineno", 0)
                                    })

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if "-----BEGIN PRIVATE KEY-----" in s or "-----BEGIN RSA PRIVATE KEY-----" in s:
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": "Hardcoded Private Key exposed",
                        "explanation": "Hardcoded private key found in source code. Store private keys in a secure secret store.",
                        "line": getattr(node, "lineno", 0)
                    })
                elif re.search(r"AKIA[0-9A-Z]{16}", s):
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": "Hardcoded AWS Access Key exposed",
                        "explanation": "AWS Access Key ID hardcoded in source code. Store AWS credentials in IAM roles or environment variables.",
                        "line": getattr(node, "lineno", 0)
                    })

        return findings

    def _contains_sql_keywords(self, text: str) -> bool:
        upper = text.upper()
        sql_patterns = ["SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM", "DROP TABLE", "ALTER TABLE", "CREATE TABLE", "TRUNCATE "]
        return any(kw in upper for kw in sql_patterns)

    def _detect_sql_injection(self, tree):
        findings = []

        def check_expression(expr, lineno):
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                if self._is_sql_expr(expr):
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": "SQL Injection Vulnerability",
                        "explanation": "SQL query is constructed using string concatenation. Use parameterized queries (e.g., cursor.execute('SELECT * FROM t WHERE id = %s', (id,))) to prevent SQL injection.",
                        "line": lineno
                    })
            elif isinstance(expr, ast.JoinedStr):
                if any(isinstance(val, ast.Constant) and isinstance(val.value, str) and self._contains_sql_keywords(val.value) for val in expr.values):
                    if any(isinstance(val, ast.FormattedValue) for val in expr.values):
                        findings.append({
                            "agent": "Security",
                            "severity": "Critical",
                            "issue": "SQL Injection Vulnerability",
                            "explanation": "SQL query is constructed using an f-string with dynamic variables. Use parameterized queries instead.",
                            "line": lineno
                        })
            elif isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                if isinstance(expr.func.value, ast.Constant) and isinstance(expr.func.value.value, str):
                    if self._contains_sql_keywords(expr.func.value.value):
                        findings.append({
                            "agent": "Security",
                            "severity": "Critical",
                            "issue": "SQL Injection Vulnerability",
                            "explanation": "SQL query constructed using .format(). Use parameterized queries to prevent SQL injection.",
                            "line": lineno
                        })
            elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
                if isinstance(expr.left, ast.Constant) and isinstance(expr.left.value, str):
                    if self._contains_sql_keywords(expr.left.value):
                        findings.append({
                            "agent": "Security",
                            "severity": "Critical",
                            "issue": "SQL Injection Vulnerability",
                            "explanation": "SQL query constructed using '%' formatting. Use parameterized queries to prevent SQL injection.",
                            "line": lineno
                        })

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 0)
            check_expression(node, lineno)

            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("execute", "executemany"):
                    if node.args:
                        query_arg = node.args[0]
                        if isinstance(query_arg, (ast.BinOp, ast.JoinedStr)) or (isinstance(query_arg, ast.Call) and getattr(query_arg.func, "attr", None) == "format"):
                            findings.append({
                                "agent": "Security",
                                "severity": "Critical",
                                "issue": "SQL Injection in execute() call",
                                "explanation": "Dynamic query argument passed to execute(). Pass query parameters as a tuple/list in the second argument instead.",
                                "line": lineno
                            })
                        elif len(node.args) == 1 and isinstance(query_arg, ast.Name):
                            findings.append({
                                "agent": "Security",
                                "severity": "High",
                                "issue": "Potential SQL Injection in execute() call",
                                "explanation": "Query variable passed to execute() without parameter tuple. Ensure the query is parameterized.",
                                "line": lineno
                            })

        return findings

    def _is_sql_expr(self, expr) -> bool:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return self._contains_sql_keywords(expr.value)
        elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self._is_sql_expr(expr.left) or self._is_sql_expr(expr.right)
        return False

    def _detect_xss(self, tree):
        findings = []

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 0)
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name == "mark_safe":
                    findings.append({
                        "agent": "Security",
                        "severity": "High",
                        "issue": "Cross-Site Scripting (XSS) via mark_safe()",
                        "explanation": "mark_safe() explicitly disables automatic HTML escaping. Ensure dynamic input is sanitized before marking it safe.",
                        "line": lineno
                    })
                elif func_name == "render_template_string":
                    findings.append({
                        "agent": "Security",
                        "severity": "High",
                        "issue": "Cross-Site Scripting (XSS) / Server-Side Template Injection",
                        "explanation": "render_template_string() renders dynamic templates from strings. Passing unsanitized user input allows SSTI and XSS.",
                        "line": lineno
                    })
                elif func_name in ("HttpResponse", "HTMLResponse", "Response"):
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, (ast.BinOp, ast.JoinedStr)) or (isinstance(first_arg, ast.Call) and getattr(first_arg.func, "attr", None) == "format"):
                            findings.append({
                                "agent": "Security",
                                "severity": "High",
                                "issue": "Cross-Site Scripting (XSS) in HTML Response",
                                "explanation": "Dynamically formatted content returned in HTML response without escaping. Use template engines with auto-escaping enabled.",
                                "line": lineno
                            })

        return findings

    def _detect_broken_auth(self, tree):
        findings = []

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 0)

            if isinstance(node, ast.Compare):
                left_name = self._get_node_name(node.left).lower()
                for comparator in node.comparators:
                    right_name = self._get_node_name(comparator).lower()

                    if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                        if any(kw in left_name for kw in ("password", "pass", "secret", "token")):
                            findings.append({
                                "agent": "Security",
                                "severity": "High",
                                "issue": "Hardcoded Authentication Logic",
                                "explanation": "Hardcoded credential comparison detected. Use a secure database lookup and password hashing verification.",
                                "line": lineno
                            })
                    elif isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                        if any(kw in right_name for kw in ("password", "pass", "secret", "token")):
                            findings.append({
                                "agent": "Security",
                                "severity": "High",
                                "issue": "Hardcoded Authentication Logic",
                                "explanation": "Hardcoded credential comparison detected. Use a secure database lookup and password hashing verification.",
                                "line": lineno
                            })
                    elif any(kw in left_name for kw in ("password", "pass")) and any(kw in right_name for kw in ("password", "pass")):
                        findings.append({
                            "agent": "Security",
                            "severity": "High",
                            "issue": "Plaintext Password Comparison",
                            "explanation": "Comparing passwords in plaintext. Use secure password hash verification (e.g. passlib, bcrypt.checkpw).",
                            "line": lineno
                        })

            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name = self._get_node_name(target).lower()
                    if "password" in target_name and not target_name.endswith("_hash"):
                        val_name = self._get_node_name(node.value).lower()
                        if "password" in val_name or isinstance(node.value, ast.Name):
                            findings.append({
                                "agent": "Security",
                                "severity": "High",
                                "issue": "Insecure Password Storage / Missing Password Hashing",
                                "explanation": "Assigning password without hash function. Hash passwords using bcrypt or Argon2 before storage.",
                                "line": lineno
                            })

        return findings

    def _get_node_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_node_name(node.value)}.{node.attr}"
        return ""

    def _detect_broken_access_control(self, tree):
        findings = []
        sensitive_func_keywords = {"delete", "admin", "update_user", "reset_password", "change_role", "export_data", "drop_db"}

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lineno = getattr(node, "lineno", 0)
                func_name = node.name.lower()

                is_route = False
                has_auth_decorator = False

                for dec in node.decorator_list:
                    dec_name = self._get_node_name(dec).lower()
                    if any(r in dec_name for r in ("get", "post", "put", "delete", "route", "patch")):
                        is_route = True
                    if any(a in dec_name for a in ("auth", "login", "permission", "protect", "jwt", "roles")):
                        has_auth_decorator = True

                for arg in node.args.args:
                    if arg.annotation:
                        ann_str = self._get_node_name(arg.annotation).lower()
                        if "user" in ann_str or "auth" in ann_str or "token" in ann_str:
                            has_auth_decorator = True

                if is_route and not has_auth_decorator:
                    if any(kw in func_name for kw in sensitive_func_keywords):
                        findings.append({
                            "agent": "Security",
                            "severity": "High",
                            "issue": f"Missing Access Control on endpoint '{node.name}'",
                            "explanation": f"Endpoint '{node.name}' performs sensitive operations but lacks authentication or authorization checks.",
                            "line": lineno
                        })

        return findings

    def _detect_path_traversal(self, tree):
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 0)
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = f"{self._get_node_name(node.func.value)}.{node.func.attr}"

                target_funcs = {"open", "os.remove", "os.unlink", "os.rmdir", "os.listdir", "shutil.rmtree", "shutil.copy", "shutil.move", "pathlib.Path"}

                if func_name in target_funcs or func_name.startswith("shutil."):
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, (ast.BinOp, ast.JoinedStr)) or (isinstance(first_arg, ast.Call) and getattr(first_arg.func, "attr", None) == "format"):
                            findings.append({
                                "agent": "Security",
                                "severity": "High",
                                "issue": "Path Traversal Vulnerability",
                                "explanation": "File system path constructed dynamically using variable inputs without sanitization (e.g. secure_filename()). This can allow path traversal attacks.",
                                "line": lineno
                            })

        return findings

    def _detect_command_injection(self, tree):
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 0)
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = f"{self._get_node_name(node.func.value)}.{node.func.attr}"

                if func_name in ("os.system", "system"):
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": "Command Injection via os.system()",
                        "explanation": "os.system() executes commands in a subshell, exposing the application to command injection. Use subprocess with shell=False.",
                        "line": lineno
                    })
                elif func_name in ("os.popen", "popen"):
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": "Command Injection via os.popen()",
                        "explanation": "os.popen() executes commands in a shell and returns a file object. Replace with subprocess.run() without shell=True.",
                        "line": lineno
                    })
                elif func_name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "subprocess.check_call"):
                    shell_true = False
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            shell_true = True
                            break

                    if shell_true:
                        findings.append({
                            "agent": "Security",
                            "severity": "Critical",
                            "issue": "subprocess with shell=True",
                            "explanation": "Executing subprocess with shell=True allows shell command injection if inputs are not strictly sanitized.",
                            "line": lineno
                        })
                    elif node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, (ast.BinOp, ast.JoinedStr)) or (isinstance(first_arg, ast.Call) and getattr(first_arg.func, "attr", None) == "format"):
                            findings.append({
                                "agent": "Security",
                                "severity": "High",
                                "issue": "Potential Command Injection in subprocess call",
                                "explanation": "Subprocess command is dynamically constructed as a string. Pass arguments as a list of strings instead.",
                                "line": lineno
                            })

        return findings

    def _detect_insecure_deserialization(self, tree):
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 0)
                func_name = ""
                module_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    module_name = self._get_node_name(node.func.value)

                if module_name in ("pickle", "_pickle", "cPickle") and func_name in ("load", "loads"):
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": f"Insecure Deserialization via {module_name}.{func_name}()",
                        "explanation": f"Deserializing untrusted data using {module_name}.{func_name}() can execute arbitrary Python bytecode.",
                        "line": lineno
                    })
                elif module_name == "marshal" and func_name in ("load", "loads"):
                    findings.append({
                        "agent": "Security",
                        "severity": "Critical",
                        "issue": f"Insecure Deserialization via marshal.{func_name}()",
                        "explanation": "marshal deserialization is unsafe for untrusted input and can lead to arbitrary code execution.",
                        "line": lineno
                    })
                elif module_name == "yaml" and func_name in ("load", "unsafe_load"):
                    has_safe_loader = False
                    if func_name == "load":
                        for kw in node.keywords:
                            if kw.arg == "Loader":
                                loader_str = self._get_node_name(kw.value)
                                if "safeloader" in loader_str.lower() or "fullloader" in loader_str.lower():
                                    has_safe_loader = True
                    if not has_safe_loader:
                        findings.append({
                            "agent": "Security",
                            "severity": "Critical",
                            "issue": "Insecure Deserialization via yaml.load()",
                            "explanation": "yaml.load() without SafeLoader executes arbitrary Python code during parsing. Use yaml.safe_load().",
                            "line": lineno
                        })
                elif module_name == "shelve" and func_name == "open":
                    findings.append({
                        "agent": "Security",
                        "severity": "High",
                        "issue": "Insecure Storage / Deserialization via shelve.open()",
                        "explanation": "shelve uses pickle under the hood for object persistence, making it vulnerable to insecure deserialization.",
                        "line": lineno
                    })

        return findings

    def _detect_weak_cryptography(self, tree):
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 0)
                func_name = ""
                module_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    module_name = self._get_node_name(node.func.value)

                if module_name == "hashlib" and func_name in ("md5", "sha1"):
                    findings.append({
                        "agent": "Security",
                        "severity": "Medium",
                        "issue": f"Weak Cryptographic Hash Algorithm ({func_name.upper()})",
                        "explanation": f"{func_name.upper()} is cryptographically broken and vulnerable to collision attacks. Use SHA256, SHA512, or Argon2/bcrypt.",
                        "line": lineno
                    })
                elif module_name == "hashlib" and func_name == "new":
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        algo = node.args[0].value.lower()
                        if algo in ("md5", "sha1"):
                            findings.append({
                                "agent": "Security",
                                "severity": "Medium",
                                "issue": f"Weak Cryptographic Hash Algorithm ({algo.upper()})",
                                "explanation": f"{algo.upper()} is cryptographically broken and vulnerable to collision attacks. Use SHA256 or SHA512 instead.",
                                "line": lineno
                            })
                elif "hash" in module_name.lower() and func_name.upper() in ("MD5", "SHA1", "SHA"):
                    findings.append({
                        "agent": "Security",
                        "severity": "Medium",
                        "issue": f"Weak Cryptographic Hash Algorithm ({func_name.upper()})",
                        "explanation": f"{func_name.upper()} is cryptographically broken. Recommend using SHA256 or stronger.",
                        "line": lineno
                    })

        return findings

    def _detect_ssrf(self, tree):
        findings = []
        http_libraries = {"requests", "urllib.request", "httpx", "aiohttp", "urllib2"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 0)
                module_name = ""
                func_name = ""

                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    module_name = self._get_node_name(node.func.value)

                if module_name in http_libraries or any(lib in module_name for lib in ("requests", "urllib", "httpx", "aiohttp")):
                    if func_name in ("get", "post", "put", "delete", "patch", "request", "urlopen", "Request"):
                        if node.args:
                            first_arg = node.args[0]
                            if isinstance(first_arg, (ast.BinOp, ast.JoinedStr, ast.Name)) or (isinstance(first_arg, ast.Call) and getattr(first_arg.func, "attr", None) == "format"):
                                findings.append({
                                    "agent": "Security",
                                    "severity": "High",
                                    "issue": "Potential Server-Side Request Forgery (SSRF)",
                                    "explanation": "HTTP request uses a dynamic or user-controlled URL without validation. Restrict target URLs/IPs using an allowlist.",
                                    "line": lineno
                                })

        return findings