import ast
import math
import re
from collections import Counter
from typing import List, Dict, Any


class CodeAnalysisAgent:

    def analyze(self, code: str) -> List[Dict[str, Any]]:
        findings = []

        try:
            tree = ast.parse(code)
            findings.extend(self._detect_bad_variable_names(tree))
            findings.extend(self._detect_long_methods(tree, code))
            findings.extend(self._detect_too_many_parameters(tree))
            findings.extend(self._detect_deep_nesting(tree))
            findings.extend(self._detect_large_classes(tree))
            findings.extend(self._detect_cyclomatic_complexity(tree))
            findings.extend(self._detect_duplicate_code(tree, code))
            findings.extend(self._detect_unused_variables(tree))
            findings.extend(self._detect_unused_imports(tree))
            findings.extend(self._detect_magic_numbers(tree))
            findings.extend(self._calculate_maintainability_score(tree, code))
        except SyntaxError:
            # Non-Python code or syntax error: fallback to line-by-line pattern scanning
            findings.extend(self._detect_pattern_quality_issues(code))

        # Always check for console debug statements across Python, Java, JS, C++, etc.
        console_findings = self._detect_console_statements(code)
        findings.extend(console_findings)

        # Standardize and consolidate repetitive code quality findings
        consolidated = self._consolidate_findings(findings)
        return consolidated

    def _detect_console_statements(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code.split("\n")
        for i, line in enumerate(lines, start=1):
            line_str = line.strip()
            if "System.out.print" in line_str or "System.err.print" in line_str or "console.log(" in line_str or "console.debug(" in line_str:
                findings.append({
                    "id": f"cq_console_{i}",
                    "title": "Console Debug Statement",
                    "issue": "Console Debug Statement",
                    "category": "Code Quality",
                    "agent": "CodeAnalysisAgent",
                    "severity": "Low",
                    "confidence": 0.99,
                    "line": i,
                    "explanation": f"Print or console debug statement on line {i}. Use a structured logging framework (e.g. SLF4J / Logback) instead.",
                    "why_it_matters": "Direct console logging can degrade performance and leak sensitive internal details to standard output streams.",
                    "recommendation": "Replace System.out/console.log with a configurable logger (e.g., Logger.getLogger() or SLF4J LoggerFactory).",
                    "secure_code": "logger.info(...) or logger.debug(...)",
                    "references": ["Clean Code - Logging Best Practices"]
                })
        return findings

    def _detect_pattern_quality_issues(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code.split("\n")

        if len(lines) > 250:
            findings.append({
                "id": "cq_file_length",
                "title": "File Length Exceeds Recommended Limit",
                "issue": "File Length Exceeds Threshold",
                "category": "Code Quality",
                "agent": "CodeAnalysisAgent",
                "severity": "Low",
                "confidence": 0.90,
                "line": 1,
                "explanation": f"File contains {len(lines)} lines, exceeding the recommended limit of 250 lines.",
                "why_it_matters": "Large files are difficult to maintain, test, and review effectively.",
                "recommendation": "Split the file into smaller, modular components.",
                "secure_code": "// Break monolithic file into distinct module classes",
                "references": ["Single Responsibility Principle"]
            })

        return findings

    def _consolidate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolidates repetitive findings (such as multiple System.out.print statements) into single aggregated items.
        """
        console_lines = []
        other_findings = []

        for f in findings:
            issue_title = str(f.get("issue", "")).lower()
            if "console" in issue_title or "system.out" in issue_title or "print statement" in issue_title:
                line_no = f.get("line", 1)
                if line_no not in console_lines:
                    console_lines.append(line_no)
            else:
                other_findings.append(f)

        if console_lines:
            console_lines.sort()
            lines_str = ", ".join(map(str, console_lines))
            consolidated_console = {
                "id": "cq_console_consolidated",
                "title": "Multiple Console Output Statements Detected",
                "issue": "Console Debug Statement",
                "category": "Code Quality",
                "agent": "CodeAnalysisAgent",
                "severity": "Low",
                "confidence": 0.99,
                "line": console_lines[0],
                "affected_lines": console_lines,
                "explanation": f"Detected {len(console_lines)} console output statements (System.out.print / console.log) on lines {lines_str}. Use a structured logging framework.",
                "why_it_matters": "Direct console output bypasses log level controls, reduces performance in production, and can leak sensitive information.",
                "recommendation": "Replace standard print statements with SLF4J / Logback / java.util.logging logger calls.",
                "secure_code": "private static final Logger logger = LoggerFactory.getLogger(YourClass.class);\nlogger.info(\"Message\");",
                "references": ["OWASP Logging Guide", "Clean Code: Logging Standards"]
            }
            other_findings.append(consolidated_console)

        # Standardize all findings to include required schema keys
        result = []
        for i, f in enumerate(other_findings, start=1):
            item = dict(f)
            item.setdefault("id", f"cq_{i}")
            item.setdefault("title", item.get("issue", "Code Quality Finding"))
            item.setdefault("category", "Code Quality")
            item.setdefault("agent", "CodeAnalysisAgent")
            item.setdefault("severity", "Low")
            item.setdefault("confidence", 0.90)
            item.setdefault("line", 1)
            item.setdefault("references", ["Clean Code Best Practices"])
            result.append(item)

        return result

    def get_depth(self, node):
        max_depth = 0
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.For, ast.While, ast.If, ast.AsyncFor, ast.Try, ast.With, ast.AsyncWith)):
                max_depth = max(max_depth, 1 + self.get_depth(child))
        return max_depth

    # --------------------------------------------------------------------------
    # Detection Rules Implementation
    # --------------------------------------------------------------------------

    def _detect_bad_variable_names(self, tree):
        findings = []
        seen = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if len(node.id) == 1:
                    lineno = getattr(node, "lineno", 0)
                    if (lineno, node.id) not in seen:
                        seen.add((lineno, node.id))
                        findings.append({
                            "agent": "Code Analysis",
                            "severity": "Low",
                            "issue": f"Variable '{node.id}' is not descriptive",
                            "explanation": f"Single-letter variable name '{node.id}' reduces code readability.",
                            "line": lineno
                        })
        return findings

    def _detect_long_methods(self, tree, code):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(node, "end_lineno") and node.end_lineno:
                    length = node.end_lineno - node.lineno + 1
                else:
                    length = len(node.body)

                if length > 20:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Function '{node.name}' is too long",
                        "explanation": f"Function '{node.name}' spans {length} lines, exceeding the recommended limit of 20 lines.",
                        "line": node.lineno
                    })
        return findings

    def _detect_too_many_parameters(self, tree):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total_params = (
                    len(node.args.args) +
                    (1 if node.args.vararg else 0) +
                    (1 if node.args.kwarg else 0) +
                    len(node.args.kwonlyargs)
                )
                if total_params > 5:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Function '{node.name}' has too many parameters",
                        "explanation": f"Function '{node.name}' has {total_params} parameters, exceeding the threshold of 5.",
                        "line": node.lineno
                    })
        return findings

    def _detect_deep_nesting(self, tree):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While, ast.If, ast.AsyncFor, ast.Try, ast.With, ast.AsyncWith)):
                depth = self.get_depth(node)
                if depth > 3:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "High",
                        "issue": "Deep nesting detected",
                        "explanation": f"Control structure has a nesting depth of {depth}, exceeding the recommended threshold of 3.",
                        "line": node.lineno
                    })
        return findings

    def _detect_large_classes(self, tree):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = [
                    n for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                if len(methods) > 10:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Large class '{node.name}'",
                        "explanation": f"Class '{node.name}' defines {len(methods)} methods, exceeding the limit of 10.",
                        "line": node.lineno
                    })
        return findings

    def _calculate_func_complexity(self, func_node):
        cc = 1
        for node in ast.walk(func_node):
            if node is func_node:
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.AsyncWith, ast.Assert, ast.IfExp)):
                cc += 1
            elif isinstance(node, ast.BoolOp):
                cc += len(node.values) - 1
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                cc += sum(len(gen.ifs) for gen in node.generators)
        return cc

    def _detect_cyclomatic_complexity(self, tree):
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cc = self._calculate_func_complexity(node)
                if cc > 10:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "High",
                        "issue": f"High Cyclomatic Complexity ({cc}) in function '{node.name}'",
                        "explanation": f"Function '{node.name}' has a cyclomatic complexity of {cc}, exceeding the recommended limit of 10.",
                        "line": node.lineno
                    })
                elif cc > 5:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Moderate Cyclomatic Complexity ({cc}) in function '{node.name}'",
                        "explanation": f"Function '{node.name}' has a cyclomatic complexity of {cc}, exceeding the recommended limit of 5.",
                        "line": node.lineno
                    })
        return findings

    def _detect_duplicate_code(self, tree, code):
        findings = []
        seen_blocks = {}

        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(body, list) and len(body) >= 3:
                stmts = [s for s in body if not isinstance(s, (ast.Pass, ast.Expr))]
                if len(stmts) >= 3:
                    for i in range(len(stmts) - 2):
                        window = stmts[i:i + 3]
                        try:
                            sig = tuple(ast.dump(s) for s in window)
                        except Exception:
                            continue

                        first_line = getattr(window[0], "lineno", 0)
                        if sig in seen_blocks:
                            prev_line = seen_blocks[sig]
                            if first_line > prev_line + 2:
                                findings.append({
                                    "agent": "Code Analysis",
                                    "severity": "Medium",
                                    "issue": "Duplicate code detected",
                                    "explanation": f"Identical code block detected near line {first_line} matching block near line {prev_line}.",
                                    "line": first_line
                                })
                        else:
                            seen_blocks[sig] = first_line

        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        func_bodies = {}
        for func in funcs:
            try:
                body_sig = tuple(ast.dump(s) for s in func.body if not isinstance(s, ast.Pass))
            except Exception:
                continue
            if len(body_sig) > 0:
                if body_sig in func_bodies:
                    prev_func, prev_line = func_bodies[body_sig]
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Duplicate function body in '{func.name}'",
                        "explanation": f"Function '{func.name}' has identical body to function '{prev_func}' at line {prev_line}.",
                        "line": func.lineno
                    })
                else:
                    func_bodies[body_sig] = (func.name, func.lineno)

        unique_findings = []
        seen_keys = set()
        for f in findings:
            key = (f["line"], f["issue"])
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        return unique_findings

    def _detect_unused_variables(self, tree):
        findings = []

        def analyze_scope(scope_node):
            stored = {}
            loaded = set()

            for node in ast.walk(scope_node):
                if node is not scope_node and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue

                if isinstance(node, ast.Name):
                    if isinstance(node.ctx, ast.Store):
                        var_name = node.id
                        if not var_name.startswith("_") and var_name not in ("self", "cls"):
                            if var_name not in stored:
                                stored[var_name] = getattr(node, "lineno", 0)
                    elif isinstance(node.ctx, ast.Load):
                        loaded.add(node.id)

            for var_name, lineno in stored.items():
                if var_name not in loaded:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Low",
                        "issue": f"Unused variable '{var_name}'",
                        "explanation": f"Variable '{var_name}' is assigned but never referenced.",
                        "line": lineno
                    })

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                analyze_scope(node)

        return findings

    def _detect_unused_imports(self, tree):
        findings = []
        imports = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound_name = alias.asname or alias.name.split('.')[0]
                    imports[bound_name] = (node.lineno, alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module == "__future__":
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    bound_name = alias.asname or alias.name
                    imports[bound_name] = (node.lineno, f"{node.module}.{alias.name}" if node.module else alias.name)

        loaded_names = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    loaded_names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    curr = node
                    while isinstance(curr, ast.Attribute):
                        curr = curr.value
                    if isinstance(curr, ast.Name):
                        loaded_names.add(curr.id)

        for bound_name, (lineno, orig_name) in imports.items():
            if bound_name not in loaded_names:
                findings.append({
                    "agent": "Code Analysis",
                    "severity": "Low",
                    "issue": f"Unused import '{orig_name}'",
                    "explanation": f"Import '{orig_name}' is defined on line {lineno} but never referenced.",
                    "line": lineno
                })

        return findings

    def _detect_magic_numbers(self, tree):
        findings = []
        ignored_numbers = {0, 1, -1, 2, 0.0, 1.0, 100}
        const_assign_lines = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        const_assign_lines.add(getattr(node, "lineno", 0))

        seen = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                val = node.value
                lineno = getattr(node, "lineno", 0)
                if val not in ignored_numbers and lineno not in const_assign_lines:
                    if (lineno, val) not in seen:
                        seen.add((lineno, val))
                        findings.append({
                            "agent": "Code Analysis",
                            "severity": "Low",
                            "issue": f"Magic number '{val}' detected",
                            "explanation": f"Literal number {val} is hardcoded without explanation. Consider replacing it with a named constant.",
                            "line": lineno
                        })
        return findings

    def _calculate_maintainability_score(self, tree, code):
        lines = code.splitlines()
        loc = max(1, len(lines))

        total_cc = 1
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total_cc += self._calculate_func_complexity(node)

        operators = Counter()
        operands = Counter()

        for node in ast.walk(tree):
            if isinstance(node, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow)):
                operators[type(node).__name__] += 1
            elif isinstance(node, (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is, ast.IsNot, ast.In, ast.NotIn)):
                operators[type(node).__name__] += 1
            elif isinstance(node, (ast.And, ast.Or, ast.Not)):
                operators[type(node).__name__] += 1
            elif isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Call, ast.Assign, ast.Return, ast.FunctionDef, ast.ClassDef)):
                operators[type(node).__name__] += 1
            elif isinstance(node, ast.Name):
                operands[node.id] += 1
            elif isinstance(node, ast.Constant):
                operands[str(node.value)] += 1

        n1 = sum(operators.values())
        n2 = sum(operands.values())
        eta1 = len(operators)
        eta2 = len(operands)

        n = n1 + n2
        eta = eta1 + eta2

        if eta > 0 and n > 0:
            volume = n * math.log2(eta)
        else:
            volume = 1.0

        volume = max(1.0, volume)

        mi_raw = 171.0 - (5.2 * math.log(volume)) - (0.23 * total_cc) - (16.2 * math.log(loc))
        score = max(0.0, min(100.0, (mi_raw * 100.0) / 171.0))

        if score >= 75:
            severity = "Low"
        elif score >= 50:
            severity = "Medium"
        else:
            severity = "High"

        return [{
            "agent": "Code Analysis",
            "severity": severity,
            "issue": f"Maintainability Score: {score:.1f}/100",
            "explanation": f"Code maintainability score is {score:.1f}/100 based on Halstead volume ({volume:.1f}), total cyclomatic complexity ({total_cc}), and lines of code ({loc}).",
            "line": 0
        }]