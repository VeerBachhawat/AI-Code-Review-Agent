import ast


class CodeAnalysisAgent:

    def analyze(self, code: str):

        findings = []

        try:
            tree = ast.parse(code)

        except SyntaxError:
            return [{
                "agent": "Code Analysis",
                "severity": "Critical",
                "issue": "Syntax Error",
                "line": 0
            }]

        # ----------------------------
        # Rule 1 - Bad Variable Names
        # ----------------------------
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if len(node.id) == 1:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Low",
                        "issue": f"Variable '{node.id}' is not descriptive",
                        "line": getattr(node, "lineno", 0)
                    })

        # ----------------------------
        # Rule 2 - Long Functions
        # ----------------------------
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if len(node.body) > 20:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Function '{node.name}' is too long",
                        "line": node.lineno
                    })

        # ----------------------------
        # Rule 3 - Too Many Parameters
        # ----------------------------
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if len(node.args.args) > 5:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Function '{node.name}' has too many parameters",
                        "line": node.lineno
                    })

        # ----------------------------
        # Rule 4 - Deep Nesting
        # ----------------------------
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While, ast.If)):
                depth = self.get_depth(node)

                if depth > 3:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "High",
                        "issue": "Deep nesting detected",
                        "line": node.lineno
                    })

        # ----------------------------
        # Rule 5 - Large Class
        # ----------------------------
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):

                methods = [
                    n for n in node.body
                    if isinstance(n, ast.FunctionDef)
                ]

                if len(methods) > 10:
                    findings.append({
                        "agent": "Code Analysis",
                        "severity": "Medium",
                        "issue": f"Large class '{node.name}'",
                        "line": node.lineno
                    })

        return findings

    def get_depth(self, node):

        max_depth = 0

        for child in ast.iter_child_nodes(node):

            if isinstance(child, (ast.For, ast.While, ast.If)):

                max_depth = max(max_depth, 1 + self.get_depth(child))

        return max_depth