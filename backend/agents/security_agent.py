import ast


class SecurityAgent:

    def analyze(self, code: str):

        findings = []

        try:
            tree = ast.parse(code)

        except SyntaxError:
            return [{
                "agent": "Security",
                "severity": "Critical",
                "issue": "Syntax Error",
                "line": 0
            }]

        # Rule 1 - eval()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id == "eval":
                        findings.append({
                            "agent": "Security",
                            "severity": "Critical",
                            "issue": "Use of eval()",
                            "line": node.lineno
                        })

        # Rule 2 - exec()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id == "exec":
                        findings.append({
                            "agent": "Security",
                            "severity": "Critical",
                            "issue": "Use of exec()",
                            "line": node.lineno
                        })

        # Rule 3 - Hardcoded Password/API Key
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):

                for target in node.targets:

                    if isinstance(target, ast.Name):

                        name = target.id.lower()

                        if "password" in name or "secret" in name or "api_key" in name:

                            if isinstance(node.value, ast.Constant):

                                findings.append({
                                    "agent": "Security",
                                    "severity": "High",
                                    "issue": f"Hardcoded credential: {target.id}",
                                    "line": node.lineno
                                })

        # Rule 4 - shell=True
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):

                if hasattr(node.func, "attr"):

                    if node.func.attr == "run":

                        for keyword in node.keywords:

                            if keyword.arg == "shell":

                                if isinstance(keyword.value, ast.Constant):

                                    if keyword.value.value is True:

                                        findings.append({
                                            "agent": "Security",
                                            "severity": "Critical",
                                            "issue": "subprocess with shell=True",
                                            "line": node.lineno
                                        })

        return findings