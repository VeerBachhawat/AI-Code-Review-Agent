import os
import unittest
from backend.agents.security_agent import SecurityAgent

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))


class TestSecurity(unittest.TestCase):

    def setUp(self):
        self.agent = SecurityAgent()

    def test_clean_python_security(self):
        sample_path = os.path.join(SAMPLES_DIR, "python", "clean_python.py")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)
        self.assertEqual(len(findings), 0, f"Clean Python code should have 0 security vulnerabilities: {findings}")

    def test_clean_java_security(self):
        sample_path = os.path.join(SAMPLES_DIR, "java", "clean_java.java")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)
        self.assertEqual(len(findings), 0, f"Clean Java code should have 0 security vulnerabilities: {findings}")

    def test_vulnerable_python_security(self):
        sample_path = os.path.join(SAMPLES_DIR, "python", "vulnerable_python.py")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)
        self.assertGreater(len(findings), 0, "Vulnerable Python code must produce security findings")

        issues = [str(f.get("issue", "")).lower() for f in findings]

        has_eval = any("eval" in issue for issue in issues)
        has_secret = any("credential" in issue or "password" in issue or "secret" in issue for issue in issues)
        has_sqli = any("sql" in issue for issue in issues)
        has_cmdi = any("command" in issue or "subprocess" in issue for issue in issues)
        has_deser = any("deserialization" in issue or "pickle" in issue for issue in issues)

        self.assertTrue(has_eval, "Should detect eval() usage")
        self.assertTrue(has_secret, "Should detect hardcoded secrets")
        self.assertTrue(has_sqli, "Should detect SQL injection")
        self.assertTrue(has_cmdi, "Should detect Command injection")
        self.assertTrue(has_deser, "Should detect unsafe deserialization")

    def test_vulnerable_java_security(self):
        sample_path = os.path.join(SAMPLES_DIR, "java", "vulnerable_java.java")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)
        self.assertGreater(len(findings), 0, "Vulnerable Java code must produce security findings")

        issues = [str(f.get("issue", "")).lower() for f in findings]

        has_sqli = any("sql" in issue for issue in issues)
        has_cmdi = any("command" in issue or "exec" in issue for issue in issues)
        has_deser = any("deserialization" in issue or "objectinputstream" in issue for issue in issues)
        has_secret = any("credential" in issue or "password" in issue for issue in issues)

        self.assertTrue(has_sqli, "Should detect Java SQL injection pattern")
        self.assertTrue(has_cmdi, "Should detect Java Command execution risk")
        self.assertTrue(has_deser, "Should detect Java unsafe object deserialization")
        self.assertTrue(has_secret, "Should detect Java hardcoded password")

    def test_finding_validity(self):
        sample_path = os.path.join(SAMPLES_DIR, "python", "vulnerable_python.py")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)
        for f in findings:
            self.assertIn(f.get("severity", "").upper(), ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            self.assertGreater(f.get("line", 0), 0)
            self.assertTrue(len(f.get("explanation", "")) > 0)


if __name__ == "__main__":
    unittest.main()
