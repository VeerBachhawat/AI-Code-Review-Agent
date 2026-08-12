import os
import unittest
from backend.agents.code_analysis_agent import CodeAnalysisAgent

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))


class TestCodeAnalysis(unittest.TestCase):

    def setUp(self):
        self.agent = CodeAnalysisAgent()

    def test_clean_python_code_analysis(self):
        sample_path = os.path.join(SAMPLES_DIR, "python", "clean_python.py")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)

        # Clean code should not trigger High or Critical findings
        high_or_crit = [f for f in findings if str(f.get("severity", "")).lower() in ("high", "critical")]
        self.assertEqual(len(high_or_crit), 0, f"Clean python code should not have High/Critical findings: {high_or_crit}")

    def test_complex_python_code_analysis(self):
        sample_path = os.path.join(SAMPLES_DIR, "python", "complex_python.py")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)
        self.assertGreater(len(findings), 0, "Complex code should produce code quality findings")

        issues_found = [f.get("issue", "") for f in findings]

        # Verify specific detectors triggered
        has_bad_var = any("is not descriptive" in issue or "Variable" in issue for issue in issues_found)
        has_params = any("too many parameters" in issue.lower() for issue in issues_found)
        has_nesting = any("nesting" in issue.lower() for issue in issues_found)
        has_complexity = any("cyclomatic complexity" in issue.lower() for issue in issues_found)
        has_long_func = any("too long" in issue.lower() for issue in issues_found)
        has_unused_import = any("unused import" in issue.lower() for issue in issues_found)

        self.assertTrue(has_bad_var, "Should detect bad variable names")
        self.assertTrue(has_params, "Should detect function with too many parameters")
        self.assertTrue(has_nesting, "Should detect deep nesting")
        self.assertTrue(has_complexity, "Should detect high cyclomatic complexity")
        self.assertTrue(has_long_func, "Should detect long functions")
        self.assertTrue(has_unused_import, "Should detect unused imports")

    def test_finding_structure(self):
        sample_path = os.path.join(SAMPLES_DIR, "python", "complex_python.py")
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = self.agent.analyze(code)
        for finding in findings:
            self.assertIn("issue", finding)
            self.assertIn("severity", finding)
            self.assertIn("line", finding)
            self.assertIn("explanation", finding)
            self.assertTrue(len(str(finding["explanation"])) > 0)


if __name__ == "__main__":
    unittest.main()
