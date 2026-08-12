import os
import unittest
from backend.agents.orchestrator import Orchestrator

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))


class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        self.orchestrator = Orchestrator()

    def test_review_clean_python(self):
        path = os.path.join(SAMPLES_DIR, "python", "clean_python.py")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        result = self.orchestrator.review(code, language="python")

        self.assertIn("status", result)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["language"], "python")
        self.assertIn("execution_time_ms", result)
        self.assertGreaterEqual(result["execution_time_ms"], 0)
        self.assertIn("summary", result)
        self.assertIn("findings", result)
        self.assertIn("remediation", result)
        self.assertIn("pr_summary", result)
        self.assertIn("agent_status", result["summary"])

    def test_review_vulnerable_python(self):
        path = os.path.join(SAMPLES_DIR, "python", "vulnerable_python.py")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        result = self.orchestrator.review(code, language="python")

        self.assertEqual(result["status"], "success")
        self.assertGreater(len(result["findings"]), 0)
        self.assertGreater(len(result["remediation"]), 0)
        self.assertIn(result["pr_summary"].get("overall_status"), ["Changes Requested", "Needs Changes", "Rejected"])

    def test_review_complex_python(self):
        path = os.path.join(SAMPLES_DIR, "python", "complex_python.py")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        result = self.orchestrator.review(code, language="python")

        self.assertEqual(result["status"], "success")
        self.assertGreater(len(result["findings"]), 0)

    def test_review_invalid_python(self):
        path = os.path.join(SAMPLES_DIR, "python", "invalid_python.py")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        # System must identify syntax problem cleanly without crashing
        result = self.orchestrator.review(code, language="python")
        self.assertIn("status", result)
        self.assertIn("summary", result)

    def test_review_clean_java(self):
        path = os.path.join(SAMPLES_DIR, "java", "clean_java.java")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        result = self.orchestrator.review(code, language="java")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["language"], "java")
        self.assertIn("summary", result)

    def test_review_vulnerable_java(self):
        path = os.path.join(SAMPLES_DIR, "java", "vulnerable_java.java")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        result = self.orchestrator.review(code, language="java")
        self.assertEqual(result["status"], "success")
        self.assertGreater(len(result["findings"]), 0)

    def test_review_complex_java(self):
        path = os.path.join(SAMPLES_DIR, "java", "complex_java.java")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        result = self.orchestrator.review(code, language="java")
        self.assertEqual(result["status"], "success")

    def test_review_invalid_java(self):
        path = os.path.join(SAMPLES_DIR, "java", "invalid_java.java")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        result = self.orchestrator.review(code, language="java")
        self.assertIn("status", result)


if __name__ == "__main__":
    unittest.main()
