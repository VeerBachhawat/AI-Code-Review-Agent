import os
import re
import shutil
import tempfile
import unittest

from backend.reporting.report_generator import ReportGenerator

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))


def count_pdf_pages(pdf_path: str) -> int:
    with open(pdf_path, "rb") as f:
        content = f.read()
    matches = re.findall(rb"/Type\s*/Page\b(?!\s*s)", content)
    return len(matches)


class TestReports(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ReportGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_report_generation_zero_findings(self):
        data = {
            "status": "success",
            "language": "python",
            "execution_time_ms": 100,
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "remediation": [],
            "pr_summary": {"overall_status": "Approved", "overall_code_quality": 100, "overall_security_score": 100}
        }
        res = self.generator.save_report(data, formats=["pdf", "html"])
        self.assertTrue(os.path.exists(res["pdf"]))
        self.assertTrue(os.path.exists(res["html"]))
        self.assertEqual(count_pdf_pages(res["pdf"]), 1)

    def test_report_generation_critical_and_high_python(self):
        data = {
            "status": "success",
            "language": "python",
            "execution_time_ms": 450,
            "summary": {"total_findings": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
            "findings": [
                {"agent": "SecurityAgent", "severity": "Critical", "issue": "eval() usage", "explanation": "Arbitrary code execution on line 2", "line": 2},
                {"agent": "SecurityAgent", "severity": "High", "issue": "Hardcoded AWS Key", "explanation": "Exposed key AKIAIOSFODNN7EXAMPLE", "line": 5}
            ],
            "remediation": [
                {"issue": "eval() usage", "severity": "Critical", "line": 2, "recommended_fix": "Use ast.literal_eval"}
            ],
            "pr_summary": {
                "overall_status": "Changes Requested",
                "overall_code_quality": 75,
                "overall_security_score": 30,
                "top_risks": ["Remote Code Execution via eval()"],
                "recommended_next_steps": ["Remove eval()"]
            }
        }
        res = self.generator.save_report(data, formats=["pdf", "html"])
        self.assertTrue(os.path.exists(res["pdf"]))
        self.assertTrue(os.path.exists(res["html"]))

        # Verify PDF single page
        self.assertEqual(count_pdf_pages(res["pdf"]), 1)

        # Verify No Secrets exposed in reports (Redaction verification)
        with open(res["html"], "r", encoding="utf-8") as f:
            html_text = f.read()
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", html_text, "Secrets must be redacted in generated HTML report")

    def test_report_generation_java_multiple_findings(self):
        data = {
            "status": "success",
            "language": "java",
            "execution_time_ms": 1200,
            "summary": {"total_findings": 3, "critical": 1, "high": 1, "medium": 1, "low": 0},
            "findings": [
                {"agent": "SecurityAgent", "severity": "Critical", "issue": "Java SQL Injection", "explanation": "Statement concatenation", "line": 10},
                {"agent": "SecurityAgent", "severity": "High", "issue": "Runtime.exec Command Injection", "explanation": "Unsanitized system exec", "line": 14},
                {"agent": "CodeAnalysisAgent", "severity": "Medium", "issue": "File Length Exceeds Threshold", "explanation": "Monolithic class", "line": 1}
            ],
            "remediation": [
                {"issue": "Java SQL Injection", "severity": "Critical", "line": 10, "recommended_fix": "Use PreparedStatement"}
            ],
            "pr_summary": {
                "overall_status": "Needs Changes",
                "overall_code_quality": 60,
                "overall_security_score": 25
            }
        }
        res = self.generator.save_report(data, formats=["pdf", "html"])
        self.assertTrue(os.path.exists(res["pdf"]))
        self.assertTrue(os.path.exists(res["html"]))
        self.assertEqual(count_pdf_pages(res["pdf"]), 1)


if __name__ == "__main__":
    unittest.main()
