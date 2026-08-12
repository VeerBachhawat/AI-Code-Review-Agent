import os
import re
import shutil
import tempfile
import unittest

from backend.reporting.report_generator import (
    ReportGenerator,
    sanitize_secret_text,
    extract_source_line,
    get_score_rating,
    format_execution_time,
    build_executive_assessment
)


def count_pdf_pages(pdf_path: str) -> int:
    """
    Parses a PDF file binary to count '/Type /Page' objects.
    """
    with open(pdf_path, "rb") as f:
        content = f.read()
    matches = re.findall(rb"/Type\s*/Page\b(?!\s*s)", content)
    return len(matches)


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ReportGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_secret_sanitization(self):
        secret_text = "Here is my key: gsk_1234567890abcdef1234567890 and AWS AKIAIOSFODNN7EXAMPLE"
        sanitized = sanitize_secret_text(secret_text)
        self.assertNotIn("gsk_1234567890abcdef1234567890", sanitized)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sanitized)
        self.assertIn("[REDACTED_API_KEY]", sanitized)
        self.assertIn("[REDACTED_AWS_KEY]", sanitized)

    def test_extract_source_line(self):
        code = "def foo():\n    return 42\n"
        self.assertEqual(extract_source_line(code, 2), "return 42")
        self.assertEqual(extract_source_line(code, 99), "")

    def test_score_rating_and_execution_time_formatting(self):
        self.assertEqual(get_score_rating(95), "Excellent / Strong")
        self.assertEqual(get_score_rating(80), "Good / Needs Minor Improvement")
        self.assertEqual(get_score_rating(60), "Needs Improvement")
        self.assertEqual(get_score_rating(40), "Poor / Significant Attention Required")

        self.assertEqual(format_execution_time(56882.47), "56.88 s")
        self.assertEqual(format_execution_time(250), "250 ms")

    def test_dynamic_executive_assessment_language(self):
        # Scenario: Critical = 0, High = 1, Medium = 1
        data = {"pr_summary": {}}
        assessment = build_executive_assessment(data, crit_count=0, high_count=1, med_count=1, low_count=0, total_findings=2, code_score=95, sec_score=90)
        self.assertIn("Overall code health is strong", assessment)
        self.assertNotIn("urgent", assessment.lower())
        self.assertNotIn("critical vulnerability", assessment.lower())

        # Scenario: Critical = 2
        assessment_crit = build_executive_assessment(data, crit_count=2, high_count=0, med_count=0, low_count=0, total_findings=2, code_score=70, sec_score=30)
        self.assertIn("Security posture requires immediate attention to resolve 2 critical vulnerability(ies)", assessment_crit)

    def test_pdf_single_page_python_full(self):
        review_data = {
            "status": "success",
            "language": "python",
            "execution_time_ms": 250,
            "code": "password = 'admin'\neval(input())\n",
            "summary": {
                "total_findings": 2,
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0
            },
            "findings": [
                {
                    "agent": "SecurityAgent",
                    "severity": "Critical",
                    "issue": "Use of eval()",
                    "explanation": "Dynamic execution allows RCE.",
                    "line": 2
                },
                {
                    "agent": "SecurityAgent",
                    "severity": "High",
                    "issue": "Hardcoded Credential",
                    "explanation": "Password hardcoded in variable.",
                    "line": 1
                }
            ],
            "remediation": [
                {
                    "issue": "Use of eval()",
                    "severity": "Critical",
                    "line": 2,
                    "why_it_is_problematic": "eval() executes untrusted string input as code.",
                    "recommended_fix": "Use ast.literal_eval or parse structured input safely.",
                    "corrected_code_example": "import ast\nresult = ast.literal_eval(user_input)",
                    "best_practice": "Never pass user input to eval().",
                    "references": ["OWASP A03: Injection"]
                }
            ],
            "pr_summary": {
                "overall_status": "Changes Requested",
                "overall_code_quality": 70,
                "overall_security_score": 30,
                "security_summary": "Critical vulnerabilities found in dynamic evaluation.",
                "code_quality_summary": "Code formatting acceptable.",
                "top_risks": ["Arbitrary Code Execution via eval()"],
                "positive_observations": ["Valid syntax structure."],
                "recommended_next_steps": ["Remove eval() call", "Move credentials to env"],
                "estimated_remediation_effort": {"critical": "10 mins", "high": "5 mins", "overall": "15 mins"},
                "developer_comment": "Fix critical issues before merge."
            }
        }

        results = self.generator.save_report(review_data, formats=["pdf", "html"])

        self.assertIn("pdf", results)
        self.assertIn("html", results)
        self.assertTrue(os.path.exists(results["pdf"]))
        self.assertTrue(os.path.exists(results["html"]))
        self.assertGreater(os.path.getsize(results["pdf"]), 0)
        self.assertGreater(os.path.getsize(results["html"]), 0)

        # Verify PDF is exactly 1 page
        self.assertEqual(count_pdf_pages(results["pdf"]), 1, "PDF report must be exactly one page")

    def test_three_different_finding_distributions(self):
        # Distribution 1: Zero findings (Approved)
        d1 = {
            "status": "success",
            "language": "python",
            "execution_time_ms": 120,
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "pr_summary": {"overall_status": "Approved", "overall_code_quality": 100, "overall_security_score": 100}
        }
        pdf1 = self.generator.generate_pdf(d1)
        self.assertEqual(count_pdf_pages(pdf1), 1)

        # Distribution 2: High + Medium findings (Needs Changes)
        d2 = {
            "status": "success",
            "language": "javascript",
            "execution_time_ms": 56882.47,
            "summary": {"total_findings": 2, "critical": 0, "high": 1, "medium": 1, "low": 0},
            "findings": [
                {"agent": "SecurityAgent", "severity": "High", "issue": "XSS vulnerability", "explanation": "Unsanitized innerHTML assignment", "line": 42},
                {"agent": "CodeAnalysisAgent", "severity": "Medium", "issue": "Unused variable", "explanation": "Variable declared but never used", "line": 15}
            ],
            "pr_summary": {"overall_code_quality": 95, "overall_security_score": 90}
        }
        pdf2 = self.generator.generate_pdf(d2)
        self.assertEqual(count_pdf_pages(pdf2), 1)

        # Distribution 3: Critical + High findings (Needs Changes)
        d3 = {
            "status": "success",
            "language": "java",
            "execution_time_ms": 3400,
            "summary": {"total_findings": 3, "critical": 1, "high": 1, "medium": 1, "low": 0},
            "findings": [
                {"agent": "SecurityAgent", "severity": "Critical", "issue": "SQL Injection", "explanation": "Concatenated SQL query in DAO", "line": 88},
                {"agent": "SecurityAgent", "severity": "High", "issue": "Hardcoded Password", "explanation": "DB password hardcoded in string", "line": 12},
                {"agent": "CodeAnalysisAgent", "severity": "Medium", "issue": "Catch Generic Exception", "explanation": "Avoid catching java.lang.Exception", "line": 105}
            ],
            "pr_summary": {"overall_code_quality": 60, "overall_security_score": 30}
        }
        pdf3 = self.generator.generate_pdf(d3)
        self.assertEqual(count_pdf_pages(pdf3), 1)

    def test_many_findings_remains_single_page(self):
        findings = [
            {"agent": "SecurityAgent", "severity": "Critical", "issue": f"Vulnerability #{i}", "explanation": f"Explanation for issue {i}", "line": i}
            for i in range(1, 15)
        ]
        review_data = {
            "language": "python",
            "summary": {"total_findings": 14, "critical": 14, "high": 0, "medium": 0, "low": 0},
            "findings": findings
        }

        pdf = self.generator.generate_pdf(review_data)
        self.assertTrue(os.path.exists(pdf))
        self.assertEqual(count_pdf_pages(pdf), 1, "PDF must stay 1 page even with many findings")

    def test_java_review(self):
        review_data = {
            "language": "java",
            "code": "public class Main {\n    public static void main(String[] args) {\n        System.out.println(\"Hello\");\n    }\n}\n",
            "findings": [
                {"agent": "CodeAnalysisAgent", "severity": "Low", "issue": "Console Debug Statement", "line": 3}
            ]
        }

        pdf = self.generator.generate_pdf(review_data)
        html_path = self.generator.generate_html(review_data)
        self.assertTrue(os.path.exists(pdf))
        self.assertTrue(os.path.exists(html_path))
        self.assertEqual(count_pdf_pages(pdf), 1)


if __name__ == "__main__":
    unittest.main()
