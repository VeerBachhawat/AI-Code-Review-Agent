import unittest
from backend.agents.pr_summary_agent import PRSummaryAgent


class TestPRSummary(unittest.TestCase):

    def setUp(self):
        self.agent = PRSummaryAgent()

    def test_pr_summary_schema(self):
        findings = [
            {"agent": "SecurityAgent", "severity": "High", "issue": "Hardcoded Password", "line": 5},
            {"agent": "CodeAnalysisAgent", "severity": "Low", "issue": "Variable 'x' is not descriptive", "line": 10}
        ]
        remediations = [
            {"issue": "Hardcoded Password", "severity": "High", "line": 5, "recommended_fix": "Use environment variables"}
        ]

        summary = self.agent.generate_summary(findings, remediations)

        self.assertIn("overall_status", summary)
        self.assertIn("overall_code_quality", summary)
        self.assertIn("overall_security_score", summary)
        self.assertIn("top_risks", summary)
        self.assertIn("recommended_next_steps", summary)
        self.assertIn("estimated_remediation_effort", summary)

    def test_pr_summary_zero_critical_consistency(self):
        findings = [
            {"agent": "SecurityAgent", "severity": "High", "issue": "Hardcoded Password", "line": 5}
        ]
        remediations = [
            {"issue": "Hardcoded Password", "severity": "High", "line": 5}
        ]

        summary = self.agent.generate_summary(findings, remediations)

        # Must not claim critical findings exist when there are zero
        sec_summary = str(summary.get("security_summary", "")).lower()
        self.assertNotIn("critical vulnerability", sec_summary)
        self.assertNotIn("critical findings", sec_summary)


if __name__ == "__main__":
    unittest.main()
