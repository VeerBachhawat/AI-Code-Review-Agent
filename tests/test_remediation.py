import unittest
from backend.agents.remediation_agent import RemediationAgent


class TestRemediation(unittest.TestCase):

    def setUp(self):
        self.agent = RemediationAgent()

    def test_rule_based_remediation_schema(self):
        findings = [
            {
                "id": "sec_eval_1",
                "issue": "Use of eval()",
                "severity": "Critical",
                "line": 10,
                "explanation": "eval() allows arbitrary code execution.",
                "category": "Security"
            },
            {
                "id": "sec_sqli_2",
                "issue": "SQL Injection",
                "severity": "Critical",
                "line": 15,
                "explanation": "String concatenation in query.",
                "category": "Security"
            }
        ]

        for finding in findings:
            enriched = self.agent._enrich_finding_with_code(finding, source_code="eval(x)\nquery = 'SELECT * FROM users WHERE name = ' + name")
            handler = self.agent._find_handler(finding["issue"])
            details = handler(enriched)

            self.assertIn("why_it_is_problematic", details)
            self.assertIn("recommended_fix", details)
            self.assertIn("corrected_code_example", details)
            self.assertIn("best_practice", details)
            self.assertIn("references", details)

            rec = details.get("recommended_fix", "")
            self.assertFalse(rec == "Follow secure coding practices.", "Remediation recommendation must not be generic placeholder")
            self.assertTrue(len(rec) > 10, "Remediation recommendation must provide actionable details")

    def test_remediation_matches_eval_finding(self):
        findings = [{
            "id": "sec_eval_1",
            "issue": "Use of eval()",
            "severity": "Critical",
            "line": 2,
            "explanation": "Dynamic code execution allows arbitrary command injection."
        }]

        remediations = self.agent.generate_remediation(findings, source_code="eval(input())")
        self.assertGreater(len(remediations), 0)

        rem = remediations[0]
        self.assertIn("why_it_is_problematic", rem)

        combined_text = (
            str(rem.get("why_it_is_problematic")) +
            str(rem.get("recommended_fix")) +
            str(rem.get("corrected_code_example"))
        ).lower()

        self.assertTrue(
            "eval" in combined_text or "ast.literal_eval" in combined_text or "dynamic" in combined_text or "parse" in combined_text,
            "Remediation must specifically target eval/dynamic execution issue"
        )


if __name__ == "__main__":
    unittest.main()
