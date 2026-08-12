import unittest
from backend.agents.conversational_code_assistant import ConversationalCodeAssistant


class TestRAGAssistant(unittest.TestCase):

    def setUp(self):
        self.assistant = ConversationalCodeAssistant()

    def test_rag_queries(self):
        queries = [
            "Explain SQL Injection.",
            "Why is eval() dangerous?",
            "How should I fix a hardcoded password?",
            "What does OWASP recommend for injection prevention?"
        ]

        for q in queries:
            res = self.assistant.ask(question=q)
            self.assertIn("answer", res)
            self.assertIn("sources", res)
            self.assertIn("related_topics", res)
            self.assertTrue(len(res["answer"]) > 0, f"Query '{q}' should produce non-empty answer")

    def test_context_aware_chat(self):
        findings = [
            {
                "id": "sec_eval_4",
                "issue": "Use of eval()",
                "severity": "Critical",
                "line": 4,
                "explanation": "eval() executes untrusted string input on line 4."
            }
        ]
        code = "user_input = input()\nprint('processing')\n# comment\nresult = eval(user_input)\n"

        res = self.assistant.ask(
            question="Explain finding on line 4.",
            optional_findings=findings,
            optional_code=code,
            code_quality_score=80,
            security_score=30
        )

        self.assertIn("answer", res)
        answer_text = res["answer"].lower()
        self.assertTrue("eval" in answer_text or "line 4" in answer_text or "critical" in answer_text or "4" in answer_text, "Response must refer to line 4 eval finding context")


if __name__ == "__main__":
    unittest.main()
