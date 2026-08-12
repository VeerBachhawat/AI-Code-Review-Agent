"""
Milestone 4 Requirement 3 — Prompt & Response Quality Test Suite
================================================================
Validates all 9 required user question types against real reviewed source code:
A. "Explain this finding."
B. "Why is this dangerous?"
C. "What exactly should I change?"
D. "Show me the corrected code."
E. "Rewrite the complete code."
F. "How can I improve this code?"
G. "Why was this marked Critical?"
H. "What does OWASP recommend?"
I. "Explain this like I am a beginner."
"""

import unittest
from backend.agents.orchestrator import Orchestrator
from backend.agents.conversational_code_assistant import ConversationalCodeAssistant

VULNERABLE_PYTHON = """import os
import eval_module

def handle_user_login(user_input):
    DB_PASSWORD = "SuperSecretPassword123!"
    result = eval(user_input)
    return result
"""

class TestPromptQuality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orchestrator = Orchestrator()
        cls.assistant = ConversationalCodeAssistant()
        # Perform real review to populate findings & remediations
        cls.review_result = cls.orchestrator.review(VULNERABLE_PYTHON, language="python")
        cls.findings = cls.review_result.get("findings", [])
        cls.remediations = cls.review_result.get("remediations", [])
        cls.pr_summary = cls.review_result.get("pr_summary", {})

    def _get_context(self):
        return {
            "optional_code": VULNERABLE_PYTHON,
            "optional_findings": self.findings,
            "remediations": self.remediations,
            "pr_summary": self.pr_summary
        }

    def test_prompt_a_explain_finding(self):
        res = self.assistant.ask("Explain this finding.", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue(len(res["answer"]) > 50)
        self.assertNotIn("# Example code", res["answer"])

    def test_prompt_b_why_dangerous(self):
        res = self.assistant.ask("Why is this dangerous?", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue(any(kw in res["answer"].lower() for kw in ["eval", "password", "security", "risk", "vulnerability"]))

    def test_prompt_c_what_exactly_should_i_change(self):
        res = self.assistant.ask("What exactly should I change?", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue(len(res["answer"]) > 30)

    def test_prompt_d_show_me_corrected_code(self):
        res = self.assistant.ask("Show me the corrected code.", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue("```" in res["answer"] or "ast.literal_eval" in res["answer"] or "getenv" in res["answer"])

    def test_prompt_e_rewrite_complete_code(self):
        res = self.assistant.ask("Rewrite the complete code.", **self._get_context())
        self.assertIn("answer", res)
        ans = res["answer"]
        self.assertTrue("def handle_user_login" in ans or "import os" in ans or "return" in ans)
        self.assertNotIn("# Sample code", ans)

    def test_prompt_f_how_can_i_improve_code(self):
        res = self.assistant.ask("How can I improve this code?", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue(len(res["answer"]) > 40)

    def test_prompt_g_why_was_this_marked_critical(self):
        res = self.assistant.ask("Why was this finding marked Critical?", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue(len(res["answer"]) > 30)

    def test_prompt_h_what_does_owasp_recommend(self):
        res = self.assistant.ask("What does OWASP recommend?", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue("OWASP" in res["answer"] or "sources" in res)

    def test_prompt_i_explain_like_beginner(self):
        res = self.assistant.ask("Explain this like I am a beginner.", **self._get_context())
        self.assertIn("answer", res)
        self.assertTrue(len(res["answer"]) > 50)

    def test_line_specific_not_found(self):
        res = self.assistant.ask("Explain finding on line 99.", **self._get_context())
        self.assertIn("I could not find a matching finding on line 99", res["answer"])

if __name__ == "__main__":
    unittest.main()
