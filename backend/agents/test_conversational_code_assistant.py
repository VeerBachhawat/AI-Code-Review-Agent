"""
Unit and integration tests for ConversationalCodeAssistant (Hybrid RAG with Ollama Qwen3:8b)
Path: backend/agents/test_conversational_code_assistant.py
Runs via: python -m pytest backend/agents/test_conversational_code_assistant.py -v
"""
import pytest
from unittest.mock import MagicMock
from backend.agents.conversational_code_assistant import ConversationalCodeAssistant

EXPECTED_UNSUPPORTED_ANSWER = (
    "I can help with SentinelAI topics such as secure coding, "
    "OWASP, PEP 8, AST analysis, vulnerabilities, code analysis, "
    "and remediation. I don't have relevant SentinelAI knowledge for this question."
)

EXPECTED_REQUEST_CODE_ANSWER = (
    "Please provide the code you want me to secure, or select a code-review finding. "
    "I can then apply SentinelAI's existing security and remediation rules."
)


@pytest.fixture
def assistant():
    bot = ConversationalCodeAssistant()
    # Mock Ollama service generation so unit tests run deterministically offline
    bot.ollama_service.generate_chat = MagicMock(side_effect=lambda system_prompt, user_prompt, history=None: (
        "Secure Code Example:\n```python\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n```"
        if "secure version" in user_prompt.lower() or "corrected code" in user_prompt.lower() or "fix" in user_prompt.lower() else
        "SQL Injection occurs when user input is concatenated into SQL queries. Use parameterized queries."
        if "SQL" in user_prompt else
        "Cyclomatic complexity measures the number of linearly independent paths through a program."
        if "Cyclomatic" in user_prompt else
        "Grounded response based on retrieved SentinelAI context."
    ))
    return bot


def test_1_what_is_iphone(assistant):
    res = assistant.ask("What is iPhone?")
    assert res.get("generated_by") == "ollama"
    assert res.get("source") == "ollama_rag"
    assert res.get("model") == "qwen3:8b"
    assert res.get("answer") == EXPECTED_UNSUPPORTED_ANSWER


def test_2_explain_cyclomatic_complexity(assistant):
    res = assistant.ask("Explain Cyclomatic Complexity.")
    assert res.get("generated_by") == "ollama"
    assert res.get("model") == "qwen3:8b"
    assert "Cyclomatic" in res.get("answer")


def test_3_what_is_sql_injection(assistant):
    res = assistant.ask("What is SQL Injection?")
    assert res.get("generated_by") == "ollama"
    assert res.get("model") == "qwen3:8b"
    assert "SQL" in res.get("answer")


def test_4_secure_version_with_code_and_finding(assistant):
    code = "query = 'SELECT * FROM users WHERE name = ' + user_input"
    findings = [
        {"line": 1, "severity": "Critical", "issue": "SQL Injection", "explanation": "Dynamic SQL concatenation detected.", "recommendation": "Use parameterized queries."}
    ]
    res = assistant.ask(
        question="Give me the secure version of this code.",
        optional_code=code,
        optional_findings=findings
    )
    assert res.get("generated_by") == "ollama"
    assert "Secure Code" in res.get("answer") or "cursor.execute" in res.get("answer")


def test_5_fix_hardcoded_password_with_finding(assistant):
    findings = [
        {"line": 5, "severity": "High", "issue": "Hardcoded Password", "explanation": "Plaintext secret DB_PASS.", "secure_code": "import os\ndb_pass = os.getenv('DB_PASS')"}
    ]
    res = assistant.ask(
        question="Fix this hardcoded password.",
        optional_findings=findings
    )
    assert res.get("generated_by") == "ollama"


def test_6_show_me_corrected_code_with_context(assistant):
    code = "eval(user_data)"
    findings = [
        {"line": 1, "severity": "Critical", "issue": "Dynamic Code Execution", "explanation": "eval() usage.", "secure_code": "import ast\nast.literal_eval(user_data)"}
    ]
    res = assistant.ask(
        question="Show me corrected code.",
        optional_code=code,
        optional_findings=findings
    )
    assert res.get("generated_by") == "ollama"


def test_7_secure_version_without_code(assistant):
    res = assistant.ask("Give me the secure version of this code.")
    assert res.get("generated_by") == "ollama"
    assert res.get("answer") == EXPECTED_REQUEST_CODE_ANSWER


def test_8_what_is_football(assistant):
    res = assistant.ask("What is football?")
    assert res.get("generated_by") == "ollama"
    assert res.get("source") == "ollama_rag"
    assert res.get("answer") == EXPECTED_UNSUPPORTED_ANSWER


def test_9_followup_question(assistant):
    res1 = assistant.ask("What is SQL Injection?")
    assert "SQL" in res1.get("answer")
    res2 = assistant.ask("Why is it dangerous?")
    assert res2.get("generated_by") == "ollama"
