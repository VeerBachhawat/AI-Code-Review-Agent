"""
Unit and integration tests for ConversationalCodeAssistant
Path: backend/agents/test_conversational_code_assistant.py
Runs via: python -m pytest backend/agents/test_conversational_code_assistant.py -v
"""
import pytest
import time
from backend.agents.conversational_code_assistant import ConversationalCodeAssistant

EXPECTED_UNSUPPORTED_ANSWER = (
    "I can only answer questions related to SentinelAI's secure coding knowledge, "
    "including OWASP Top 10, PEP 8, AST analysis, security vulnerabilities, code analysis, and remediation rules."
)

EXPECTED_REQUEST_CODE_ANSWER = (
    "Please provide the code you want me to secure, or select a code-review finding. "
    "I can then apply SentinelAI's existing security and remediation rules."
)


@pytest.fixture
def assistant():
    return ConversationalCodeAssistant()


def test_1_what_is_iphone(assistant):
    res = assistant.ask("What is iPhone?")
    assert res.get("generated_by") == "local_knowledge_engine"
    assert res.get("source") == "local_knowledge"
    assert res.get("answer") == EXPECTED_UNSUPPORTED_ANSWER


def test_2_explain_cyclomatic_complexity(assistant):
    res = assistant.ask("Explain Cyclomatic Complexity.")
    assert res.get("generated_by") == "local_knowledge_engine"
    assert "Cyclomatic Complexity" in res.get("answer")
    assert "Maintainability" in res.get("answer") or "McCabe" in res.get("answer")


def test_3_what_is_sql_injection(assistant):
    res = assistant.ask("What is SQL Injection?")
    assert res.get("generated_by") == "local_knowledge_engine"
    assert "OWASP" in res.get("answer") or "SQL Injection" in res.get("answer")


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
    assert res.get("generated_by") == "local_knowledge_engine"
    assert "Security Remediation" in res.get("answer") or "SQL Injection" in res.get("answer")


def test_5_fix_hardcoded_password_with_finding(assistant):
    findings = [
        {"line": 5, "severity": "High", "issue": "Hardcoded Password", "explanation": "Plaintext secret DB_PASS.", "secure_code": "import os\ndb_pass = os.getenv('DB_PASS')"}
    ]
    res = assistant.ask(
        question="Fix this hardcoded password.",
        optional_findings=findings
    )
    assert res.get("generated_by") == "local_knowledge_engine"
    assert "Hardcoded Password" in res.get("answer") or "os.getenv" in res.get("answer")


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
    assert res.get("generated_by") == "local_knowledge_engine"
    assert "Dynamic Code Execution" in res.get("answer") or "eval" in res.get("answer")


def test_7_secure_version_without_code(assistant):
    res = assistant.ask("Give me the secure version of this code.")
    assert res.get("generated_by") == "local_knowledge_engine"
    assert res.get("answer") == EXPECTED_REQUEST_CODE_ANSWER


def test_8_what_is_football(assistant):
    res = assistant.ask("What is football?")
    assert res.get("generated_by") == "local_knowledge_engine"
    assert res.get("source") == "local_knowledge"
    assert res.get("answer") == EXPECTED_UNSUPPORTED_ANSWER
