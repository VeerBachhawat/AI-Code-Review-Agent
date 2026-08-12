"""
Test /chat API endpoint with FastAPI TestClient for Hybrid RAG Conversational Assistant (Ollama qwen3:8b).
"""
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from backend.main import app, assistant

client = TestClient(app)

EXPECTED_UNSUPPORTED = (
    "I can help with SentinelAI topics such as secure coding, "
    "OWASP, PEP 8, AST analysis, vulnerabilities, code analysis, "
    "and remediation. I don't have relevant SentinelAI knowledge for this question."
)

EXPECTED_REQUEST_CODE = (
    "Please provide the code you want me to secure, or select a code-review finding. "
    "I can then apply SentinelAI's existing security and remediation rules."
)

def test_chat_offline_all_intents():
    # Mock Ollama service for deterministic offline endpoint testing
    assistant.ollama_service.generate_chat = MagicMock(side_effect=lambda system_prompt, user_prompt, history=None: (
        "Secure Code Example:\n```python\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n```"
        if "secure version" in user_prompt.lower() or "corrected code" in user_prompt.lower() or "fix" in user_prompt.lower() else
        "SQL Injection allows attackers to manipulate database queries. Use parameterized queries (%s placeholders)."
        if "SQL" in user_prompt else
        "Cyclomatic complexity counts linearly independent execution paths."
        if "Cyclomatic" in user_prompt else
        "Grounded response based on retrieved SentinelAI context."
    ))

    print("\n========================================================")
    print("RUNNING SENTINELAI HYBRID RAG /CHAT ENDPOINT TESTS")
    print("========================================================\n")

    # 1. Unsupported Question: "What is iPhone?"
    r1 = client.post("/chat", json={"question": "What is iPhone?"})
    assert r1.status_code == 200
    d1 = r1.json()
    print("[1/8] Question: 'What is iPhone?'")
    print("      Category: UNSUPPORTED | Source:", d1["source"])
    assert d1["answer"] == EXPECTED_UNSUPPORTED
    assert d1["generated_by"] == "ollama"
    assert d1["model"] == "qwen3:8b"

    # 2. Code Analysis: "Explain Cyclomatic Complexity."
    r2 = client.post("/chat", json={"question": "Explain Cyclomatic Complexity."})
    assert r2.status_code == 200
    d2 = r2.json()
    print("[2/8] Question: 'Explain Cyclomatic Complexity.'")
    print("      Category: CODE_ANALYSIS | Source:", d2["source"])
    assert "Cyclomatic" in d2["answer"]

    # 3. Security: "What is SQL Injection?"
    r3 = client.post("/chat", json={"question": "What is SQL Injection?"})
    assert r3.status_code == 200
    d3 = r3.json()
    print("[3/8] Question: 'What is SQL Injection?'")
    print("      Category: SECURITY | Source:", d3["source"])
    assert "SQL Injection" in d3["answer"] or "SQL" in d3["answer"]

    # 4. Remediation (WITH Code + Finding): "Give me the secure version of this code."
    r4 = client.post("/chat", json={
        "question": "Give me the secure version of this code.",
        "optional_code": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        "optional_findings": [{"line": 1, "severity": "Critical", "issue": "SQL Injection", "explanation": "Concatenated query."}]
    })
    assert r4.status_code == 200
    d4 = r4.json()
    print("[4/8] Question: 'Give me the secure version of this code.' (WITH Code + Finding)")
    print("      Category: REMEDIATION | Source:", d4["source"])
    assert d4["generated_by"] == "ollama"

    # 5. Remediation (WITH Finding): "Fix this hardcoded password."
    r5 = client.post("/chat", json={
        "question": "Fix this hardcoded password.",
        "optional_findings": [{"line": 5, "severity": "High", "issue": "Hardcoded Password", "explanation": "DB secret exposed."}]
    })
    assert r5.status_code == 200
    d5 = r5.json()
    print("[5/8] Question: 'Fix this hardcoded password.' (WITH Finding)")
    print("      Category: REMEDIATION | Source:", d5["source"])
    assert d5["generated_by"] == "ollama"

    # 6. Remediation (WITH Context): "Show me corrected code."
    r6 = client.post("/chat", json={
        "question": "Show me corrected code.",
        "optional_code": "eval(user_input)",
        "optional_findings": [{"line": 1, "severity": "Critical", "issue": "Dynamic Code Execution"}]
    })
    assert r6.status_code == 200
    d6 = r6.json()
    print("[6/8] Question: 'Show me corrected code.' (WITH Context)")
    print("      Category: REMEDIATION | Source:", d6["source"])
    assert d6["generated_by"] == "ollama"

    # 7. Remediation (WITHOUT Code): "Give me the secure version of this code."
    r7 = client.post("/chat", json={"question": "Give me the secure version of this code."})
    assert r7.status_code == 200
    d7 = r7.json()
    print("[7/8] Question: 'Give me the secure version of this code.' (WITHOUT Code)")
    print("      Category: REQUEST_CODE | Source:", d7["source"])
    assert d7["answer"] == EXPECTED_REQUEST_CODE

    # 8. Unsupported Question: "What is football?"
    r8 = client.post("/chat", json={"question": "What is football?"})
    assert r8.status_code == 200
    d8 = r8.json()
    print("[8/8] Question: 'What is football?'")
    print("      Category: UNSUPPORTED | Source:", d8["source"])
    assert d8["answer"] == EXPECTED_UNSUPPORTED

    print("\n========================================================")
    print("ALL 8 HYBRID RAG CHAT TESTS PASSED SUCCESSFULLY!")
    print("========================================================\n")

if __name__ == "__main__":
    test_chat_offline_all_intents()
