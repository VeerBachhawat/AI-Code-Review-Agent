"""
Test /chat API endpoint with FastAPI TestClient for all 8 intent & remediation test cases.
Zero LLM / zero Ollama dependency.
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

EXPECTED_UNSUPPORTED = (
    "I can only answer questions related to SentinelAI's secure coding knowledge, "
    "including OWASP Top 10, PEP 8, AST analysis, security vulnerabilities, code analysis, and remediation rules."
)

EXPECTED_REQUEST_CODE = (
    "Please provide the code you want me to secure, or select a code-review finding. "
    "I can then apply SentinelAI's existing security and remediation rules."
)

def test_chat_offline_all_intents():
    print("\n========================================================")
    print("RUNNING SENTINELAI OFFLINE /CHAT ENDPOINT TESTS")
    print("========================================================\n")

    # 1. Unsupported Question: "What is iPhone?"
    r1 = client.post("/chat", json={"question": "What is iPhone?"})
    assert r1.status_code == 200
    d1 = r1.json()
    print("[1/8] Question: 'What is iPhone?'")
    print("      Category: UNSUPPORTED | Source:", d1["source"])
    assert d1["answer"] == EXPECTED_UNSUPPORTED
    assert d1["generated_by"] == "local_knowledge_engine"

    # 2. Code Analysis: "Explain Cyclomatic Complexity."
    r2 = client.post("/chat", json={"question": "Explain Cyclomatic Complexity."})
    assert r2.status_code == 200
    d2 = r2.json()
    print("[2/8] Question: 'Explain Cyclomatic Complexity.'")
    print("      Category: CODE_ANALYSIS | Source:", d2["source"])
    assert "Cyclomatic Complexity" in d2["answer"]

    # 3. Security: "What is SQL Injection?"
    r3 = client.post("/chat", json={"question": "What is SQL Injection?"})
    assert r3.status_code == 200
    d3 = r3.json()
    print("[3/8] Question: 'What is SQL Injection?'")
    print("      Category: SECURITY | Source:", d3["source"])
    assert "SQL Injection" in d3["answer"] or "OWASP" in d3["answer"]

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
    assert "Security Remediation" in d4["answer"] or "SQL Injection" in d4["answer"]

    # 5. Remediation (WITH Finding): "Fix this hardcoded password."
    r5 = client.post("/chat", json={
        "question": "Fix this hardcoded password.",
        "optional_findings": [{"line": 5, "severity": "High", "issue": "Hardcoded Password", "explanation": "DB secret exposed."}]
    })
    assert r5.status_code == 200
    d5 = r5.json()
    print("[5/8] Question: 'Fix this hardcoded password.' (WITH Finding)")
    print("      Category: REMEDIATION | Source:", d5["source"])
    assert "Hardcoded Password" in d5["answer"] or "Remediation" in d5["answer"]

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
    assert "Dynamic Code Execution" in d6["answer"] or "eval" in d6["answer"]

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
    print("ALL 8 INTENT & REMEDIATION TESTS PASSED SUCCESSFULLY!")
    print("========================================================\n")

if __name__ == "__main__":
    test_chat_offline_all_intents()
