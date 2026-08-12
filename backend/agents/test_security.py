import os
from backend.agents.security_agent import SecurityAgent

file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "test_files", "security_test.py"))
with open(file_path, "r", encoding="utf-8") as f:
    code = f.read()

agent = SecurityAgent()

results = agent.analyze(code)

for r in results:
    print(r)