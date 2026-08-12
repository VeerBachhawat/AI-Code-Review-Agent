import os
from backend.agents.orchestrator import Orchestrator

file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "test_files", "full_test.py"))
with open(file_path, "r", encoding="utf-8") as f:
    code = f.read()

result = Orchestrator().review(code)

print("\nSUMMARY")
print(result["summary"])

print("\nFINDINGS")

for finding in result["findings"]:
    print(finding)