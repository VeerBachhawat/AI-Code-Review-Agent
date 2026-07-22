from orchestrator import Orchestrator

with open("../../test_files/full_test.py") as f:
    code = f.read()

result = Orchestrator().review(code)

print("\nSUMMARY")
print(result["summary"])

print("\nFINDINGS")

for finding in result["findings"]:
    print(finding)