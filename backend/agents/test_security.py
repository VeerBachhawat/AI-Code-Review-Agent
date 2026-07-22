from security_agent import SecurityAgent

with open("../../test_files/security_test.py", "r") as f:
    code = f.read()

agent = SecurityAgent()

results = agent.analyze(code)

for r in results:
    print(r)