from code_analysis_agent import CodeAnalysisAgent

with open("../../test_files/bad_code.py", "r") as f:
    code = f.read()

agent = CodeAnalysisAgent()

result = agent.analyze(code)

for issue in result:
    print(issue)