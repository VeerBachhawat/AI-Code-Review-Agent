import os
from backend.agents.code_analysis_agent import CodeAnalysisAgent

file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "test_files", "bad_code.py"))
with open(file_path, "r", encoding="utf-8") as f:
    code = f.read()

agent = CodeAnalysisAgent()

result = agent.analyze(code)

for issue in result:
    print(issue)