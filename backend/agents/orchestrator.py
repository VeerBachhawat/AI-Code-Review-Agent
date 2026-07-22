from concurrent.futures import ThreadPoolExecutor

from .code_analysis_agent import CodeAnalysisAgent
from .security_agent import SecurityAgent

class Orchestrator:

    def __init__(self):
        self.code_agent = CodeAnalysisAgent()
        self.security_agent = SecurityAgent()

    def review(self, code):

        with ThreadPoolExecutor(max_workers=2) as executor:

            future_code = executor.submit(self.code_agent.analyze, code)
            future_security = executor.submit(self.security_agent.analyze, code)

            code_findings = future_code.result()
            security_findings = future_security.result()

        findings = code_findings + security_findings

        summary = {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "Critical"),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low")
        }

        return {
            "summary": summary,
            "findings": findings
        }