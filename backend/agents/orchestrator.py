from concurrent.futures import ThreadPoolExecutor
import logging
import time
from typing import Any, Dict, List, Tuple

from backend.agents.code_analysis_agent import CodeAnalysisAgent
from backend.agents.security_agent import SecurityAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.pr_summary_agent import PRSummaryAgent

# Configure logger
logger = logging.getLogger("Orchestrator")
logger.setLevel(logging.INFO)


class Orchestrator:
    """
    Multi-Agent Orchestrator managing concurrent static code analysis,
    security scanning, automated remediation generation, and PR review summarization.
    """

    def __init__(self) -> None:
        self.code_agent = CodeAnalysisAgent()
        self.security_agent = SecurityAgent()
        self.remediation_agent = RemediationAgent()
        self.pr_summary_agent = PRSummaryAgent()

    def review(self, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Main execution pipeline that runs Code Analysis & Security scanning concurrently,
        merges findings, generates remediations, and compiles a PR summary.
        """
        from backend.llm.ollama_service import ollama_service
        if ollama_service:
            ollama_service.reset_call_count()

        total_start = time.perf_counter()
        agent_status: Dict[str, str] = {
            "code_analysis": "pending",
            "security": "pending",
            "remediation": "pending",
            "pr_summary": "pending"
        }

        # Step 1: Run Code Analysis and Security agents concurrently
        t0 = time.perf_counter()
        code_findings, security_findings, agent_status = self._run_concurrent_analysis(code, agent_status)
        analysis_time = time.perf_counter() - t0
        logger.info(f"[PERF] AST & Security analysis: {analysis_time:.2f}s")

        # Step 2: Merge Findings
        merged_findings = self._merge_findings(code_findings, security_findings)

        # Step 3: Run Remediation Agent with source code context
        t1 = time.perf_counter()
        remediations, agent_status = self._run_remediation_agent(merged_findings, code, agent_status)
        remediation_time = time.perf_counter() - t1
        logger.info(f"[PERF] Ollama remediation: {remediation_time:.2f}s")

        # Step 4: Run PR Summary Agent
        t2 = time.perf_counter()
        pr_summary, agent_status = self._run_pr_summary_agent(merged_findings, remediations, agent_status)
        summary_time = time.perf_counter() - t2
        logger.info(f"[PERF] Ollama summary: {summary_time:.2f}s")

        # Step 5: Build Summary Metrics
        summary_metrics = self._build_summary_metrics(merged_findings, agent_status)

        total_elapsed = time.perf_counter() - total_start
        elapsed_time_ms = round(total_elapsed * 1000, 2)

        total_ollama_calls = ollama_service.call_count if ollama_service else 0

        logger.info(f"[PERF] TOTAL REVIEW: {total_elapsed:.2f}s")
        logger.info(f"[OLLAMA] TOTAL CALLS: {total_ollama_calls}")

        return {
            "status": "success",
            "language": language.lower(),
            "execution_time_ms": elapsed_time_ms,
            "summary": summary_metrics,
            "findings": merged_findings,
            "remediation": remediations,
            "pr_summary": pr_summary
        }

    def analyze(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Alias for review to preserve API compatibility."""
        return self.review(code, language)

    def analyze_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Alias for review to preserve API compatibility."""
        return self.review(code, language)

    def run(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Alias for review to preserve API compatibility."""
        return self.review(code, language)

    # --------------------------------------------------------------------------
    # Pipeline Step Implementations
    # --------------------------------------------------------------------------

    def _run_concurrent_analysis(self, code: str, agent_status: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str]]:
        code_findings: List[Dict[str, Any]] = []
        security_findings: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=2) as executor:
            future_code = executor.submit(self._safe_execute_agent, "code_analysis", self.code_agent.analyze, code)
            future_security = executor.submit(self._safe_execute_agent, "security", self.security_agent.analyze, code)

            code_res, code_status = future_code.result()
            sec_res, sec_status = future_security.result()

            agent_status["code_analysis"] = code_status
            agent_status["security"] = sec_status

            if isinstance(code_res, list):
                code_findings = code_res
            else:
                code_findings = [code_res]

            if isinstance(sec_res, list):
                security_findings = sec_res
            else:
                security_findings = [sec_res]

        return code_findings, security_findings, agent_status

    def _safe_execute_agent(self, name: str, agent_func, code: str) -> Tuple[Any, str]:
        try:
            logger.info(f"Starting execution of agent: {name}")
            result = agent_func(code)
            logger.info(f"Agent {name} completed successfully.")
            return result, "success"
        except Exception as e:
            logger.error(f"Agent {name} failed with error: {str(e)}", exc_info=True)
            error_finding = {
                "agent": name.replace("_", " ").title(),
                "status": "failed",
                "severity": "High",
                "issue": f"{name.replace('_', ' ').title()} Failure",
                "explanation": f"Agent failed during execution: {str(e)}",
                "line": 0,
                "error": str(e)
            }
            return [error_finding], "failed"

    def _merge_findings(self, code_findings: List[Dict[str, Any]], security_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged = []
        merged.extend(code_findings)
        merged.extend(security_findings)
        return merged

    def _run_remediation_agent(self, findings: List[Dict[str, Any]], code: str, agent_status: Dict[str, str]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        try:
            logger.info("Executing RemediationAgent...")
            remediations = self.remediation_agent.generate_remediation(findings, source_code=code)
            agent_status["remediation"] = "success"
            return remediations, agent_status
        except Exception as e:
            logger.error(f"RemediationAgent failed: {str(e)}", exc_info=True)
            agent_status["remediation"] = "failed"
            fallback_remediation = [{
                "issue": "Remediation Agent Error",
                "severity": "Low",
                "line": 0,
                "why_it_is_problematic": f"Remediation engine encountered an error: {str(e)}",
                "recommended_fix": "Refer to standard security documentation for manual remediation guidance.",
                "corrected_code_example": f"# Error during remediation: {str(e)}",
                "best_practice": "Ensure code adheres to OWASP guidelines and PEP 8 standards.",
                "references": ["OWASP Guidelines"]
            }]
            return fallback_remediation, agent_status

    def _run_pr_summary_agent(self, findings: List[Dict[str, Any]], remediations: List[Dict[str, Any]], agent_status: Dict[str, str]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        try:
            logger.info("Executing PRSummaryAgent...")
            summary = self.pr_summary_agent.generate_summary(findings, remediations)
            agent_status["pr_summary"] = "success"
            return summary, agent_status
        except Exception as e:
            logger.error(f"PRSummaryAgent failed: {str(e)}", exc_info=True)
            agent_status["pr_summary"] = "failed"
            fallback_pr_summary = {
                "overall_status": "Needs Review",
                "overall_code_quality": 50,
                "overall_security_score": 50,
                "summary": {
                    "total_findings": len(findings),
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "top_risks": ["PR Summary Agent encountered an error during review aggregation."],
                "code_quality_summary": "Summary generation encountered an error.",
                "security_summary": "Summary generation encountered an error.",
                "positive_observations": [],
                "recommended_next_steps": ["Review individual agent findings."],
                "estimated_remediation_effort": {"critical": "Unknown", "high": "Unknown", "overall": "Unknown"},
                "developer_comment": f"⚠️ Automated PR summary failed: {str(e)}"
            }
            return fallback_pr_summary, agent_status

    def _build_summary_metrics(self, findings: List[Dict[str, Any]], agent_status: Dict[str, str]) -> Dict[str, Any]:
        return {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical"),
            "high": sum(1 for f in findings if str(f.get("severity", "")).lower() == "high"),
            "medium": sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium"),
            "low": sum(1 for f in findings if str(f.get("severity", "")).lower() == "low"),
            "agent_status": agent_status
        }