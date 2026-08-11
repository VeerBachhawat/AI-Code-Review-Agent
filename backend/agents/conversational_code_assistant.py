"""
Conversational Code Assistant
=============================
Deterministic, LLM-Free AI Assistant for SentinelAI.
Zero LLM dependencies (No Ollama, No Groq, No OpenAI, No external API calls).
Operates 100% offline using local in-memory rules and knowledge engine.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.knowledge.assistant_knowledge import assistant_knowledge_engine

logger = logging.getLogger("ConversationalCodeAssistant")
logger.setLevel(logging.INFO)


class ConversationalCodeAssistant:
    """
    Deterministic Local Knowledge Conversational Assistant.
    Provides instantaneous, offline Q&A responses grounded strictly in:
    - OWASP Top 10 Security Standards
    - PEP 8 Guidelines
    - AST Analysis Rules
    - SentinelAI SecurityAgent Rules
    - SentinelAI CodeAnalysisAgent Rules
    - SentinelAI Remediation Rules
    """

    def __init__(self, source: str = "local_knowledge") -> None:
        self.source = source
        self.knowledge_engine = assistant_knowledge_engine
        # Hard Safety Guarantee: Zero LLM attributes present

    def answer(self, question: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Unified answer interface receiving question and optional context dict.
        """
        context = context or {}
        return self.ask(
            question=question,
            optional_findings=context.get("optional_findings") or context.get("findings"),
            optional_code=context.get("optional_code") or context.get("code"),
            remediations=context.get("remediations"),
            pr_summary=context.get("pr_summary"),
            code_quality_score=context.get("code_quality_score"),
            security_score=context.get("security_score")
        )

    def ask(
        self,
        question: Any,
        optional_findings: Optional[List[Dict[str, Any]]] = None,
        optional_code: Optional[str] = None,
        remediations: Optional[List[Dict[str, Any]]] = None,
        pr_summary: Optional[Dict[str, Any]] = None,
        code_quality_score: Optional[int] = None,
        security_score: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Main entry point for developer questions.
        Operates completely offline without any LLM call.
        """
        start_time = time.perf_counter()

        (
            q_text,
            findings,
            code,
            remediation_list,
            pr_sum,
            cq_score,
            sec_score
        ) = self._normalize_inputs(
            question=question,
            optional_findings=optional_findings,
            optional_code=optional_code,
            remediations=remediations,
            pr_summary=pr_summary,
            code_quality_score=code_quality_score,
            security_score=security_score
        )

        if not q_text:
            q_text = "Explain the security and quality analysis of this code."

        # Query the Deterministic Local Knowledge Engine
        response = self.knowledge_engine.query(
            question=q_text,
            findings=findings,
            code=code,
            remediations=remediation_list,
            pr_summary=pr_sum,
            code_quality_score=cq_score,
            security_score=sec_score
        )

        elapsed = time.perf_counter() - start_time

        return {
            "question": q_text,
            "answer": response["answer"],
            "source": self.source,
            "sources": response.get("sources", [{"document": self.source, "score": 1.0}]),
            "related_topics": response.get("related_topics", []),
            "model": "local_knowledge_engine",
            "generated_by": "local_knowledge_engine"
        }

    def query(self, question: Any, **kwargs) -> Dict[str, Any]:
        """Alias for ask method to maintain API compatibility."""
        return self.ask(question, **kwargs)

    def chat(self, question: Any, **kwargs) -> Dict[str, Any]:
        """Alias for ask method to maintain API compatibility."""
        return self.ask(question, **kwargs)

    # --------------------------------------------------------------------------
    # Input Normalization Helper
    # --------------------------------------------------------------------------

    def _normalize_inputs(
        self,
        question: Any,
        optional_findings: Optional[List[Dict[str, Any]]],
        optional_code: Optional[str],
        remediations: Optional[List[Dict[str, Any]]],
        pr_summary: Optional[Dict[str, Any]],
        code_quality_score: Optional[int],
        security_score: Optional[int]
    ) -> Tuple[str, List[Dict[str, Any]], str, List[Dict[str, Any]], Dict[str, Any], int, int]:
        q_text = ""
        findings = optional_findings or []
        code = optional_code or ""
        rem_list = remediations or []
        pr_sum = pr_summary or {}
        cq_score = code_quality_score if code_quality_score is not None else 100
        sec_score = security_score if security_score is not None else 100

        if isinstance(question, dict):
            q_text = question.get("question", "")
            findings = question.get("optional_findings", question.get("findings", findings))
            code = question.get("optional_code", question.get("code", question.get("source_code", code)))
            rem_list = question.get("remediations", question.get("remediation", rem_list))
            pr_sum = question.get("pr_summary", pr_sum)
            cq_score = question.get("code_quality_score", cq_score)
            sec_score = question.get("security_score", sec_score)
        elif isinstance(question, str):
            q_text = question

        if findings and (code_quality_score is None or security_score is None):
            critical_cnt = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
            high_cnt = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
            medium_cnt = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
            low_cnt = sum(1 for f in findings if str(f.get("severity", "")).lower() == "low")

            if security_score is None:
                sec_score = max(0, 100 - (critical_cnt * 25 + high_cnt * 15 + medium_cnt * 5))
            if code_quality_score is None:
                cq_score = max(0, 100 - (high_cnt * 10 + medium_cnt * 5 + low_cnt * 2))

        return q_text.strip(), findings, code.strip(), rem_list, pr_sum, cq_score, sec_score
