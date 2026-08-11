import json
import logging
from typing import List, Dict, Any, Tuple

from backend.llm.ollama_service import ollama_service

logger = logging.getLogger(__name__)


class PRSummaryAgent:
    """
    PR Summary Agent that aggregates analysis findings and remediation suggestions
    into a professional, mentor-style Pull Request code review summary.
    """

    SEVERITY_WEIGHTS = {
        "critical": 20,
        "high": 10,
        "medium": 5,
        "low": 2
    }

    SEVERITY_RANK = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }

    def generate_summary(self, findings, remediations=None, security_findings=None) -> Dict[str, Any]:
        """
        Main entry point for generating a Pull Request review summary.
        Accepts findings (list or dict), optional remediations, and optional security_findings.
        """
        all_findings, all_remediations = self._normalize_inputs(findings, remediations, security_findings)

        code_findings = [f for f in all_findings if f.get("agent") == "Code Analysis"]
        sec_findings = [f for f in all_findings if f.get("agent") == "Security"]

        # If agent tag is missing, classify based on presence in security keywords
        if not code_findings and not sec_findings and all_findings:
            code_findings, sec_findings = self._classify_unlabeled_findings(all_findings)

        # 1. Preserved Scoring & Metrics Calculation
        code_quality_score = self._calculate_score(code_findings)
        security_score = self._calculate_score(sec_findings)
        counts = self._calculate_counts(all_findings)

        # 2. Rule-Based Summary Fallbacks
        rule_status = self._determine_status(counts, security_score, code_quality_score)
        rule_top_risks = self._extract_top_risks(all_findings, limit=5)
        rule_code_quality_summary = self._build_code_quality_summary(code_findings, code_quality_score)
        rule_security_summary = self._build_security_summary(sec_findings, security_score)
        rule_positive_observations = self._build_positive_observations(all_findings, code_findings, sec_findings)
        rule_recommended_next_steps = self._build_recommended_next_steps(all_findings, all_remediations)
        rule_estimated_effort = self._estimate_effort(counts)
        rule_developer_comment = self._build_developer_comment(
            overall_status=rule_status,
            code_quality_score=code_quality_score,
            security_score=security_score,
            counts=counts,
            top_risks=rule_top_risks,
            recommended_next_steps=rule_recommended_next_steps
        )

        # 3. Attempt Ollama LLM Summary Generation
        try:
            ollama_data = self._ollama_generate_summary(
                all_findings=all_findings,
                all_remediations=all_remediations,
                code_quality_score=code_quality_score,
                security_score=security_score,
                counts=counts
            )
            overall_status = ollama_data.get("overall_status") or rule_status
            top_risks = ollama_data.get("top_risks") if isinstance(ollama_data.get("top_risks"), list) else rule_top_risks
            code_quality_summary = ollama_data.get("code_quality_summary") or rule_code_quality_summary
            security_summary = ollama_data.get("security_summary") or rule_security_summary
            positive_observations = ollama_data.get("positive_observations") if isinstance(ollama_data.get("positive_observations"), list) else rule_positive_observations
            recommended_next_steps = ollama_data.get("recommended_next_steps") if isinstance(ollama_data.get("recommended_next_steps"), list) else rule_recommended_next_steps
            estimated_effort = ollama_data.get("estimated_remediation_effort") if isinstance(ollama_data.get("estimated_remediation_effort"), dict) else rule_estimated_effort
            developer_comment = ollama_data.get("developer_comment") or rule_developer_comment

        except Exception as e:
            logger.warning(f"Ollama PR Summary generation failed ({str(e)}). Falling back to rule-based PR summary.")
            overall_status = rule_status
            top_risks = rule_top_risks
            code_quality_summary = rule_code_quality_summary
            security_summary = rule_security_summary
            positive_observations = rule_positive_observations
            recommended_next_steps = rule_recommended_next_steps
            estimated_effort = rule_estimated_effort
            developer_comment = rule_developer_comment

        return {
            "overall_status": overall_status,
            "overall_code_quality": code_quality_score,
            "overall_security_score": security_score,
            "summary": counts,
            "top_risks": top_risks,
            "code_quality_summary": code_quality_summary,
            "security_summary": security_summary,
            "positive_observations": positive_observations,
            "recommended_next_steps": recommended_next_steps,
            "estimated_remediation_effort": estimated_effort,
            "developer_comment": developer_comment
        }

    def summarize(self, findings, remediations=None, security_findings=None) -> Dict[str, Any]:
        """Alias for generate_summary to preserve compatibility."""
        return self.generate_summary(findings, remediations, security_findings)

    def analyze(self, findings, remediations=None, security_findings=None) -> Dict[str, Any]:
        """Alias for generate_summary to preserve compatibility."""
        return self.generate_summary(findings, remediations, security_findings)

    def _ollama_generate_summary(
        self,
        all_findings: list,
        all_remediations: list,
        code_quality_score: int,
        security_score: int,
        counts: dict
    ) -> dict:
        """
        Calls Ollama LLM to generate a mentor-style Pull Request review summary.
        """
        if ollama_service is None:
            raise RuntimeError("Ollama service module unavailable.")

        client = ollama_service

        compact_findings = []
        for f in all_findings[:8]:
            compact_findings.append({
                "issue": f.get("issue"),
                "severity": f.get("severity")
            })

        prompt = f"""You are a senior engineer mentoring a junior developer on a Pull Request.

Metrics:
- Code Quality Score: {code_quality_score}/100
- Security Score: {security_score}/100
- Findings: {json.dumps(counts)}
- Top Issues: {json.dumps(compact_findings)}

Return a concise JSON object:
{{
  "overall_status": "Approved | Approved with Suggestions | Needs Changes | Rejected",
  "top_risks": ["1. Fix critical security issues"],
  "code_quality_summary": "Brief 1-sentence code quality assessment.",
  "security_summary": "Brief 1-sentence security assessment.",
  "positive_observations": ["Good effort on structure."],
  "recommended_next_steps": ["Address high severity security findings first."],
  "estimated_remediation_effort": {{
    "critical": "0 hours",
    "high": "1 hour",
    "overall": "Low"
  }},
  "developer_comment": "### PR Review Summary\\n**Status**: {counts.get('critical', 0)} critical issues found. Please address security findings before merging."
}}
"""

        system_prompt = "You are a supportive senior engineer mentoring junior developers. Output valid JSON only."
        result = client.generate_json(prompt=prompt, system_prompt=system_prompt, temperature=0.1, max_tokens=250)

        if not isinstance(result, dict):
            raise ValueError("Ollama returned non-dictionary JSON.")

        valid_statuses = {"Approved", "Approved with Suggestions", "Needs Changes", "Rejected"}
        if result.get("overall_status") not in valid_statuses:
            result["overall_status"] = "Needs Changes" if counts["critical"] > 0 or counts["high"] > 0 else "Approved with Suggestions"

        return result

    # --------------------------------------------------------------------------
    # Helper Rule-Based Methods (Fallback)
    # --------------------------------------------------------------------------

    def _normalize_inputs(self, findings, remediations=None, security_findings=None) -> Tuple[list, list]:
        all_findings = []
        all_remediations = []

        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except Exception:
                findings = []

        if isinstance(remediations, str):
            try:
                remediations = json.loads(remediations)
            except Exception:
                remediations = []

        if isinstance(findings, dict):
            if "findings" in findings and isinstance(findings["findings"], list):
                all_findings.extend(findings["findings"])
            if "remediations" in findings and isinstance(findings["remediations"], list):
                all_remediations.extend(findings["remediations"])
            if "code_analysis" in findings and isinstance(findings["code_analysis"], list):
                for f in findings["code_analysis"]:
                    f["agent"] = "Code Analysis"
                    all_findings.append(f)
            if "security" in findings and isinstance(findings["security"], list):
                for f in findings["security"]:
                    f["agent"] = "Security"
                    all_findings.append(f)
        elif isinstance(findings, list):
            all_findings.extend(findings)

        if isinstance(security_findings, list):
            for f in security_findings:
                if isinstance(f, dict):
                    f["agent"] = "Security"
                    all_findings.append(f)

        if isinstance(remediations, list):
            all_remediations.extend(remediations)

        return all_findings, all_remediations

    def _classify_unlabeled_findings(self, findings) -> Tuple[list, list]:
        sec_keywords = {"sql", "xss", "auth", "permission", "traversal", "injection", "eval", "exec", "crypto", "secret", "password", "ssrf", "pickle", "shell"}
        code_findings = []
        sec_findings = []

        for f in findings:
            issue = f.get("issue", "").lower()
            if any(kw in issue for kw in sec_keywords):
                sec_findings.append(f)
            else:
                code_findings.append(f)

        return code_findings, sec_findings

    def _calculate_score(self, findings) -> int:
        total_deduction = 0
        for f in findings:
            severity = f.get("severity", "low").lower()
            penalty = self.SEVERITY_WEIGHTS.get(severity, 2)
            total_deduction += penalty

        return max(0, 100 - total_deduction)

    def _calculate_counts(self, findings) -> dict:
        counts = {
            "total_findings": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["low"] += 1
        return counts

    def _determine_status(self, counts: dict, security_score: int, code_quality_score: int) -> str:
        if counts["critical"] > 0 or security_score < 40:
            return "Rejected"
        elif counts["high"] > 0 or security_score < 70 or code_quality_score < 60:
            return "Needs Changes"
        elif counts["medium"] > 0 or counts["low"] > 2:
            return "Approved with Suggestions"
        else:
            return "Approved"

    def _extract_top_risks(self, findings, limit=5) -> list:
        sorted_findings = sorted(
            findings,
            key=lambda f: self.SEVERITY_RANK.get(f.get("severity", "").lower(), 0),
            reverse=True
        )

        top_risks = []
        for i, f in enumerate(sorted_findings[:limit], 1):
            line = f.get("line", 0)
            sev = f.get("severity", "Medium")
            issue = f.get("issue", "Issue")
            explanation = f.get("explanation", "")
            risk_str = f"Priority {i} - Line {line} [{sev}]: {issue}"
            if explanation:
                risk_str += f" ({explanation})"
            top_risks.append(risk_str)

        return top_risks

    def _build_code_quality_summary(self, code_findings, score: int) -> str:
        if not code_findings:
            return "Great work! Your code quality is clean, readable, and easy to maintain."
        elif score >= 80:
            return f"Good code quality ({score}/100) with minor maintainability suggestions to clean up."
        elif score >= 60:
            return f"Fair code quality ({score}/100). Consider breaking down long functions to improve readability."
        else:
            return f"Code quality needs improvement ({score}/100). High complexity or duplication detected."

    def _build_security_summary(self, sec_findings, score: int) -> str:
        if not sec_findings:
            return "Security checks passed! No security vulnerabilities were detected in your code."
        elif score >= 80:
            return f"Security posture is solid ({score}/100), but minor items require attention."
        elif score >= 50:
            return f"Security posture has notable items ({score}/100) that should be fixed before merging."
        else:
            return f"Critical security items flagged ({score}/100). Please resolve these before deployment."

    def _build_positive_observations(self, all_findings, code_findings, sec_findings) -> list:
        positives = []
        critical_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "high")

        if critical_count == 0:
            positives.append("No critical security vulnerabilities were found.")
        if high_count == 0:
            positives.append("Zero high-severity security issues or exposed passwords detected.")
        if len(code_findings) == 0:
            positives.append("Code structure is clean, modular, and follows Python style guidelines.")
        if len(sec_findings) == 0:
            positives.append("Passed automated security scanning with clean results.")

        if not positives:
            positives.append("Code is formatted cleanly and adheres to standard Python syntax.")

        return positives

    def _build_recommended_next_steps(self, all_findings, remediations) -> list:
        steps = []
        critical_findings = [f for f in all_findings if f.get("severity", "").lower() == "critical"]
        high_findings = [f for f in all_findings if f.get("severity", "").lower() == "high"]
        other_findings = [f for f in all_findings if f.get("severity", "").lower() in ("medium", "low")]

        if critical_findings:
            issues = ", ".join({f.get("issue", "Critical issue") for f in critical_findings[:2]})
            steps.append(f"1. Immediately resolve Critical security items ({issues}).")
        if high_findings:
            steps.append(f"2. Fix High-severity issues before merging the PR.")
        if other_findings:
            steps.append(f"3. Address minor code quality and readability suggestions.")

        if remediations:
            steps.append("4. Apply the provided step-by-step code fixes.")

        if not steps:
            steps.append("Everything looks great! Ready to merge.")

        return steps

    def _estimate_effort(self, counts: dict) -> dict:
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        total = counts.get("total_findings", 0)

        crit_effort = f"{crit * 2} hours" if crit > 0 else "0 hours"
        high_effort = f"{high * 1.5:.1f} hours" if high > 0 else "0 hours"

        if crit > 0 or high > 3:
            overall_effort = "High (1-2 days)"
        elif high > 0 or total > 5:
            overall_effort = "Moderate (3-5 hours)"
        elif total > 0:
            overall_effort = "Low (1-2 hours)"
        else:
            overall_effort = "None (Ready to merge)"

        return {
            "critical": crit_effort,
            "high": high_effort,
            "overall": overall_effort
        }

    def _build_developer_comment(self, overall_status, code_quality_score, security_score, counts, top_risks, recommended_next_steps) -> str:
        status_icon = {
            "Approved": "✅",
            "Approved with Suggestions": "⚡",
            "Needs Changes": "⚠️",
            "Rejected": "❌"
        }.get(overall_status, "🔍")

        comment = [
            f"## {status_icon} Pull Request Review Summary",
            f"**Overall Status:** `{overall_status}`",
            f"**Security Score:** `{security_score}/100` | **Code Quality Score:** `{code_quality_score}/100`",
            "",
            "### Executive Summary",
            f"Thanks for submitting this pull request! The code has been reviewed for security and readability.",
            f"We found **{counts['total_findings']} total findings** ({counts['critical']} Critical, {counts['high']} High, {counts['medium']} Medium, {counts['low']} Low).",
            ""
        ]

        if top_risks:
            comment.append("### Priority Fix Order (Top Issues)")
            for risk in top_risks:
                comment.append(f"- {risk}")
            comment.append("")

        if recommended_next_steps:
            comment.append("### Recommended Next Steps")
            for step in recommended_next_steps:
                comment.append(f"- {step}")
            comment.append("")

        comment.append("### Overall Recommendation")
        comment.append(f"Status: **{overall_status}**. Please review the suggestions above to finalize your code!")
        comment.append("")
        comment.append("---")
        comment.append("*Automated Senior Engineer Code Reviewer*")

        return "\n".join(comment)
