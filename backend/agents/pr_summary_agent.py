import json


class PRSummaryAgent:
    """
    PR Summary Agent that aggregates analysis findings and remediation suggestions
    into a professional, executive Pull Request code review summary.
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

    def generate_summary(self, findings, remediations=None, security_findings=None):
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

        # 1. Scoring Calculation
        code_quality_score = self._calculate_score(code_findings)
        security_score = self._calculate_score(sec_findings)

        # 2. Severity Breakdown Counts
        counts = self._calculate_counts(all_findings)

        # 3. Determine Overall Review Status
        overall_status = self._determine_status(counts, security_score, code_quality_score)

        # 4. Extract Top Risks
        top_risks = self._extract_top_risks(all_findings, limit=5)

        # 5. Summaries
        code_quality_summary = self._build_code_quality_summary(code_findings, code_quality_score)
        security_summary = self._build_security_summary(sec_findings, security_score)

        # 6. Positive Observations
        positive_observations = self._build_positive_observations(all_findings, code_findings, sec_findings)

        # 7. Recommended Next Steps
        recommended_next_steps = self._build_recommended_next_steps(all_findings, all_remediations)

        # 8. Estimated Remediation Effort
        estimated_effort = self._estimate_effort(counts)

        # 9. Developer PR Review Comment
        developer_comment = self._build_developer_comment(
            overall_status=overall_status,
            code_quality_score=code_quality_score,
            security_score=security_score,
            counts=counts,
            top_risks=top_risks,
            recommended_next_steps=recommended_next_steps
        )

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

    def summarize(self, findings, remediations=None, security_findings=None):
        """Alias for generate_summary to preserve compatibility."""
        return self.generate_summary(findings, remediations, security_findings)

    def analyze(self, findings, remediations=None, security_findings=None):
        """Alias for generate_summary to preserve compatibility."""
        return self.generate_summary(findings, remediations, security_findings)

    # --------------------------------------------------------------------------
    # Helper Methods
    # --------------------------------------------------------------------------

    def _normalize_inputs(self, findings, remediations=None, security_findings=None):
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

    def _classify_unlabeled_findings(self, findings):
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
        for f in sorted_findings[:limit]:
            line = f.get("line", 0)
            sev = f.get("severity", "Medium")
            issue = f.get("issue", "Issue")
            explanation = f.get("explanation", "")
            risk_str = f"Line {line} [{sev}]: {issue}"
            if explanation:
                risk_str += f" - {explanation}"
            top_risks.append(risk_str)

        return top_risks

    def _build_code_quality_summary(self, code_findings, score: int) -> str:
        if not code_findings:
            return "Code quality is excellent. No code maintainability or style issues were detected."
        elif score >= 80:
            return f"Code quality is good ({score}/100) with minor maintainability suggestions noted."
        elif score >= 60:
            return f"Code quality is fair ({score}/100). Moderate refactoring is recommended for maintainability."
        else:
            return f"Code quality requires improvement ({score}/100). High complexity or duplication detected."

    def _build_security_summary(self, sec_findings, score: int) -> str:
        if not sec_findings:
            return "Security analysis passed cleanly. No security vulnerabilities were detected."
        elif score >= 80:
            return f"Security posture is relatively sound ({score}/100), but minor vulnerabilities require attention."
        elif score >= 50:
            return f"Security posture has significant vulnerabilities ({score}/100) that need remediation before deployment."
        else:
            return f"CRITICAL SECURITY RISK ({score}/100). Critical vulnerabilities detected that must be resolved immediately."

    def _build_positive_observations(self, all_findings, code_findings, sec_findings) -> list:
        positives = []
        critical_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in all_findings if f.get("severity", "").lower() == "high")

        if critical_count == 0:
            positives.append("No critical severity vulnerabilities or system-blocking defects were identified.")
        if high_count == 0:
            positives.append("Zero high-severity security breaches or hardcoded credentials detected.")
        if len(code_findings) == 0:
            positives.append("Code structure adheres cleanly to Python modularity and complexity guidelines.")
        if len(sec_findings) == 0:
            positives.append("Application passed automated AST security scanning with no flagged vulnerabilities.")

        if not positives:
            positives.append("The codebase demonstrates modular layout and standard AST parsing compatibility.")

        return positives

    def _build_recommended_next_steps(self, all_findings, remediations) -> list:
        steps = []
        critical_findings = [f for f in all_findings if f.get("severity", "").lower() == "critical"]
        high_findings = [f for f in all_findings if f.get("severity", "").lower() == "high"]
        other_findings = [f for f in all_findings if f.get("severity", "").lower() in ("medium", "low")]

        if critical_findings:
            issues = ", ".join({f.get("issue", "Critical issue") for f in critical_findings[:2]})
            steps.append(f"Immediately resolve Critical severity security vulnerabilities ({issues}).")
        if high_findings:
            steps.append(f"Remediate {len(high_findings)} High-severity issues prior to merging PR.")
        if other_findings:
            steps.append(f"Address {len(other_findings)} Medium/Low maintainability and code quality suggestions.")

        if remediations:
            steps.append("Apply provided automated code remediation refactoring examples.")

        if not steps:
            steps.append("Proceed with final peer review and merge into target branch.")

        return steps

    def _estimate_effort(self, counts: dict) -> dict:
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        total = counts.get("total_findings", 0)

        crit_effort = f"{crit * 2} hours" if crit > 0 else "0 hours (None detected)"
        high_effort = f"{high * 1.5:.1f} hours" if high > 0 else "0 hours (None detected)"

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
            "### 📊 Findings Breakdown",
            f"- **Total Findings:** {counts['total_findings']}",
            f"- **Critical:** {counts['critical']} | **High:** {counts['high']} | **Medium:** {counts['medium']} | **Low:** {counts['low']}",
            ""
        ]

        if top_risks:
            comment.append("### 🚨 Top Priority Risks")
            for risk in top_risks:
                comment.append(f"- {risk}")
            comment.append("")

        if recommended_next_steps:
            comment.append("### 📋 Recommended Next Steps")
            for step in recommended_next_steps:
                comment.append(f"- {step}")
            comment.append("")

        comment.append("---")
        comment.append("*Automated Code Review & Security Analysis Agent*")

        return "\n".join(comment)
