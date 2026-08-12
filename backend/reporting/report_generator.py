import datetime
import html
import os
import re
from typing import Any, Dict, List, Optional

# ReportLab Imports for PDF Generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def sanitize_secret_text(text: Any) -> str:
    """
    Sanitizes strings to prevent exposing credentials, API keys, or tokens in reports.
    """
    if not isinstance(text, str):
        text = str(text) if text is not None else ""

    # Redact common API key & token patterns
    text = re.sub(r'gsk_[A-Za-z0-9_]{20,}', '[REDACTED_API_KEY]', text)
    text = re.sub(r'sk-[A-Za-z0-9_]{20,}', '[REDACTED_API_KEY]', text)
    text = re.sub(r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]', text)
    text = re.sub(r'Bearer\s+[A-Za-z0-9._\-]+', 'Bearer [REDACTED_TOKEN]', text)
    return text


def extract_source_line(source_code: Optional[str], line_num: Any) -> str:
    """
    Extracts the exact line of source code given line_num.
    """
    if not source_code:
        return ""
    try:
        line_int = int(line_num)
        lines = source_code.splitlines()
        if 1 <= line_int <= len(lines):
            return lines[line_int - 1].strip()
    except (ValueError, TypeError):
        pass
    return ""


def normalize_review_payload(review_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensures nested 'review' dictionary is unwrapped if present.
    """
    if isinstance(review_data, dict) and "review" in review_data and isinstance(review_data["review"], dict):
        base = dict(review_data["review"])
        for k in ("code", "source_code", "app_name", "language", "execution_time_ms"):
            if k not in base and k in review_data:
                base[k] = review_data[k]
        return base
    return review_data or {}


def format_pdf_text(text: Any) -> str:
    """
    Escapes text for ReportLab Paragraphs and converts newlines to <br/>.
    """
    sanitized = sanitize_secret_text(text)
    escaped = html.escape(sanitized)
    return escaped.replace("\n", "<br/>")


def truncate_text(text: Any, max_chars: int = 120) -> str:
    """
    Safely truncates long text strings to prevent layout overflow in single-page reports.
    """
    if not text:
        return ""
    text_str = str(text).strip()
    if len(text_str) <= max_chars:
        return text_str
    return text_str[:max_chars - 3].rsplit(' ', 1)[0] + "..."


def get_score_rating(score: Any) -> str:
    """
    Configurable score rating thresholds for enterprise reporting.
    """
    try:
        s = int(score)
    except (ValueError, TypeError):
        s = 100

    if s >= 90:
        return "Excellent / Strong"
    elif s >= 75:
        return "Good / Needs Minor Improvement"
    elif s >= 50:
        return "Needs Improvement"
    else:
        return "Poor / Significant Attention Required"


def format_execution_time(exec_time_ms: Any) -> str:
    """
    Formats genuine execution time in milliseconds or seconds cleanly.
    """
    try:
        ms = float(exec_time_ms)
        if ms >= 1000:
            return f"{ms / 1000:.2f} s"
        return f"{int(ms)} ms"
    except (ValueError, TypeError):
        return "N/A"


def derive_overall_status(data: Dict[str, Any], crit_count: int, high_count: int, total_findings: int) -> str:
    """
    Ensures overall_status strictly matches severity counts and score evaluation.
    """
    pr_summary = data.get("pr_summary") or {}
    status_raw = pr_summary.get("overall_status") or data.get("status")

    if status_raw and str(status_raw).upper() not in ("REVIEWED", "SUCCESS"):
        return str(status_raw).upper()

    if crit_count > 0 or high_count > 0:
        return "NEEDS CHANGES"
    elif total_findings > 0:
        return "APPROVED WITH SUGGESTIONS"
    else:
        return "APPROVED"


def build_executive_assessment(data: Dict[str, Any], crit_count: int, high_count: int, med_count: int, low_count: int, total_findings: int, code_score: int, sec_score: int) -> str:
    """
    Generates a dynamic, non-alarmist executive assessment strictly matching actual severity data.
    """
    pr_summary = data.get("pr_summary") or {}
    sec_sum = (pr_summary.get("security_summary") or "").strip()
    cq_sum = (pr_summary.get("code_quality_summary") or "").strip()

    if total_findings == 0:
        return "Automated security and quality audit completed with zero identified vulnerabilities or code defects. Code posture is optimal for merge."

    if crit_count > 0:
        return truncate_text(
            f"Security posture requires immediate attention to resolve {crit_count} critical vulnerability(ies). "
            f"Code quality is rated {code_score}/100 ({get_score_rating(code_score)}) and security is rated {sec_score}/100. "
            f"Critical findings must be remediated prior to deployment.",
            250
        )

    if high_count > 0:
        sec_label = "one high-severity security issue" if high_count == 1 else f"{high_count} high-severity security issues"
        qual_label = f" and {med_count + low_count} maintainability issue(s)" if (med_count + low_count) > 0 else ""
        return truncate_text(
            f"Overall code health is strong. {sec_label}{qual_label} should be addressed before release. "
            f"Security score is rated {sec_score}/100 ({get_score_rating(sec_score)}).",
            250
        )

    if med_count > 0 or low_count > 0:
        return truncate_text(
            f"Code security is sound with zero critical or high vulnerabilities. {med_count + low_count} routine code quality "
            f"and maintainability improvement(s) are recommended for follow-up refactoring.",
            250
        )

    if sec_sum or cq_sum:
        return truncate_text(f"{sec_sum} {cq_sum}".strip(), 250)

    return "Automated static analysis completed. Review individual findings for detailed refactoring guidelines."


def build_code_health_interpretation(crit_count: int, high_count: int, med_count: int, low_count: int, code_score: int, sec_score: int, total_findings: int) -> str:
    """
    Generates a dynamic interpretation sentence for the bottom Code Health Summary.
    """
    cq_rating = get_score_rating(code_score)
    sec_rating = get_score_rating(sec_score)

    if total_findings == 0:
        return f"Optimal code health ({cq_rating}) and full security compliance ({sec_rating})."
    if crit_count > 0:
        return f"Critical vulnerability remediation required. Code Quality: {cq_rating} | Security: {sec_rating}."
    if high_count > 0:
        return f"Strong overall code health ({cq_rating}) with high-priority security remediation requested."
    if med_count > 0 or low_count > 0:
        return f"Good overall code health ({cq_rating}) with limited routine maintenance required."
    return f"Code Quality: {cq_rating} | Security: {sec_rating}."


class PDFReportBuilder:
    """
    Builds a single-page, professional enterprise PDF code review report in A4 Landscape.
    Strictly fits on exactly one page with zero lower-half whitespace wastage.
    """

    def __init__(self) -> None:
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self._init_custom_styles()

    def _init_custom_styles(self) -> None:
        self.primary_color = colors.HexColor("#0f172a")      # Dark Slate Header
        self.secondary_color = colors.HexColor("#1e293b")    # Slate Dark
        self.accent_color = colors.HexColor("#2563eb")       # Royal Blue
        self.border_color = colors.HexColor("#cbd5e1")       # Border Light Gray
        self.bg_light = colors.HexColor("#f8fafc")           # Light Background
        self.text_dark = colors.HexColor("#0f172a")          # Body Dark Text
        self.text_muted = colors.HexColor("#64748b")         # Muted Text

        self.hdr_title_style = ParagraphStyle(
            "HdrTitle",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=15,
            textColor=colors.white
        )

        self.hdr_sub_style = ParagraphStyle(
            "HdrSub",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#94a3b8")
        )

        self.hdr_doc_type = ParagraphStyle(
            "HdrDocType",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=12,
            alignment=2,
            textColor=colors.HexColor("#38bdf8")
        )

        self.meta_label_style = ParagraphStyle(
            "MetaLabel",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            textColor=self.text_dark
        )

        self.meta_val_style = ParagraphStyle(
            "MetaVal",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=self.secondary_color
        )

        self.section_title_style = ParagraphStyle(
            "SectionTitle",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10.5,
            textColor=self.primary_color,
            spaceAfter=3
        )

        self.body_style = ParagraphStyle(
            "BodyCustom",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=self.text_dark
        )

        self.finding_title_style = ParagraphStyle(
            "FindingTitle",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=self.primary_color
        )

        self.finding_meta_style = ParagraphStyle(
            "FindingMeta",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=self.text_muted
        )

        self.footer_style = ParagraphStyle(
            "FooterStyle",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=6.5,
            leading=8.5,
            alignment=1,
            textColor=self.text_muted
        )

    def build(self, review_data: Dict[str, Any], output_path: str) -> str:
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("ReportLab is not installed.")

        data = normalize_review_payload(review_data)

        app_name = sanitize_secret_text(data.get("app_name") or os.getenv("APP_NAME", "SentinelAI"))
        review_date = sanitize_secret_text(data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        language = sanitize_secret_text(data.get("language", "python")).capitalize()
        raw_exec_time = data.get("execution_time_ms", 0)
        formatted_exec_time = format_execution_time(raw_exec_time)
        review_id = sanitize_secret_text(data.get("review_id") or data.get("session_id") or data.get("id") or "")

        pr_summary = data.get("pr_summary") or {}
        summary = data.get("summary") or {}
        findings = data.get("findings") or []

        code_score = pr_summary.get("overall_code_quality", 100)
        sec_score = pr_summary.get("overall_security_score", 100)

        total_findings = summary.get("total_findings", len(findings))
        crit_count = summary.get("critical", sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical"))
        high_count = summary.get("high", sum(1 for f in findings if str(f.get("severity", "")).lower() == "high"))
        med_count = summary.get("medium", sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium"))
        low_count = summary.get("low", sum(1 for f in findings if str(f.get("severity", "")).lower() == "low"))

        overall_status = derive_overall_status(data, crit_count, high_count, total_findings)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=landscape(A4),
            leftMargin=24,
            rightMargin=24,
            topMargin=18,
            bottomMargin=18
        )

        printable_width = 793.89

        story: List[Any] = []

        # =========================================================================
        # 1. HEADER BANNER
        # =========================================================================
        status_clean = overall_status.upper()
        status_color = "#16a34a" if "APPROV" in status_clean and "SUGGEST" not in status_clean else "#d97706" if "SUGGEST" in status_clean or "REVIEW" in status_clean else "#dc2626"

        hdr_table_data = [
            [
                Paragraph(f"<b>{format_pdf_text(app_name.upper())}</b>", self.hdr_title_style),
                Paragraph("<b>AUTOMATED CODE REVIEW REPORT</b>", self.hdr_doc_type)
            ],
            [
                Paragraph("AI Code Review & Security Analysis Agent", self.hdr_sub_style),
                Paragraph(f"STATUS: <font color='{status_color}'><b>{format_pdf_text(status_clean)}</b></font>", ParagraphStyle("HdrStatus", parent=self.hdr_sub_style, alignment=2, fontName="Helvetica-Bold"))
            ]
        ]
        hdr_table = Table(hdr_table_data, colWidths=[400, 393.89])
        hdr_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.primary_color),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(hdr_table)
        story.append(Spacer(1, 4))

        # Metadata Row Table
        meta_row_1 = [
            Paragraph("<b>Project / Review:</b>", self.meta_label_style),
            Paragraph(format_pdf_text(app_name), self.meta_val_style),
            Paragraph("<b>Language:</b>", self.meta_label_style),
            Paragraph(format_pdf_text(language), self.meta_val_style),
            Paragraph("<b>Review Date:</b>", self.meta_label_style),
            Paragraph(format_pdf_text(review_date), self.meta_val_style),
            Paragraph("<b>Execution Time:</b>", self.meta_label_style),
            Paragraph(format_pdf_text(formatted_exec_time), self.meta_val_style)
        ]
        meta_data = [meta_row_1]

        meta_table = Table(meta_data, colWidths=[80, 120, 55, 90, 70, 140, 80, 158.89])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 5))

        # =========================================================================
        # 2. EXECUTIVE SCORECARD
        # =========================================================================
        score_card_data = [
            [
                Paragraph("<b>CODE QUALITY</b>", ParagraphStyle("CardH", parent=self.body_style, alignment=1, fontSize=6.5, textColor=self.text_muted)),
                Paragraph("<b>SECURITY</b>", ParagraphStyle("CardH", parent=self.body_style, alignment=1, fontSize=6.5, textColor=self.text_muted)),
                Paragraph("<b>TOTAL FINDINGS</b>", ParagraphStyle("CardH", parent=self.body_style, alignment=1, fontSize=6.5, textColor=self.text_muted)),
                Paragraph("<b>CRITICAL</b>", ParagraphStyle("CardH", parent=self.body_style, alignment=1, fontSize=6.5, textColor=colors.HexColor("#991b1b"))),
                Paragraph("<b>HIGH</b>", ParagraphStyle("CardH", parent=self.body_style, alignment=1, fontSize=6.5, textColor=colors.HexColor("#9a3412"))),
                Paragraph("<b>MEDIUM</b>", ParagraphStyle("CardH", parent=self.body_style, alignment=1, fontSize=6.5, textColor=colors.HexColor("#92400e"))),
                Paragraph("<b>LOW</b>", ParagraphStyle("CardH", parent=self.body_style, alignment=1, fontSize=6.5, textColor=colors.HexColor("#1e40af")))
            ],
            [
                Paragraph(f"<font color='#059669'><b>{code_score}</b></font><font size=7 color='#64748b'> /100</font>", ParagraphStyle("CardV", parent=self.body_style, alignment=1, fontSize=12, fontName="Helvetica-Bold")),
                Paragraph(f"<font color='#2563eb'><b>{sec_score}</b></font><font size=7 color='#64748b'> /100</font>", ParagraphStyle("CardV", parent=self.body_style, alignment=1, fontSize=12, fontName="Helvetica-Bold")),
                Paragraph(f"<font color='#0f172a'><b>{total_findings}</b></font>", ParagraphStyle("CardV", parent=self.body_style, alignment=1, fontSize=12, fontName="Helvetica-Bold")),
                Paragraph(f"<font color='#dc2626'><b>{crit_count}</b></font>", ParagraphStyle("CardV", parent=self.body_style, alignment=1, fontSize=12, fontName="Helvetica-Bold")),
                Paragraph(f"<font color='#ea580c'><b>{high_count}</b></font>", ParagraphStyle("CardV", parent=self.body_style, alignment=1, fontSize=12, fontName="Helvetica-Bold")),
                Paragraph(f"<font color='#d97706'><b>{med_count}</b></font>", ParagraphStyle("CardV", parent=self.body_style, alignment=1, fontSize=12, fontName="Helvetica-Bold")),
                Paragraph(f"<font color='#2563eb'><b>{low_count}</b></font>", ParagraphStyle("CardV", parent=self.body_style, alignment=1, fontSize=12, fontName="Helvetica-Bold"))
            ]
        ]
        score_table = Table(score_card_data, colWidths=[113.41, 113.41, 113.41, 113.41, 113.41, 113.41, 113.43])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(score_table)
        story.append(Spacer(1, 5))

        # =========================================================================
        # 3. EXECUTIVE ASSESSMENT
        # =========================================================================
        exec_assessment_text = build_executive_assessment(data, crit_count, high_count, med_count, low_count, total_findings, code_score, sec_score)

        assess_table_data = [
            [Paragraph("<b>EXECUTIVE ASSESSMENT</b>", self.section_title_style)],
            [Paragraph(format_pdf_text(exec_assessment_text), self.body_style)]
        ]
        assess_table = Table(assess_table_data, colWidths=[printable_width])
        assess_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8)
        ]))
        story.append(assess_table)
        story.append(Spacer(1, 5))

        # =========================================================================
        # 4. TWO-COLUMN SPLIT (Top Priority Findings vs Remediation Roadmap)
        # =========================================================================
        left_flowables: List[Any] = []
        left_flowables.append(Paragraph("<b>TOP PRIORITY FINDINGS (MAX 3)</b>", self.section_title_style))
        left_flowables.append(HRFlowable(width="100%", thickness=1, color=self.accent_color, spaceAfter=4))

        def sev_weight(sev_str: Any) -> int:
            s = str(sev_str).lower()
            return 4 if s == "critical" else 3 if s == "high" else 2 if s == "medium" else 1

        sorted_findings = sorted(findings, key=lambda f: sev_weight(f.get("severity")), reverse=True)
        top_3 = sorted_findings[:3]

        if top_3:
            for idx, f in enumerate(top_3, start=1):
                sev = str(f.get("severity", "Low")).upper()
                sev_color = "#dc2626" if sev == "CRITICAL" else "#ea580c" if sev == "HIGH" else "#d97706" if sev == "MEDIUM" else "#2563eb"

                issue_name = truncate_text(f.get("issue") or f.get("title") or "Issue", 50)
                line_num = f.get("line", 0)
                agent = f.get("agent", "Security")
                agent_cat = "Security" if "security" in agent.lower() else "Code Quality"
                explanation = truncate_text(f.get("explanation") or "Issue identified during static review.", 110)

                finding_cell = [
                    Paragraph(f"<font color='{sev_color}'><b>[{sev}]</b></font> <b>{format_pdf_text(issue_name)}</b>", self.finding_title_style),
                    Paragraph(f"Line {line_num} • {format_pdf_text(agent_cat)}", self.finding_meta_style),
                    Paragraph(format_pdf_text(explanation), self.body_style)
                ]
                f_table = Table([[finding_cell]], colWidths=[385])
                f_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6)
                ]))
                left_flowables.append(f_table)
                left_flowables.append(Spacer(1, 3))
        else:
            left_flowables.append(Paragraph("<b>✓ No issues detected.</b> All code quality and security checks passed.", self.body_style))

        right_flowables: List[Any] = []
        right_flowables.append(Paragraph("<b>REMEDIATION ROADMAP</b>", self.section_title_style))
        right_flowables.append(HRFlowable(width="100%", thickness=1, color=self.accent_color, spaceAfter=4))

        if crit_count > 0:
            imm_text = f"Resolve all {crit_count} Critical finding(s) immediately before deployment."
        else:
            imm_text = "No critical findings requiring emergency remediation."

        if high_count > 0:
            high_text = f"Address {high_count} high-severity vulnerability(ies) prior to PR merge."
        else:
            high_text = "No high-severity security vulnerabilities identified."

        if med_count > 0 or low_count > 0:
            fol_text = f"Schedule {med_count + low_count} medium/low code-quality item(s) for routine maintenance."
        else:
            fol_text = "No routine maintainability follow-up items remaining."

        roadmap_box_data = [
            [Paragraph("<b>IMMEDIATE:</b>", self.meta_label_style), Paragraph(format_pdf_text(imm_text), self.body_style)],
            [Paragraph("<b>HIGH PRIORITY:</b>", self.meta_label_style), Paragraph(format_pdf_text(high_text), self.body_style)],
            [Paragraph("<b>FOLLOW-UP:</b>", self.meta_label_style), Paragraph(format_pdf_text(fol_text), self.body_style)]
        ]
        roadmap_table = Table(roadmap_box_data, colWidths=[90, 280])
        roadmap_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        right_flowables.append(roadmap_table)

        split_table_data = [[left_flowables, right_flowables]]
        split_table = Table(split_table_data, colWidths=[395, 393.89])
        split_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('RIGHTPADDING', (0, 0), (0, 0), 6),
            ('LEFTPADDING', (1, 0), (1, 0), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0)
        ]))
        story.append(split_table)
        story.append(Spacer(1, 6))

        # =========================================================================
        # 5. BOTTOM SECTION: CODE HEALTH SUMMARY
        # =========================================================================
        health_interp = build_code_health_interpretation(crit_count, high_count, med_count, low_count, code_score, sec_score, total_findings)

        health_data = [
            [
                Paragraph("<b>CODE QUALITY</b>", ParagraphStyle("HealthH1", parent=self.body_style, alignment=1, fontSize=6.5, textColor=self.text_muted)),
                Paragraph("<b>SECURITY POSTURE</b>", ParagraphStyle("HealthH2", parent=self.body_style, alignment=1, fontSize=6.5, textColor=self.text_muted)),
                Paragraph("<b>REVIEW OUTCOME</b>", ParagraphStyle("HealthH3", parent=self.body_style, alignment=1, fontSize=6.5, textColor=self.text_muted))
            ],
            [
                Paragraph(f"<b>{code_score}/100</b> <font size=7 color='#64748b'>({get_score_rating(code_score)})</font>", ParagraphStyle("HealthV1", parent=self.body_style, alignment=1, fontSize=10, textColor=colors.HexColor("#059669"))),
                Paragraph(f"<b>{sec_score}/100</b> <font size=7 color='#64748b'>({get_score_rating(sec_score)})</font>", ParagraphStyle("HealthV2", parent=self.body_style, alignment=1, fontSize=10, textColor=colors.HexColor("#2563eb"))),
                Paragraph(f"<font color='{status_color}'><b>{format_pdf_text(status_clean)}</b></font>", ParagraphStyle("HealthV3", parent=self.body_style, alignment=1, fontSize=10))
            ],
            [
                Paragraph(f"<b>Assessment Summary:</b> {format_pdf_text(health_interp)}", ParagraphStyle("HealthInterp", parent=self.body_style, fontSize=7.5, textColor=self.secondary_color, alignment=1))
            ]
        ]
        health_table = Table(health_data, colWidths=[264.63, 264.63, 264.63])
        health_table.setStyle(TableStyle([
            ('SPAN', (0, 2), (2, 2)),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, 1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(health_table)

        # =========================================================================
        # 6. FOOTER
        # =========================================================================
        story.append(Spacer(1, 5))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=3))

        footer_text = f"Generated by <b>SentinelAI</b> • Automated AI Code Review & Security Analysis &bull; Date: {format_pdf_text(review_date)}"
        if review_id:
            footer_text += f" &bull; Review ID: {format_pdf_text(review_id)}"

        story.append(Paragraph(footer_text, self.footer_style))

        doc.build(story)
        return output_path

    def _find_matching_remediation(self, finding: Dict[str, Any], remediations: List[Dict[str, Any]], index: int) -> Dict[str, Any]:
        """
        Attempts to match a finding to a remediation dictionary by line, issue, or index.
        """
        f_line = finding.get("line")
        f_issue = str(finding.get("issue", "")).lower()

        for r in remediations:
            if f_line and r.get("line") == f_line:
                return r
            if f_issue and str(r.get("issue", "")).lower() == f_issue:
                return r

        if 0 <= index < len(remediations):
            return remediations[index]

        return {}


class HTMLReportBuilder:
    """
    Builds a responsive, modern, self-contained HTML code review & security report.
    Adheres strictly to dynamic data and includes printable page break CSS.
    """

    def build(self, review_data: Dict[str, Any], output_path: str) -> str:
        data = normalize_review_payload(review_data)

        app_name = sanitize_secret_text(data.get("app_name") or os.getenv("APP_NAME", "SentinelAI"))
        review_date = sanitize_secret_text(data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        language = sanitize_secret_text(data.get("language", "python")).capitalize()
        exec_time = data.get("execution_time_ms", 0)

        pr_summary = data.get("pr_summary") or {}
        summary = data.get("summary") or {}
        findings = data.get("findings") or []
        remediations = data.get("remediation") or []
        source_code = data.get("code") or data.get("source_code") or ""

        overall_status = sanitize_secret_text(pr_summary.get("overall_status") or data.get("status", "Reviewed"))
        code_score = pr_summary.get("overall_code_quality", 100)
        sec_score = pr_summary.get("overall_security_score", 100)

        total_findings = summary.get("total_findings", len(findings))
        crit_count = summary.get("critical", sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical"))
        high_count = summary.get("high", sum(1 for f in findings if str(f.get("severity", "")).lower() == "high"))
        med_count = summary.get("medium", sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium"))
        low_count = summary.get("low", sum(1 for f in findings if str(f.get("severity", "")).lower() == "low"))

        status_class = "status-approved" if overall_status.lower() in ("approved", "approved with suggestions") else "status-rejected" if overall_status.lower() == "rejected" else "status-changes"

        # Findings Rows HTML
        findings_rows = ""
        for idx, f in enumerate(findings, start=1):
            sev = str(f.get("severity", "Low"))
            sev_class = f"badge-{sev.lower()}"
            issue_str = html.escape(sanitize_secret_text(f.get("issue") or f.get("title") or "Issue"))
            agent_str = html.escape(sanitize_secret_text(f.get("agent", "Analysis")))
            explanation_str = html.escape(sanitize_secret_text(f.get("explanation", "")))
            line_num = f.get("line", 0)

            findings_rows += f"""
            <tr>
                <td><strong>#{idx} {issue_str}</strong></td>
                <td><span class="badge {sev_class}">{html.escape(sev)}</span></td>
                <td><code>Line {line_num}</code></td>
                <td><span class="agent-tag">{agent_str}</span></td>
                <td>{explanation_str}</td>
            </tr>
            """

        if not findings_rows:
            findings_rows = "<tr><td colspan='5' class='text-center'>✅ No code issues or security vulnerabilities identified.</td></tr>"

        # Detailed Finding Cards HTML
        finding_cards = ""
        for idx, f in enumerate(findings, start=1):
            sev = str(f.get("severity", "Low"))
            sev_class = f"badge-{sev.lower()}"
            issue_str = html.escape(sanitize_secret_text(f.get("issue") or "Issue"))
            agent_str = html.escape(sanitize_secret_text(f.get("agent", "Analysis")))
            line_num = f.get("line", 0)
            explanation_str = html.escape(sanitize_secret_text(f.get("explanation", "")))

            rem_match = self._find_matching_remediation(f, remediations, idx - 1)
            why_matters = html.escape(sanitize_secret_text(f.get("why_it_matters") or (rem_match.get("why_it_is_problematic") if rem_match else "")))
            actual_line = extract_source_line(source_code, line_num) or f.get("offending_code") or ""
            actual_line_str = html.escape(sanitize_secret_text(actual_line))
            rec_fix = html.escape(sanitize_secret_text((rem_match.get("recommended_fix") if rem_match else "") or f.get("recommendation") or ""))
            corrected_code = html.escape(sanitize_secret_text((rem_match.get("corrected_code_example") if rem_match else "") or f.get("secure_code") or ""))
            best_prac = html.escape(sanitize_secret_text((rem_match.get("best_practice") if rem_match else "") or "Follow OWASP & language-specific secure coding standards."))
            refs = (rem_match.get("references") if rem_match else []) or f.get("references", [])
            refs_html = "".join(f"<li>{html.escape(sanitize_secret_text(r))}</li>" for r in refs) if refs else ""

            finding_cards += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge {sev_class}">{html.escape(sev)}</span>
                    <h3 class="finding-title">#{idx} {issue_str}</h3>
                    <span class="finding-meta">Line {line_num} &bull; {agent_str}</span>
                </div>
                <div class="finding-body">
                    <p><strong>What is wrong?</strong> {explanation_str}</p>
                    {f'<p><strong>Why it matters?</strong> {why_matters}</p>' if why_matters else ''}
                    {f'<div class="code-block-wrapper"><div class="code-title">Actual source code (Line {line_num}):</div><pre><code>{actual_line_str}</code></pre></div>' if actual_line_str else ''}
                    {f'<p><strong>Recommended fix:</strong> {rec_fix}</p>' if rec_fix else ''}
                    {f'<div class="code-block-wrapper"><div class="code-title">Corrected code example:</div><pre><code>{corrected_code}</code></pre></div>' if corrected_code else ''}
                    <p><strong>Best practice:</strong> {best_prac}</p>
                    {f'<div class="ref-block"><strong>References:</strong><ul>{refs_html}</ul></div>' if refs_html else ''}
                </div>
            </div>
            """

        if not finding_cards:
            finding_cards = "<p>✅ No code issues or security vulnerabilities were identified in the codebase.</p>"

        # Remediation Roadmap HTML
        groups = {
            "Immediate Action (Critical)": [f for f in findings if str(f.get("severity")).lower() == "critical"],
            "High Priority (High)": [f for f in findings if str(f.get("severity")).lower() == "high"],
            "Medium Priority (Medium)": [f for f in findings if str(f.get("severity")).lower() == "medium"],
            "Low Priority (Low)": [f for f in findings if str(f.get("severity")).lower() not in ("critical", "high", "medium")]
        }

        roadmap_html = ""
        for g_name, g_findings in groups.items():
            g_badge_class = "badge-critical" if "Critical" in g_name else "badge-high" if "High" in g_name else "badge-medium" if "Medium" in g_name else "badge-low"
            items_html = ""
            if g_findings:
                for gf in g_findings:
                    items_html += f"<li><strong>Line {gf.get('line', 0)}</strong> ({html.escape(sanitize_secret_text(gf.get('agent', 'Agent')))}): {html.escape(sanitize_secret_text(gf.get('issue', 'Issue')))}</li>"
            else:
                items_html = "<li><em>No items in this priority category.</em></li>"

            roadmap_html += f"""
            <div class="roadmap-card">
                <h4><span class="badge {g_badge_class}">{g_name}</span> ({len(g_findings)})</h4>
                <ul>{items_html}</ul>
            </div>
            """

        # PR Summary Lists
        positive_obs = pr_summary.get("positive_observations") or pr_summary.get("what_is_good") or []
        positive_html = "".join(f"<li>{html.escape(sanitize_secret_text(obs))}</li>" for obs in positive_obs)
        top_risks = pr_summary.get("top_risks") or []
        top_risks_html = "".join(f"<li>{html.escape(sanitize_secret_text(risk))}</li>" for risk in top_risks)
        next_steps = pr_summary.get("recommended_next_steps") or []
        next_steps_html = "".join(f"<li>{html.escape(sanitize_secret_text(step))}</li>" for step in next_steps)

        est_effort = pr_summary.get("estimated_remediation_effort")
        effort_html = ""
        if est_effort:
            if isinstance(est_effort, dict):
                effort_str = f"Critical: {est_effort.get('critical', 'N/A')} | High: {est_effort.get('high', 'N/A')} | Overall: {est_effort.get('overall', 'N/A')}"
            else:
                effort_str = str(est_effort)
            effort_html = f"<p><strong>Estimated Remediation Effort:</strong> {html.escape(sanitize_secret_text(effort_str))}</p>"

        dev_comment_str = html.escape(sanitize_secret_text(pr_summary.get("developer_comment") or ""))

        sec_summary = pr_summary.get("security_summary", "")
        cq_summary = pr_summary.get("code_quality_summary", "")
        exec_text = f"{sec_summary} {cq_summary}".strip() or "Automated audit completed for source code."

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(app_name)} — Code Review & Security Report</title>
    <style>
        :root {{
            --bg-main: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #2563eb;
            --radius: 12px;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1100px;
            margin: 40px auto;
            padding: 0 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--card-border);
            color: #ffffff;
            padding: 32px;
            border-radius: var(--radius);
            margin-bottom: 24px;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3);
        }}

        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 28px;
            color: #38bdf8;
        }}

        .header-meta {{
            font-size: 14px;
            color: var(--text-secondary);
        }}

        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}

        .card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: var(--radius);
            border: 1px solid var(--card-border);
            text-align: center;
        }}

        .card-title {{
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}

        .card-value {{
            font-size: 30px;
            font-weight: 800;
            color: var(--text-primary);
        }}

        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .badge-critical {{ background-color: #fee2e2; color: #991b1b; }}
        .badge-high {{ background-color: #ffedd5; color: #9a3412; }}
        .badge-medium {{ background-color: #fef3c7; color: #92400e; }}
        .badge-low {{ background-color: #dbeafe; color: #1e40af; }}

        .status-approved {{ color: #4ade80; }}
        .status-rejected {{ color: #f87171; }}
        .status-changes {{ color: #fbbf24; }}

        .section {{
            background: var(--card-bg);
            padding: 28px;
            border-radius: var(--radius);
            border: 1px solid var(--card-border);
            margin-bottom: 24px;
        }}

        .section-title {{
            font-size: 20px;
            margin-top: 0;
            margin-bottom: 16px;
            border-bottom: 2px solid var(--card-border);
            padding-bottom: 10px;
            color: #38bdf8;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--card-border);
        }}

        th {{
            background-color: #0f172a;
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}

        .agent-tag {{
            background: #334155;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            color: #e2e8f0;
        }}

        .finding-card {{
            border: 1px solid var(--card-border);
            border-radius: var(--radius);
            padding: 20px;
            margin-bottom: 16px;
            background: #111827;
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }}

        .finding-title {{
            margin: 0;
            font-size: 16px;
            flex-grow: 1;
            color: #f1f5f9;
        }}

        .finding-meta {{
            font-size: 12px;
            color: var(--text-secondary);
        }}

        .code-block-wrapper {{
            margin: 10px 0;
        }}

        .code-title {{
            font-size: 11px;
            color: #94a3b8;
            font-weight: bold;
            margin-bottom: 4px;
        }}

        pre {{
            background: #090d16;
            border: 1px solid #1e293b;
            color: #e2e8f0;
            padding: 14px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 13px;
            font-family: "Courier New", Courier, monospace;
            margin: 0;
        }}

        .roadmap-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }}

        .roadmap-card {{
            background: #111827;
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 16px;
        }}

        .roadmap-card h4 {{
            margin-top: 0;
            margin-bottom: 10px;
        }}

        .roadmap-card ul {{
            padding-left: 18px;
            margin: 0;
            font-size: 13px;
        }}

        footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-secondary);
            font-size: 13px;
        }}

        /* Print Specific CSS Page Breaks */
        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #000000 !important;
            }}
            .container {{
                max-width: 100% !important;
                margin: 0 !important;
                padding: 0 !important;
            }}
            .header, .card, .section, .finding-card, .roadmap-card {{
                background: #ffffff !important;
                color: #000000 !important;
                border: 1px solid #ccc !important;
                box-shadow: none !important;
            }}
            .header h1, .section-title, .finding-title {{
                color: #000000 !important;
            }}
            pre {{
                background: #f8fafc !important;
                color: #000000 !important;
                border: 1px solid #ccc !important;
            }}
            .page-break {{
                page-break-before: always;
                break-before: page;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- PAGE 1: Header Banner & Review Summary -->
        <div class="header">
            <h1>{html.escape(app_name)}</h1>
            <div class="header-meta">
                <span>Date: <strong>{html.escape(review_date)}</strong></span> | 
                <span>Language: <strong>{html.escape(language)}</strong></span> | 
                <span>Execution Time: <strong>{exec_time} ms</strong></span> | 
                <span>Status: <strong class="{status_class}">{html.escape(overall_status)}</strong></span>
            </div>
        </div>

        <div class="dashboard">
            <div class="card">
                <div class="card-title">Review Status</div>
                <div class="card-value {status_class}">{html.escape(overall_status)}</div>
            </div>
            <div class="card">
                <div class="card-title">Code Quality Score</div>
                <div class="card-value" style="color: #4ade80;">{code_score}<small style="font-size:16px;">/100</small></div>
            </div>
            <div class="card">
                <div class="card-title">Security Score</div>
                <div class="card-value" style="color: #60a5fa;">{sec_score}<small style="font-size:16px;">/100</small></div>
            </div>
            <div class="card">
                <div class="card-title">Total Findings</div>
                <div class="card-value" style="color: #f87171;">{total_findings}</div>
            </div>
        </div>

        <div class="page-break"></div>

        <!-- PAGE 2: Executive Summary & PR Review -->
        <div class="section">
            <h2 class="section-title">Executive Summary & Severity Distribution</h2>
            <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;">
                <span class="badge badge-critical">Critical: {crit_count}</span>
                <span class="badge badge-high">High: {high_count}</span>
                <span class="badge badge-medium">Medium: {med_count}</span>
                <span class="badge badge-low">Low: {low_count}</span>
            </div>
            <p>{html.escape(sanitize_secret_text(exec_text))}</p>
        </div>

        <div class="section">
            <h2 class="section-title">Pull Request Summary</h2>
            {f'<h3>What is Good</h3><ul>{positive_html}</ul>' if positive_html else ''}
            {f'<h3>Top Priority Risks</h3><ul>{top_risks_html}</ul>' if top_risks_html else ''}
            {f'<h3>Recommended Next Steps</h3><ul>{next_steps_html}</ul>' if next_steps_html else ''}
            {effort_html}
            {f'<p><strong>Developer Comment:</strong> <em>{dev_comment_str}</em></p>' if dev_comment_str else ''}
        </div>

        <div class="page-break"></div>

        <!-- PAGE 3+: Detailed Findings -->
        <div class="section">
            <h2 class="section-title">Detailed Findings Overview</h2>
            <table>
                <thead>
                    <tr>
                        <th>Issue</th>
                        <th>Severity</th>
                        <th>Line</th>
                        <th>Agent</th>
                        <th>Explanation</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2 class="section-title">Detailed Findings & Remediation Guidance</h2>
            {finding_cards}
        </div>

        <div class="section">
            <h2 class="section-title">Remediation Roadmap</h2>
            <p>Prioritized developer action plan based on issue severity:</p>
            <div class="roadmap-grid">
                {roadmap_html}
            </div>
        </div>

        <footer>
            Generated by {html.escape(app_name)} Agent &bull; Confidential Code Audit Report
        </footer>
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _find_matching_remediation(self, finding: Dict[str, Any], remediations: List[Dict[str, Any]], index: int) -> Dict[str, Any]:
        f_line = finding.get("line")
        f_issue = str(finding.get("issue", "")).lower()

        for r in remediations:
            if f_line and r.get("line") == f_line:
                return r
            if f_issue and str(r.get("issue", "")).lower() == f_issue:
                return r

        if 0 <= index < len(remediations):
            return remediations[index]

        return {}


class ReportGenerator:
    """
    Main Report Generator orchestrating PDF and HTML report creation.
    """

    def __init__(self, output_dir: Optional[str] = None) -> None:
        self.output_dir = output_dir or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "reports")
        )
        os.makedirs(self.output_dir, exist_ok=True)

        self.pdf_builder = PDFReportBuilder()
        self.html_builder = HTMLReportBuilder()

    def generate_pdf(self, review_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generates a PDF code review report."""
        if not output_path:
            filename = f"code_review_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            output_path = os.path.join(self.output_dir, filename)

        return self.pdf_builder.build(review_data, output_path)

    def generate_html(self, review_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generates a responsive HTML code review report."""
        if not output_path:
            filename = f"code_review_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            output_path = os.path.join(self.output_dir, filename)

        return self.html_builder.build(review_data, output_path)

    def save_report(
        self,
        review_data: Dict[str, Any],
        output_dir: Optional[str] = None,
        formats: List[str] = ["pdf", "html"]
    ) -> Dict[str, str]:
        """
        Generates and saves code review reports in specified formats ('pdf', 'html').
        Returns a dictionary of generated file paths.
        """
        target_dir = output_dir or self.output_dir
        os.makedirs(target_dir, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        results: Dict[str, str] = {}

        for fmt in formats:
            fmt_lower = fmt.lower().strip()
            filename = f"code_review_report_{timestamp}.{fmt_lower}"
            out_path = os.path.join(target_dir, filename)

            if fmt_lower == "pdf":
                results["pdf"] = self.generate_pdf(review_data, out_path)
            elif fmt_lower == "html":
                results["html"] = self.generate_html(review_data, out_path)

        return results
