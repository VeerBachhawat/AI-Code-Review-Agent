import datetime
import html
import os
import re
from typing import Any, Dict, List, Optional

# ReportLab Imports for PDF Generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
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


class PDFReportBuilder:
    """
    Builds professional PDF code review & security reports using ReportLab.
    """

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

    def _init_custom_styles(self) -> None:
        self.primary_color = colors.HexColor("#0f172a")
        self.secondary_color = colors.HexColor("#334155")
        self.accent_color = colors.HexColor("#2563eb")
        self.text_dark = colors.HexColor("#1e293b")

        self.title_style = ParagraphStyle(
            "DocTitle",
            parent=self.styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=self.primary_color,
            spaceAfter=6
        )

        self.h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=self.styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=self.secondary_color,
            spaceBefore=12,
            spaceAfter=6
        )

        self.body_style = ParagraphStyle(
            "BodyCustom",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=self.text_dark
        )

        self.code_style = ParagraphStyle(
            "CodeCustom",
            parent=self.styles["Normal"],
            fontName="Courier",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#0f172a"),
            backColor=colors.HexColor("#f1f5f9"),
            borderPadding=4
        )

        self.table_header_style = ParagraphStyle(
            "TableHeader",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=colors.white
        )

    def build(self, review_data: Dict[str, Any], output_path: str) -> str:
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("ReportLab is not installed. Please install reportlab to generate PDF reports.")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        story: List[Any] = []
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        pr_summary = review_data.get("pr_summary", {})
        summary = review_data.get("summary", {})
        findings = review_data.get("findings", [])
        remediations = review_data.get("remediation", [])
        language = review_data.get("language", "python").capitalize()

        overall_status = pr_summary.get("overall_status", "Reviewed")
        code_score = pr_summary.get("overall_code_quality", 100)
        sec_score = pr_summary.get("overall_security_score", 100)

        # 1. Header / Banner
        story.append(Paragraph("AI Code Review & Security Analysis Report", self.title_style))
        story.append(Paragraph(f"<b>Date:</b> {date_str} | <b>Language:</b> {language} | <b>Status:</b> {overall_status}", self.body_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=self.accent_color, spaceAfter=15))

        # 2. Executive Dashboard Scores Table
        score_data = [
            [
                Paragraph("<b>Overall Review Status</b>", self.body_style),
                Paragraph("<b>Code Quality Score</b>", self.body_style),
                Paragraph("<b>Security Score</b>", self.body_style),
                Paragraph("<b>Total Findings</b>", self.body_style)
            ],
            [
                Paragraph(f"<font color='#2563eb'><b>{overall_status}</b></font>", self.h2_style),
                Paragraph(f"<b>{code_score}/100</b>", self.h2_style),
                Paragraph(f"<b>{sec_score}/100</b>", self.h2_style),
                Paragraph(f"<b>{summary.get('total_findings', len(findings))}</b>", self.h2_style)
            ]
        ]
        score_table = Table(score_data, colWidths=[130, 130, 130, 130])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8)
        ]))
        story.append(score_table)
        story.append(Spacer(1, 15))

        # 3. Severity Distribution Summary
        story.append(Paragraph("Executive Summary & Severity Distribution", self.h2_style))
        sev_counts = [
            f"<b>Critical:</b> {summary.get('critical', 0)}",
            f"<b>High:</b> {summary.get('high', 0)}",
            f"<b>Medium:</b> {summary.get('medium', 0)}",
            f"<b>Low:</b> {summary.get('low', 0)}"
        ]
        story.append(Paragraph(" | ".join(sev_counts), self.body_style))
        
        exec_summary_text = pr_summary.get("security_summary", "") + " " + pr_summary.get("code_quality_summary", "")
        if exec_summary_text.strip():
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<i>{exec_summary_text}</i>", self.body_style))

        story.append(Spacer(1, 15))

        # 4. Findings Table
        story.append(Paragraph("Detailed Findings", self.h2_style))
        if findings:
            table_data = [
                [
                    Paragraph("<b>Issue</b>", self.table_header_style),
                    Paragraph("<b>Severity</b>", self.table_header_style),
                    Paragraph("<b>Line</b>", self.table_header_style),
                    Paragraph("<b>Agent</b>", self.table_header_style),
                    Paragraph("<b>Explanation</b>", self.table_header_style)
                ]
            ]

            for f in findings:
                sev = str(f.get("severity", "Low"))
                sev_color = "#ef4444" if sev.lower() == "critical" else "#f97316" if sev.lower() == "high" else "#f59e0b" if sev.lower() == "medium" else "#3b82f6"
                table_data.append([
                    Paragraph(html.escape(str(f.get("issue", ""))), self.body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", self.body_style),
                    Paragraph(str(f.get("line", 0)), self.body_style),
                    Paragraph(html.escape(str(f.get("agent", "Analysis"))), self.body_style),
                    Paragraph(html.escape(str(f.get("explanation", ""))), self.body_style)
                ])

            findings_table = Table(table_data, colWidths=[120, 60, 40, 70, 230])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.primary_color),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5)
            ]))
            story.append(findings_table)
        else:
            story.append(Paragraph("✅ No code issues or security vulnerabilities were identified.", self.body_style))

        story.append(Spacer(1, 15))

        # 5. Remediation Guidance Section
        story.append(Paragraph("Remediation Guidance & Refactoring", self.h2_style))
        if remediations:
            for i, r in enumerate(remediations, start=1):
                rem_elements = []
                rem_elements.append(Paragraph(f"<b>{i}. {html.escape(str(r.get('issue', 'Issue')))}</b> (Line {r.get('line', '?')})", self.body_style))
                rem_elements.append(Paragraph(f"<b>Problem:</b> {html.escape(str(r.get('why_it_is_problematic', '')))}", self.body_style))
                rem_elements.append(Paragraph(f"<b>Recommended Fix:</b> {html.escape(str(r.get('recommended_fix', '')))}", self.body_style))

                code_example = r.get("corrected_code_example", "")
                if code_example:
                    rem_elements.append(Spacer(1, 3))
                    rem_elements.append(Paragraph(f"<font fontName='Courier'>{html.escape(code_example).replace(chr(10), '<br/>')}</font>", self.code_style))

                rem_elements.append(Spacer(1, 3))
                rem_elements.append(Paragraph(f"<b>Best Practice:</b> {html.escape(str(r.get('best_practice', '')))}", self.body_style))
                refs = r.get("references", [])
                if refs:
                    rem_elements.append(Paragraph(f"<b>References:</b> {html.escape(', '.join(refs))}", self.body_style))
                rem_elements.append(Spacer(1, 10))

                story.append(KeepTogether(rem_elements))
        else:
            story.append(Paragraph("No remediation actions required.", self.body_style))

        story.append(Spacer(1, 15))

        # 6. PR Review Summary & Recommendations
        story.append(Paragraph("Pull Request Summary & Next Steps", self.h2_style))
        top_risks = pr_summary.get("top_risks", [])
        if top_risks:
            story.append(Paragraph("<b>Top Priority Risks:</b>", self.body_style))
            for risk in top_risks:
                story.append(Paragraph(f"• {html.escape(str(risk))}", self.body_style))
            story.append(Spacer(1, 6))

        next_steps = pr_summary.get("recommended_next_steps", [])
        if next_steps:
            story.append(Paragraph("<b>Recommended Next Steps:</b>", self.body_style))
            for step in next_steps:
                story.append(Paragraph(f"1. {html.escape(str(step))}", self.body_style))
            story.append(Spacer(1, 6))

        # 7. Footer
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=20, spaceAfter=10))
        story.append(Paragraph("<i>Generated by AI Code Review & Security Analysis Agent. Confidential Code Audit.</i>", self.body_style))

        doc.build(story)
        return output_path


class HTMLReportBuilder:
    """
    Builds a responsive, modern HTML code review & security report with embedded CSS styling.
    """

    def build(self, review_data: Dict[str, Any], output_path: str) -> str:
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pr_summary = review_data.get("pr_summary", {})
        summary = review_data.get("summary", {})
        findings = review_data.get("findings", [])
        remediations = review_data.get("remediation", [])
        language = review_data.get("language", "python").capitalize()

        overall_status = pr_summary.get("overall_status", "Reviewed")
        code_score = pr_summary.get("overall_code_quality", 100)
        sec_score = pr_summary.get("overall_security_score", 100)

        status_class = "status-approved" if overall_status.lower() in ("approved", "approved with suggestions") else "status-rejected" if overall_status.lower() == "rejected" else "status-changes"

        # Generate Findings Table Rows
        findings_rows = ""
        for f in findings:
            sev = str(f.get("severity", "Low"))
            sev_class = f"badge-{sev.lower()}"
            findings_rows += f"""
            <tr>
                <td><strong>{html.escape(str(f.get("issue", "")))}</strong></td>
                <td><span class="badge {sev_class}">{html.escape(sev)}</span></td>
                <td><code>{f.get("line", 0)}</code></td>
                <td><span class="agent-tag">{html.escape(str(f.get("agent", "Analysis")))}</span></td>
                <td>{html.escape(str(f.get("explanation", "")))}</td>
            </tr>
            """

        if not findings_rows:
            findings_rows = "<tr><td colspan='5' class='text-center'>✅ No code issues or security vulnerabilities identified.</td></tr>"

        # Generate Remediation Cards
        rem_cards = ""
        for i, r in enumerate(remediations, start=1):
            refs_list = "".join(f"<li>{html.escape(ref)}</li>" for ref in r.get("references", []))
            code_block = f"<pre><code>{html.escape(r.get('corrected_code_example', ''))}</code></pre>" if r.get('corrected_code_example') else ""
            
            rem_cards += f"""
            <div class="rem-card">
                <div class="rem-header">
                    <span class="rem-number">#{i}</span>
                    <h4 class="rem-title">{html.escape(str(r.get("issue", "Issue")))} (Line {r.get("line", "?")})</h4>
                </div>
                <div class="rem-body">
                    <p><strong>Problem:</strong> {html.escape(str(r.get("why_it_is_problematic", "")))}</p>
                    <p><strong>Recommended Fix:</strong> {html.escape(str(r.get("recommended_fix", "")))}</p>
                    {code_block}
                    <p><strong>Best Practice:</strong> {html.escape(str(r.get("best_practice", "")))}</p>
                    {f'<div class="rem-refs"><strong>References:</strong><ul>{refs_list}</ul></div>' if refs_list else ''}
                </div>
            </div>
            """

        if not rem_cards:
            rem_cards = "<p>No remediation actions required.</p>"

        # Generate Top Risks List
        top_risks_html = "".join(f"<li>{html.escape(str(risk))}</li>" for risk in pr_summary.get("top_risks", []))
        next_steps_html = "".join(f"<li>{html.escape(str(step))}</li>" for step in pr_summary.get("recommended_next_steps", []))

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Code Review & Security Analysis Report</title>
    <style>
        :root {{
            --bg-main: #f8fafc;
            --card-bg: #ffffff;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --accent: #2563eb;
            --border: #e2e8f0;
            --radius: 8px;
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
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            padding: 30px;
            border-radius: var(--radius);
            margin-bottom: 24px;
            box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        .header-meta {{
            font-size: 14px;
            color: #94a3b8;
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
            border: 1px solid var(--border);
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            text-align: center;
        }}
        .card-title {{
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }}
        .card-value {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: #fee2e2; color: #991b1b; }}
        .badge-high {{ background-color: #ffedd5; color: #9a3412; }}
        .badge-medium {{ background-color: #fef3c7; color: #92400e; }}
        .badge-low {{ background-color: #dbeafe; color: #1e40af; }}
        .status-approved {{ color: #16a34a; }}
        .status-rejected {{ color: #dc2626; }}
        .status-changes {{ color: #d97706; }}
        
        .section {{
            background: var(--card-bg);
            padding: 24px;
            border-radius: var(--radius);
            border: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        .section-title {{
            font-size: 20px;
            margin-top: 0;
            margin-bottom: 16px;
            border-bottom: 2px solid var(--bg-main);
            padding-bottom: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: #f1f5f9;
            font-size: 13px;
            color: var(--text-secondary);
        }}
        .agent-tag {{
            background: #e2e8f0;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
        }}
        .rem-card {{
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px;
            margin-bottom: 16px;
            background: #fafafa;
        }}
        .rem-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }}
        .rem-number {{
            background: var(--accent);
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .rem-title {{
            margin: 0;
            font-size: 16px;
        }}
        pre {{
            background: #0f172a;
            color: #f8fafc;
            padding: 14px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Banner -->
        <div class="header">
            <h1>AI Code Review & Security Analysis Report</h1>
            <div class="header-meta">
                <span>Date: {date_str}</span> | 
                <span>Language: {language}</span> | 
                <span>Overall Status: <strong>{overall_status}</strong></span>
            </div>
        </div>

        <!-- Metric Dashboard Cards -->
        <div class="dashboard">
            <div class="card">
                <div class="card-title">Review Status</div>
                <div class="card-value {status_class}">{overall_status}</div>
            </div>
            <div class="card">
                <div class="card-title">Code Quality Score</div>
                <div class="card-value">{code_score}<small style="font-size:16px;">/100</small></div>
            </div>
            <div class="card">
                <div class="card-title">Security Score</div>
                <div class="card-value">{sec_score}<small style="font-size:16px;">/100</small></div>
            </div>
            <div class="card">
                <div class="card-title">Total Findings</div>
                <div class="card-value">{summary.get('total_findings', len(findings))}</div>
            </div>
        </div>

        <!-- Severity Breakdown & Executive Summary -->
        <div class="section">
            <h2 class="section-title">Executive Summary & Severity Distribution</h2>
            <div style="display: flex; gap: 12px; margin-bottom: 16px;">
                <span class="badge badge-critical">Critical: {summary.get('critical', 0)}</span>
                <span class="badge badge-high">High: {summary.get('high', 0)}</span>
                <span class="badge badge-medium">Medium: {summary.get('medium', 0)}</span>
                <span class="badge badge-low">Low: {summary.get('low', 0)}</span>
            </div>
            <p>{html.escape(pr_summary.get("security_summary", ""))} {html.escape(pr_summary.get("code_quality_summary", ""))}</p>
        </div>

        <!-- Detailed Findings Table -->
        <div class="section">
            <h2 class="section-title">Detailed Findings Table</h2>
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

        <!-- Remediation Section -->
        <div class="section">
            <h2 class="section-title">Remediation Guidance</h2>
            {rem_cards}
        </div>

        <!-- PR Review & Recommendations -->
        <div class="section">
            <h2 class="section-title">PR Review Summary & Next Steps</h2>
            {f'<h3>Top Priority Risks</h3><ul>{top_risks_html}</ul>' if top_risks_html else ''}
            {f'<h3>Recommended Next Steps</h3><ul>{next_steps_html}</ul>' if next_steps_html else ''}
        </div>

        <footer>
            Generated by AI Code Review & Security Analysis Agent &bull; Confidential Code Audit Report
        </footer>
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path


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
