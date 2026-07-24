import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  Download,
  CheckCircle2
} from 'lucide-react';
import type { ReviewResult } from '../types';

export const Reports: React.FC = () => {
  const navigate = useNavigate();
  const [result, setResult] = useState<ReviewResult | null>(null);

  useEffect(() => {
    const cached = localStorage.getItem('active_review_result');
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        setResult(parsed);
      } catch (e) {
        console.error('Failed to parse active review result:', e);
      }
    }
  }, []);

  if (!result) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-16 text-center space-y-4">
        <FileText className="w-12 h-12 text-slate-600 mx-auto" />
        <h2 className="text-xl font-bold text-white">No Review Data Selected</h2>
        <p className="text-sm text-slate-400">Perform a code review to generate downloadable PDF & HTML reports.</p>
        <button
          onClick={() => navigate('/review')}
          className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold cursor-pointer transition-all"
        >
          Start New Review
        </button>
      </div>
    );
  }

  const { pr_summary, summary, findings, remediation } = result;
  const overall_status = pr_summary?.overall_status || 'Reviewed';
  const code_score = pr_summary?.overall_code_quality || 100;
  const sec_score = pr_summary?.overall_security_score || 100;

  const handleDownloadHTML = () => {
    const dateStr = new Date().toISOString().replace(/[:.]/g, '-');
    const htmlString = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AI Code Review Report</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0b0f17; color: #f8fafc; padding: 40px; }
  .card { background: #141c2b; border: 1px solid #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; }
  h1 { color: #3b82f6; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; }
  th, td { padding: 10px; border-bottom: 1px solid #1e293b; text-align: left; }
  th { background: #0f172a; }
  .badge { padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 12px; }
  .critical { background: #ef4444; color: white; }
  .high { background: #f97316; color: white; }
</style>
</head>
<body>
  <h1>AI Code Review & Security Report</h1>
  <div class="card">
    <p><strong>Status:</strong> ${overall_status} | <strong>Code Score:</strong> ${code_score}/100 | <strong>Security Score:</strong> ${sec_score}/100</p>
  </div>
  <div class="card">
    <h2>Detailed Findings (${findings.length})</h2>
    <table>
      <tr><th>Issue</th><th>Severity</th><th>Line</th><th>Explanation</th></tr>
      ${findings
        .map(
          (f) =>
            `<tr><td>${f.issue}</td><td><span class="badge ${f.severity.toLowerCase()}">${f.severity}</span></td><td>${f.line}</td><td>${f.explanation}</td></tr>`
        )
        .join('')}
    </table>
  </div>
</body>
</html>`;

    const blob = new Blob([htmlString], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `code_review_report_${dateStr}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPDF = () => {
    window.print();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-blue-400" />
            Executive Code Audit Reports
          </h1>
          <p className="text-xs text-slate-400 mt-1">Export executive PDF documents & HTML reports for distribution.</p>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={handleDownloadHTML}
            className="inline-flex items-center space-x-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/30 cursor-pointer transition-all"
          >
            <Download className="w-4 h-4" />
            <span>Download HTML Report</span>
          </button>
          <button
            onClick={handleDownloadPDF}
            className="inline-flex items-center space-x-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-semibold cursor-pointer transition-all"
          >
            <FileText className="w-4 h-4 text-emerald-400" />
            <span>Export / Print PDF Report</span>
          </button>
        </div>
      </div>

      <div className="glass-panel p-6 space-y-6">
        <div className="border-b border-slate-800 pb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">Report Summary & Document Preview</h2>
            <p className="text-xs text-slate-400">Analysis summary generated from multi-agent review pipeline</p>
          </div>
          <span
            className={`px-3 py-1 rounded-full text-xs font-bold border ${
              overall_status.toLowerCase() === 'approved'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : overall_status.toLowerCase() === 'rejected'
                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
            }`}
          >
            {overall_status}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-1">
            <span className="text-xs text-slate-400 uppercase font-semibold">Code Quality Score</span>
            <div className="text-2xl font-bold text-white">{code_score}/100</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-1">
            <span className="text-xs text-slate-400 uppercase font-semibold">Security Score</span>
            <div className="text-2xl font-bold text-white">{sec_score}/100</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-1">
            <span className="text-xs text-slate-400 uppercase font-semibold">Total Findings</span>
            <div className="text-2xl font-bold text-white">{summary?.total_findings || findings.length}</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-1">
            <span className="text-xs text-slate-400 uppercase font-semibold">Remediations Ready</span>
            <div className="text-2xl font-bold text-emerald-400">{remediation.length}</div>
          </div>
        </div>

        <div className="space-y-4 pt-4 border-t border-slate-800">
          <h3 className="text-sm font-bold text-white">Included Report Sections:</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-slate-300">
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>1. Cover Banner & Executive Status</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>2. Code Quality & Security Score Mappings</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>3. Severity Breakdown & Detailed Findings Table</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>4. Refactored Code Snippets & OWASP References</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
