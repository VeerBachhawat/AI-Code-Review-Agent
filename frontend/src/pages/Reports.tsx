import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  Download,
  CheckCircle2,
  Loader2,
  AlertCircle,
  Sparkles
} from 'lucide-react';
import type { ReviewResult } from '../types';
import { apiService } from '../services/api';

export const Reports: React.FC = () => {
  const navigate = useNavigate();
  const [result, setResult] = useState<ReviewResult | null>(null);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState<boolean>(false);
  const [isDownloadingHtml, setIsDownloadingHtml] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [generatedInfo, setGeneratedInfo] = useState<{
    pdf_filename?: string;
    html_filename?: string;
    pdf_url?: string;
    html_url?: string;
  } | null>(null);

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
        <p className="text-sm text-slate-400">Perform a code review first to generate exportable PDF & HTML reports.</p>
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

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    setError(null);
    setSuccess(null);
    try {
      const data = await apiService.generateReport(result, 'both');
      if (data.status === 'success') {
        setGeneratedInfo(data);
        setSuccess('PDF & HTML Reports generated successfully!');
      } else {
        setError(data.message || 'Report generation failed.');
      }
    } catch (err: any) {
      console.error('Report generation error:', err);
      setError(err.response?.data?.message || err.message || 'Failed to generate reports from backend server.');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownloadPDF = async () => {
    setIsDownloadingPdf(true);
    setError(null);
    try {
      const blob = await apiService.downloadReportPdf(result);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = generatedInfo?.pdf_filename || `code_review_report_${Date.now()}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      setSuccess('PDF Report downloaded successfully!');
    } catch (err: any) {
      console.error('PDF Download error:', err);
      setError(err.response?.data?.message || err.message || 'Failed to download PDF report.');
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleDownloadHTML = async () => {
    setIsDownloadingHtml(true);
    setError(null);
    try {
      const blob = await apiService.downloadReportHtml(result);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = generatedInfo?.html_filename || `code_review_report_${Date.now()}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      setSuccess('HTML Report downloaded successfully!');
    } catch (err: any) {
      console.error('HTML Download error:', err);
      setError(err.response?.data?.message || err.message || 'Failed to download HTML report.');
    } finally {
      setIsDownloadingHtml(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-blue-400" />
            Executive Code Audit Reports
          </h1>
          <p className="text-xs text-slate-400 mt-1">Export executive multi-page PDF & HTML reports generated dynamically from review results.</p>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="inline-flex items-center space-x-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/30 cursor-pointer transition-all"
          >
            {isGenerating ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Generating Reports...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>Generate Backend Report</span>
              </>
            )}
          </button>

          <button
            onClick={handleDownloadPDF}
            disabled={isDownloadingPdf}
            className="inline-flex items-center space-x-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold shadow-lg shadow-emerald-600/30 cursor-pointer transition-all"
          >
            {isDownloadingPdf ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Downloading PDF...</span>
              </>
            ) : (
              <>
                <FileText className="w-4 h-4" />
                <span>Download PDF Report</span>
              </>
            )}
          </button>

          <button
            onClick={handleDownloadHTML}
            disabled={isDownloadingHtml}
            className="inline-flex items-center space-x-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 rounded-xl text-xs font-semibold cursor-pointer transition-all"
          >
            {isDownloadingHtml ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Downloading HTML...</span>
              </>
            ) : (
              <>
                <Download className="w-4 h-4 text-blue-400" />
                <span>Download HTML Report</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Notifications / Alerts */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{success}</span>
        </div>
      )}

      {/* Report Metrics & Details */}
      <div className="glass-panel p-6 space-y-6">
        <div className="border-b border-slate-800 pb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">Report Content Summary</h2>
            <p className="text-xs text-slate-400">Review results mapped dynamically from backend orchestrator pipeline</p>
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
          <h3 className="text-sm font-bold text-white">Included Document Sections:</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-slate-300">
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Page 1: Title, Metadata & Review Summary Dashboard</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Page 2: Executive Summary, Severity Breakdown & PR Summary</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Page 3+: Detailed Findings with Source Code & Remediation</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Remediation Roadmap: Prioritized Action Categories</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
