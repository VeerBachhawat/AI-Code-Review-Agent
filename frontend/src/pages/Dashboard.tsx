import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  Code2,
  AlertTriangle,
  ArrowRight,
  Sparkles,
  CheckCircle2,
  Clock,
  ExternalLink,
  Bot
} from 'lucide-react';
import { storageService } from '../utils/storage';
import type { HistoricalReview } from '../types';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [history, setHistory] = useState<HistoricalReview[]>([]);

  useEffect(() => {
    setHistory(storageService.getReviewHistory());
  }, []);

  const totalReviews = history.length;
  const avgQuality = history.length > 0
    ? Math.round(history.reduce((acc, curr) => acc + (curr.result?.pr_summary?.overall_code_quality || 100), 0) / history.length)
    : 100;
  const avgSecurity = history.length > 0
    ? Math.round(history.reduce((acc, curr) => acc + (curr.result?.pr_summary?.overall_security_score || 100), 0) / history.length)
    : 100;
  const totalFindings = history.reduce((acc, curr) => acc + (curr.result?.summary?.total_findings || 0), 0);
  const totalCritical = history.reduce((acc, curr) => acc + (curr.result?.summary?.critical || 0), 0);
  const totalHigh = history.reduce((acc, curr) => acc + (curr.result?.summary?.high || 0), 0);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-blue-900/40 via-slate-900 to-indigo-950/50 border border-blue-500/20 p-8">
        <div className="relative z-10 max-w-3xl space-y-4">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-semibold">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Multi-Agent Autonomous Code Security Platform</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Automated Code Review & OWASP Vulnerability Analysis
          </h1>
          <p className="text-slate-300 text-sm sm:text-base leading-relaxed">
            Inspect source code using AST static analysis, detect OWASP Top 10 security flaws, generate automated refactoring remediations, and chat with RAG AI assistants.
          </p>
          <div className="flex flex-wrap gap-4 pt-2">
            <button
              onClick={() => navigate('/review')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-blue-600/30 cursor-pointer"
            >
              <Code2 className="w-4 h-4" />
              <span>Start Code Review</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>
            <button
              onClick={() => navigate('/chat')}
              className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-sm transition-all cursor-pointer"
            >
              <Bot className="w-4 h-4 text-blue-400" />
              <span>Ask AI Assistant</span>
            </button>
          </div>
        </div>
      </div>

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5">
        <div className="glass-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold tracking-wider uppercase">
            <span>Avg Quality Score</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-black text-white flex items-baseline gap-1">
            {avgQuality} <span className="text-sm font-normal text-slate-400">/ 100</span>
          </div>
          <p className="text-xs text-slate-400">Across {totalReviews} review sessions</p>
        </div>

        <div className="glass-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold tracking-wider uppercase">
            <span>Avg Security Score</span>
            <ShieldAlert className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-3xl font-black text-white flex items-baseline gap-1">
            {avgSecurity} <span className="text-sm font-normal text-slate-400">/ 100</span>
          </div>
          <p className="text-xs text-slate-400">OWASP security rating</p>
        </div>

        <div className="glass-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold tracking-wider uppercase">
            <span>Total Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-black text-white">{totalFindings}</div>
          <p className="text-xs text-slate-400">Code & Security issues</p>
        </div>

        <div className="glass-card p-5 space-y-2 border-red-500/20 bg-red-950/10">
          <div className="flex items-center justify-between text-red-400 text-xs font-semibold tracking-wider uppercase">
            <span>Critical Findings</span>
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-3xl font-black text-red-400">{totalCritical}</div>
          <p className="text-xs text-slate-400">Immediate action required</p>
        </div>

        <div className="glass-card p-5 space-y-2 border-amber-500/20 bg-amber-950/10">
          <div className="flex items-center justify-between text-amber-400 text-xs font-semibold tracking-wider uppercase">
            <span>High Severity</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-black text-amber-400">{totalHigh}</div>
          <p className="text-xs text-slate-400">High priority flaws</p>
        </div>
      </div>

      {/* Main Dashboard Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Recent Review Sessions */}
        <div className="lg:col-span-2 glass-panel p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Clock className="w-5 h-5 text-blue-400" />
                Recent Code Reviews
              </h2>
              <p className="text-xs text-slate-400">Latest analysis runs from browser storage</p>
            </div>
            {history.length > 0 && (
              <button
                onClick={() => navigate('/history')}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1 cursor-pointer"
              >
                <span>View All ({history.length})</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {history.length === 0 ? (
            <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl space-y-3">
              <Code2 className="w-10 h-10 text-slate-600 mx-auto" />
              <p className="text-slate-400 text-sm">No code reviews performed yet.</p>
              <button
                onClick={() => navigate('/review')}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium cursor-pointer transition-all"
              >
                Start First Review
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {history.slice(0, 5).map((item) => {
                const status = item.result?.pr_summary?.overall_status || 'Reviewed';
                const statusBg =
                  status.toLowerCase() === 'approved'
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : status.toLowerCase() === 'rejected'
                    ? 'bg-red-500/10 text-red-400 border-red-500/30'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/30';

                return (
                  <div
                    key={item.id}
                    onClick={() => {
                      localStorage.setItem('active_review_result', JSON.stringify(item.result));
                      navigate('/results');
                    }}
                    className="flex items-center justify-between p-4 rounded-xl bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 cursor-pointer transition-all"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-sm text-white">{item.filename}</span>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                          {item.language}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">
                        {new Date(item.timestamp).toLocaleString()} &bull; {item.result?.summary?.total_findings || 0} findings
                      </p>
                    </div>

                    <div className="flex items-center space-x-4">
                      <span className={`text-xs px-2.5 py-1 rounded-full border font-medium ${statusBg}`}>
                        {status}
                      </span>
                      <ExternalLink className="w-4 h-4 text-slate-500 hover:text-slate-300" />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* System Capabilities Sidebar */}
        <div className="glass-panel p-6 space-y-5">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            Agent Capabilities
          </h2>

          <div className="space-y-4">
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <h3 className="text-sm font-semibold text-blue-400">Code Analysis Agent</h3>
              <p className="text-xs text-slate-400">
                Detects Cyclomatic Complexity, deep nesting, magic numbers, duplicate code, unused variables, and maintainability scores.
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <h3 className="text-sm font-semibold text-amber-400">Security Vulnerability Agent</h3>
              <p className="text-xs text-slate-400">
                Identifies OWASP Top 10 issues: SQL Injection, XSS, Path Traversal, Command Injection, Insecure Deserialization, & Secrets.
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <h3 className="text-sm font-semibold text-emerald-400">Remediation & PR Summary</h3>
              <p className="text-xs text-slate-400">
                Generates refactored corrected code snippets, best practice guidance, and automated GitHub PR review comments.
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
              <h3 className="text-sm font-semibold text-indigo-400">Conversational RAG Assistant</h3>
              <p className="text-xs text-slate-400">
                Answers developer questions using ChromaDB vector database indexed with secure coding standards & OWASP PDFs.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
