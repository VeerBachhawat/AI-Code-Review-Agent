import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FileCheck2,
  Filter,
  Search,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Bot,
  FileText,
  Code2,
  Sparkles
} from 'lucide-react';
import type { ReviewResult, Finding, Remediation } from '../types';

export const Results: React.FC = () => {
  const navigate = useNavigate();

  const [result, setResult] = useState<ReviewResult | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedIndex, setExpandedIndex] = useState<number | null>(0);
  const [copiedCodeIndex, setCopiedCodeIndex] = useState<number | null>(null);

  useEffect(() => {
    const cached = localStorage.getItem('active_review_result');
    if (cached) {
      try {
        setResult(JSON.parse(cached));
      } catch (e) {
        console.error('Failed to parse cached review result:', e);
      }
    }
  }, []);

  if (!result) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-16 text-center space-y-4">
        <FileCheck2 className="w-12 h-12 text-slate-600 mx-auto" />
        <h2 className="text-xl font-bold text-white">No Review Results Available</h2>
        <p className="text-sm text-slate-400">Perform a code review to view analysis results.</p>
        <button
          onClick={() => navigate('/review')}
          className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold cursor-pointer transition-all"
        >
          Start New Review
        </button>
      </div>
    );
  }

  const { pr_summary, summary, findings, remediation, execution_time_ms, language } = result;
  const overall_status = pr_summary?.overall_status || 'Reviewed';
  const code_score = pr_summary?.overall_code_quality || 100;
  const sec_score = pr_summary?.overall_security_score || 100;

  const filteredFindings = findings.filter((f) => {
    const matchesSev = selectedSeverity === 'All' || f.severity.toLowerCase() === selectedSeverity.toLowerCase();
    const matchesQuery =
      searchQuery === '' ||
      f.issue.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.explanation.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesSev && matchesQuery;
  });

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    }
  };

  const handleCopyCode = (codeText: string, index: number) => {
    navigator.clipboard.writeText(codeText);
    setCopiedCodeIndex(index);
    setTimeout(() => setCopiedCodeIndex(null), 2000);
  };

  const handleAskAI = (finding: Finding) => {
    localStorage.setItem('chat_prefill_finding', JSON.stringify(finding));
    navigate('/chat');
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-6">
        <div>
          <div className="flex items-center space-x-3">
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <FileCheck2 className="w-6 h-6 text-blue-400" />
              Analysis Results & PR Review
            </h1>
            <span
              className={`px-3 py-1 rounded-full border text-xs font-bold ${
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
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-2">
            <span>Language: <strong className="text-slate-200 uppercase">{language}</strong></span>
            <span>&bull;</span>
            <span>Execution Time: <strong className="text-slate-200">{execution_time_ms} ms</strong></span>
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => navigate('/reports')}
            className="inline-flex items-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-medium cursor-pointer transition-all"
          >
            <FileText className="w-4 h-4 text-blue-400" />
            <span>Generate Reports</span>
          </button>
          <button
            onClick={() => navigate('/review')}
            className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-blue-600/30 cursor-pointer transition-all"
          >
            <Code2 className="w-4 h-4" />
            <span>New Review</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="glass-card p-5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-semibold">
            <span>Code Quality Score</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-black text-white">{code_score}<span className="text-sm font-normal text-slate-400">/100</span></div>
          <div className="w-full bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
            <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: `${code_score}%` }}></div>
          </div>
        </div>

        <div className="glass-card p-5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-semibold">
            <span>Security Score</span>
            <ShieldAlert className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-3xl font-black text-white">{sec_score}<span className="text-sm font-normal text-slate-400">/100</span></div>
          <div className="w-full bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
            <div className="bg-blue-500 h-1.5 rounded-full" style={{ width: `${sec_score}%` }}></div>
          </div>
        </div>

        <div className="glass-card p-5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-semibold">
            <span>Total Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-black text-white">{summary?.total_findings || findings.length}</div>
          <p className="text-xs text-slate-400">Across all security & code rules</p>
        </div>

        <div className="glass-card p-5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-semibold">
            <span>Severity Counts</span>
            <Filter className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-center space-x-2 pt-1">
            <span className="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-bold">C: {summary?.critical || 0}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 font-bold">H: {summary?.high || 0}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 font-bold">M: {summary?.medium || 0}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-bold">L: {summary?.low || 0}</span>
          </div>
        </div>
      </div>

      {/* Main Results Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Detailed Findings & Remediation */}
        <div className="lg:col-span-2 space-y-6">
          {/* Filters Bar */}
          <div className="glass-panel p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold text-slate-400 flex items-center gap-1">
                <Filter className="w-3.5 h-3.5" /> Sev:
              </span>
              {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    selectedSeverity === sev
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            <div className="relative w-full sm:w-48">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* Findings List */}
          <div className="space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center justify-between">
              <span>Findings & Remediations ({filteredFindings.length})</span>
            </h2>

            {filteredFindings.length === 0 ? (
              <div className="text-center py-12 glass-panel space-y-2">
                <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
                <p className="text-slate-300 font-semibold text-sm">No findings match the selected filter criteria.</p>
              </div>
            ) : (
              filteredFindings.map((finding, idx) => {
                const isExpanded = expandedIndex === idx;

                const rem: Remediation | undefined = remediation.find(
                  (r) => r.issue.toLowerCase() === finding.issue.toLowerCase() || r.line === finding.line
                );

                return (
                  <div key={idx} className="glass-panel overflow-hidden transition-all border border-slate-800">
                    <div
                      onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                      className="p-4 bg-slate-900/60 hover:bg-slate-800/80 cursor-pointer flex items-center justify-between gap-4 transition-all"
                    >
                      <div className="flex items-center space-x-3">
                        <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${getSeverityBadgeClass(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <div>
                          <h3 className="text-sm font-semibold text-white">{finding.issue}</h3>
                          <p className="text-xs text-slate-400">
                            Line {finding.line} &bull; <span className="text-blue-400">{finding.agent}</span>
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center space-x-3">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleAskAI(finding);
                          }}
                          className="px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-xs font-medium flex items-center gap-1 transition-all"
                        >
                          <Bot className="w-3.5 h-3.5" />
                          <span>Ask AI</span>
                        </button>
                        {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="p-5 border-t border-slate-800 space-y-4 bg-slate-950/40 text-xs">
                        <div>
                          <h4 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px] mb-1">
                            Explanation
                          </h4>
                          <p className="text-slate-300 leading-relaxed">{finding.explanation}</p>
                        </div>

                        {rem && (
                          <div className="space-y-3 pt-2 border-t border-slate-800/80">
                            <div>
                              <h4 className="font-semibold text-amber-400 uppercase tracking-wider text-[11px] mb-1">
                                Problem Impact
                              </h4>
                              <p className="text-slate-300">{rem.why_it_is_problematic}</p>
                            </div>

                            <div>
                              <h4 className="font-semibold text-emerald-400 uppercase tracking-wider text-[11px] mb-1">
                                Recommended Fix
                              </h4>
                              <p className="text-slate-300">{rem.recommended_fix}</p>
                            </div>

                            {rem.corrected_code_example && (
                              <div className="space-y-1">
                                <div className="flex items-center justify-between">
                                  <h4 className="font-semibold text-blue-400 uppercase tracking-wider text-[11px]">
                                    Refactored Code Example
                                  </h4>
                                  <button
                                    onClick={() => handleCopyCode(rem.corrected_code_example, idx)}
                                    className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px]"
                                  >
                                    {copiedCodeIndex === idx ? (
                                      <>
                                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                                        <span className="text-emerald-400">Copied!</span>
                                      </>
                                    ) : (
                                      <>
                                        <Copy className="w-3.5 h-3.5" />
                                        <span>Copy Code</span>
                                      </>
                                    )}
                                  </button>
                                </div>

                                <pre className="bg-[#0b0f17] border border-slate-800 rounded-xl p-3 font-mono text-slate-200 text-xs overflow-x-auto">
                                  <code>{rem.corrected_code_example}</code>
                                </pre>
                              </div>
                            )}

                            <div className="pt-2 flex flex-wrap gap-2">
                              <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-medium">
                                Best Practice: {rem.best_practice}
                              </span>
                              {rem.references?.map((ref, rIdx) => (
                                <span key={rIdx} className="px-2.5 py-1 rounded bg-blue-950/50 border border-blue-500/20 text-blue-300">
                                  {ref}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Col: Executive PR Review Summary */}
        <div className="space-y-6">
          <div className="glass-panel p-6 space-y-5">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-blue-400" />
              Executive PR Review Summary
            </h2>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400 font-medium">Automated PR Status</span>
                <span
                  className={`px-2.5 py-1 rounded-full text-xs font-bold border ${
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
              <p className="text-xs text-slate-300 leading-relaxed">
                {pr_summary?.security_summary} {pr_summary?.code_quality_summary}
              </p>
            </div>

            {pr_summary?.top_risks && pr_summary.top_risks.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold text-red-400 uppercase tracking-wider">Top Priority Risks</h3>
                <div className="space-y-1.5">
                  {pr_summary.top_risks.map((risk, rIdx) => (
                    <div key={rIdx} className="p-2.5 rounded-lg bg-red-950/20 border border-red-500/20 text-xs text-slate-200">
                      {risk}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {pr_summary?.recommended_next_steps && pr_summary.recommended_next_steps.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Recommended Actions</h3>
                <div className="space-y-1.5">
                  {pr_summary.recommended_next_steps.map((step, sIdx) => (
                    <div key={sIdx} className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-xs text-slate-200">
                      &bull; {step}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {pr_summary?.estimated_remediation_effort && (
              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs space-y-1">
                <div className="flex justify-between">
                  <span className="text-slate-400">Critical Effort:</span>
                  <span className="font-semibold text-slate-200">{pr_summary.estimated_remediation_effort.critical}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Overall Effort:</span>
                  <span className="font-semibold text-blue-400">{pr_summary.estimated_remediation_effort.overall}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
