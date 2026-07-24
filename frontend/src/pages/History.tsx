import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History as HistoryIcon,
  Trash2,
  ExternalLink,
  Code2,
  Search,
  Calendar,
  AlertTriangle,
  FileCode
} from 'lucide-react';
import { storageService } from '../utils/storage';
import type { HistoricalReview } from '../types';

export const HistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const [history, setHistory] = useState<HistoricalReview[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    setHistory(storageService.getReviewHistory());
  }, []);

  const handleDelete = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const updated = storageService.deleteReview(id);
    setHistory(updated);
  };

  const handleClearAll = () => {
    if (window.confirm('Are you sure you want to clear all review history?')) {
      storageService.clearHistory();
      setHistory([]);
    }
  };

  const filteredHistory = history.filter(
    (item) =>
      item.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.language.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <HistoryIcon className="w-6 h-6 text-blue-400" />
            Review Session History
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Access past code review sessions stored locally in browser storage.
          </p>
        </div>

        {history.length > 0 && (
          <button
            onClick={handleClearAll}
            className="inline-flex items-center space-x-2 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-xl text-xs font-semibold cursor-pointer transition-all"
          >
            <Trash2 className="w-4 h-4" />
            <span>Clear History</span>
          </button>
        )}
      </div>

      {history.length > 0 && (
        <div className="glass-panel p-4 flex items-center justify-between">
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by filename or language..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>
          <span className="text-xs text-slate-400">Total Saved: {filteredHistory.length}</span>
        </div>
      )}

      {filteredHistory.length === 0 ? (
        <div className="text-center py-16 glass-panel space-y-3">
          <FileCode className="w-12 h-12 text-slate-600 mx-auto" />
          <h2 className="text-lg font-bold text-white">No Review History Found</h2>
          <p className="text-xs text-slate-400">Perform a code review to automatically save results here.</p>
          <button
            onClick={() => navigate('/review')}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold cursor-pointer transition-all"
          >
            Start Code Review
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredHistory.map((item) => {
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
                className="glass-panel p-4 hover:bg-slate-800/80 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all"
              >
                <div className="flex items-center space-x-4">
                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-blue-400">
                    <Code2 className="w-5 h-5" />
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-sm text-white">{item.filename}</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                        {item.language}
                      </span>
                    </div>
                    <div className="flex items-center space-x-3 text-xs text-slate-400">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3.5 h-3.5" />
                        {new Date(item.timestamp).toLocaleString()}
                      </span>
                      <span>&bull;</span>
                      <span className="flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        {item.result?.summary?.total_findings || 0} findings
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <span className={`text-xs px-3 py-1 rounded-full border font-bold ${statusBg}`}>
                    {status}
                  </span>

                  <button
                    onClick={(e) => handleDelete(item.id, e)}
                    className="p-2 hover:bg-red-500/20 text-slate-500 hover:text-red-400 rounded-lg transition-all"
                    title="Delete entry"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>

                  <ExternalLink className="w-4 h-4 text-slate-500 hover:text-slate-300" />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
