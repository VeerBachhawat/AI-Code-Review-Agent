import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Code2,
  Play,
  CheckCircle2,
  AlertCircle,
  FileCode,
  Sparkles,
  Loader2,
  FileText
} from 'lucide-react';
import { apiService } from '../services/api';
import { storageService } from '../utils/storage';
import { FileDropzone } from '../components/FileDropzone';

const SAMPLES = {
  vulnerable: `import os
import pickle
import hashlib

password = 'admin_secret_key_123'

def execute_user_query(user_id, raw_input):
    # Dynamic SQL string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    # Dynamic code evaluation
    eval(raw_input)
    
    # Path traversal vulnerability
    filepath = "/var/uploads/" + raw_input
    with open(filepath, "r") as f:
        data = f.read()
        
    # Unsafe deserialization
    obj = pickle.loads(data)
    return obj

def overly_complex_function(a, b, c, d, e, f, g):
    if a:
        if b:
            if c:
                if d:
                    if e:
                        return f + g
    return None
`,
  complexity: `def process_orders(orders, user_role, config, db_conn, logger, cache, flags):
    x = 10
    y = 20
    if user_role == 'admin':
        for order in orders:
            if order.is_valid:
                if order.status == 'pending':
                    if order.amount > 1000:
                        if config.allow_large_orders:
                            db_conn.save(order)
                            logger.info("Saved order")
                        else:
                            cache.set(order.id, order)
                    else:
                        db_conn.save(order)
    return True
`,
  secure: `import os
import ast

def get_user(cursor, user_id: str):
    # Secure parameterized SQL query:
    query = "SELECT id, username, email FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def parse_safe_literal(data_str: str):
    # Secure literal evaluation:
    return ast.literal_eval(data_str)
`
};

export const ReviewCode: React.FC = () => {
  const navigate = useNavigate();

  // Issue 1: Editor starts completely empty by default
  const [code, setCode] = useState('');
  const [filename, setFilename] = useState('');
  const [loading, setLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [syntaxStatus, setSyntaxStatus] = useState<{ status: 'idle' | 'valid' | 'error'; message: string }>({
    status: 'idle',
    message: ''
  });
  const [errorMsg, setErrorMsg] = useState('');

  const steps = [
    '✓ Syntax validation',
    '✓ AST Code & Security analysis',
    '⏳ AI Remediation generation',
    '○ Compiling PR summary'
  ];

  const detectedLanguage = useMemo(() => {
    if (filename) {
      const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
      if (ext === '.py') return 'Python';
      if (ext === '.java') return 'Java';
      if (['.cpp', '.cc', '.cxx', '.c', '.h', '.hpp'].includes(ext)) return 'C++';
      if (['.js', '.jsx', '.mjs', '.cjs'].includes(ext)) return 'JavaScript';
      if (['.ts', '.tsx'].includes(ext)) return 'TypeScript';
    }

    if (!code || !code.trim()) return 'Python';

    const text = code.trim();
    if (text.includes('public class ') || text.includes('System.out.print') || text.includes('public static void main')) {
      return 'Java';
    }
    if (text.includes('#include ') || text.includes('std::') || text.includes('int main(')) {
      return 'C++';
    }
    if (text.includes('interface ') || text.includes(': string') || text.includes(': number') || text.includes('type ')) {
      return 'TypeScript';
    }
    if (text.includes('const ') || text.includes('let ') || text.includes('function ') || text.includes('console.log')) {
      return 'JavaScript';
    }
    if (text.includes('def ') || text.includes('import ') || text.includes('elif ') || text.includes('self.') || text.includes('print(')) {
      return 'Python';
    }

    return 'Python';
  }, [code, filename]);

  const handleSyntaxCheck = async () => {
    if (!code.trim()) return;
    setSyntaxStatus({ status: 'idle', message: '' });

    try {
      const res = await apiService.submitCode(code, detectedLanguage.toLowerCase());
      if (res.status === 'success') {
        setSyntaxStatus({ status: 'valid', message: res.message || 'Syntax is valid!' });
      } else {
        setSyntaxStatus({ status: 'error', message: res.message || 'Syntax error detected.' });
      }
    } catch (e: any) {
      setSyntaxStatus({ status: 'error', message: e.response?.data?.message || e.message });
    }
  };

  const handleFileLoaded = (loadedCode: string, loadedFilename: string) => {
    setCode(loadedCode);
    setFilename(loadedFilename);
    setSyntaxStatus({ status: 'valid', message: `Loaded ${loadedFilename} successfully.` });
  };

  const handleRunReview = async () => {
    if (!code.trim()) {
      setErrorMsg('Please enter code or upload a file before starting review.');
      return;
    }

    setLoading(true);
    setErrorMsg('');
    setCurrentStep(0);

    const interval = setInterval(() => {
      setCurrentStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 2500);

    try {
      const response = await apiService.reviewCode(code, detectedLanguage.toLowerCase());
      clearInterval(interval);

      if (response.review) {
        const reviewResult = response.review;

        // Save to browser history
        storageService.saveReviewToHistory(
          code,
          filename || `snippet.${detectedLanguage.toLowerCase() === 'python' ? 'py' : 'txt'}`,
          detectedLanguage,
          reviewResult
        );

        // Store active result and code for Results page view & Chat context
        localStorage.setItem('active_review_result', JSON.stringify(reviewResult));
        localStorage.setItem('active_review_code', code);

        setLoading(false);
        navigate('/results');
      } else {
        throw new Error('Invalid review response received from backend.');
      }
    } catch (err: any) {
      clearInterval(interval);
      setLoading(false);
      setErrorMsg(err.response?.data?.message || err.message || 'Failed to analyze code.');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Code2 className="w-6 h-6 text-blue-400" />
            Code Security & Analysis Portal
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Submit source code or upload files for multi-agent AST static analysis & OWASP vulnerability scanning.
          </p>
        </div>

        {/* Read-only Detected Language Badge (Issue 2) */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-700 px-3 py-1.5 rounded-xl">
            <span className="text-xs text-slate-400">Detected Language:</span>
            <span className="text-xs font-bold text-blue-400 font-mono uppercase bg-blue-500/10 border border-blue-500/30 px-2 py-0.5 rounded">
              {detectedLanguage}
            </span>
          </div>
        </div>
      </div>

      {/* Issue 3: Professional Drag-and-Drop Area */}
      <FileDropzone
        onFileLoaded={handleFileLoaded}
        currentFilename={filename}
        detectedLanguage={detectedLanguage}
        hasCode={Boolean(code.trim())}
      />

      {/* Issue 1: Load Sample Button */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-400 font-medium whitespace-nowrap">Load Sample Code:</span>
        <button
          onClick={() => {
            setCode(SAMPLES.vulnerable);
            setFilename('vulnerable_demo.py');
          }}
          className="px-3 py-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg cursor-pointer transition-all whitespace-nowrap"
        >
          Load OWASP Flaws Sample
        </button>
        <button
          onClick={() => {
            setCode(SAMPLES.complexity);
            setFilename('complex_demo.py');
          }}
          className="px-3 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded-lg cursor-pointer transition-all whitespace-nowrap"
        >
          Load Complexity Sample
        </button>
        <button
          onClick={() => {
            setCode(SAMPLES.secure);
            setFilename('secure_demo.py');
          }}
          className="px-3 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg cursor-pointer transition-all whitespace-nowrap"
        >
          Load Secure Sample
        </button>
      </div>

      {/* Main Code Editor & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Code Editor Panel */}
        <div className="lg:col-span-3 space-y-4">
          <div className="glass-panel overflow-hidden border border-slate-800">
            <div className="bg-slate-900/80 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <FileCode className="w-4 h-4 text-blue-400" />
                <span className="text-xs font-mono text-slate-300 font-semibold">
                  {filename || 'pasted_code'}
                </span>
              </div>
              <div className="flex items-center space-x-2 text-xs text-slate-500">
                <span>UTF-8</span>
                <span>&bull;</span>
                <span>{code ? code.split('\n').length : 0} Lines</span>
              </div>
            </div>

            {/* Issue 1: Placeholder text */}
            <textarea
              value={code}
              onChange={(e) => {
                setCode(e.target.value);
                if (filename && !e.target.value) setFilename('');
              }}
              placeholder="Paste your source code here or drag & drop a source file."
              rows={18}
              className="w-full bg-[#0b0f17] text-slate-200 font-mono text-sm p-4 focus:outline-none resize-none border-none leading-relaxed placeholder-slate-600"
            ></textarea>
          </div>

          {/* Syntax Status & Error Messages */}
          {syntaxStatus.status !== 'idle' && (
            <div
              className={`p-3 rounded-xl border text-xs flex items-center space-x-2 ${
                syntaxStatus.status === 'valid'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-red-500/10 text-red-400 border-red-500/30'
              }`}
            >
              {syntaxStatus.status === 'valid' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-400" />
              )}
              <span>{syntaxStatus.message}</span>
            </div>
          )}

          {errorMsg && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center space-x-2">
              <AlertCircle className="w-4 h-4" />
              <span>{errorMsg}</span>
            </div>
          )}
        </div>

        {/* Action Controls Sidebar */}
        <div className="glass-panel p-6 space-y-6 flex flex-col justify-between">
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-blue-400" />
              Review Controls
            </h3>
            <p className="text-xs text-slate-400">
              Run AST analysis, complexity checks, security detectors, and remediation generators.
            </p>

            <button
              onClick={handleSyntaxCheck}
              disabled={!code.trim() || loading}
              className="w-full py-2.5 px-4 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-slate-200 rounded-xl text-xs font-semibold border border-slate-700 transition-all cursor-pointer flex items-center justify-center space-x-2"
            >
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Validate Syntax</span>
            </button>

            {/* Issue 4: Execute AI Review disabled until code exists OR file uploaded */}
            <button
              onClick={handleRunReview}
              disabled={!code.trim() || loading}
              className="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl text-sm font-bold shadow-lg shadow-blue-600/30 transition-all cursor-pointer flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing Code...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Execute AI Review</span>
                </>
              )}
            </button>
          </div>

          {/* Issue 5: Loading State Progress Messages */}
          {loading && (
            <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-500/30 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-semibold text-blue-400">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Multi-Agent Pipeline Active</span>
              </div>

              <div className="space-y-2">
                {steps.map((step, idx) => (
                  <div
                    key={idx}
                    className={`text-xs flex items-center space-x-2 transition-all ${
                      idx <= currentStep ? 'text-slate-200 font-medium' : 'text-slate-500'
                    }`}
                  >
                    <span
                      className={`w-2 h-2 rounded-full ${
                        idx === currentStep
                          ? 'bg-blue-400 animate-ping'
                          : idx < currentStep
                          ? 'bg-emerald-400'
                          : 'bg-slate-700'
                      }`}
                    ></span>
                    <span className="truncate">{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-slate-800 text-xs text-slate-400 space-y-1">
            <p className="flex items-center gap-1 text-slate-300 font-medium">
              <FileText className="w-3.5 h-3.5 text-blue-400" />
              Automated PDF & HTML Reports
            </p>
            <p>Generate downloadable executive reports instantly after review completion.</p>
          </div>
        </div>
      </div>
    </div>
  );
};
