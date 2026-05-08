import React, { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, CheckCircle, Info, Code, Play, Trash2, Zap, ChevronRight, FileCode, ExternalLink, ListChecks } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import Editor from '@monaco-editor/react';
import { analyzeCode } from './lib/analyzer/analyzer';
import { AnalysisReport, RiskLevel, VulnerabilityType, SecurityIssue } from './lib/analyzer/types';
import { SAMPLE_CODE_RCE, SAMPLE_CODE_XSS, SAMPLE_CODE_CSRF, SECURE_CODE } from './constants';

// Suppress ResizeObserver loop limit exceeded error
if (typeof window !== 'undefined') {
  const resizeObserverError = 'ResizeObserver loop completed with undelivered notifications.';
  const errorHandler = (e: any) => {
    if (e.message === resizeObserverError || e.message === 'ResizeObserver loop limit exceeded') {
      const resizeObserverErrDiv = document.getElementById('webpack-dev-server-client-overlay-div');
      const resizeObserverErrOverlay = document.getElementById('webpack-dev-server-client-overlay');
      if (resizeObserverErrDiv) resizeObserverErrDiv.style.display = 'none';
      if (resizeObserverErrOverlay) resizeObserverErrOverlay.style.display = 'none';
      e.stopImmediatePropagation();
    }
  };
  window.addEventListener('error', errorHandler);
  window.addEventListener('unhandledrejection', errorHandler);
}

const RiskBadge = ({ level }: { level: RiskLevel }) => {
  const colors = {
    [RiskLevel.CRITICAL]: 'bg-red-950 text-white border-red-900',
    [RiskLevel.HIGH]: 'bg-red-100 text-red-700 border-red-200',
    [RiskLevel.MEDIUM]: 'bg-amber-100 text-amber-700 border-amber-200',
    [RiskLevel.LOW]: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    [RiskLevel.INFORMATIONAL]: 'bg-blue-100 text-blue-700 border-blue-200',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border uppercase tracking-wider ${colors[level] || 'bg-slate-100'}`}>
      {level}
    </span>
  );
};

const ScoreCircle = ({ score }: { score: number }) => {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const getStatus = () => {
    if (score >= 96) return { name: 'Secure', color: 'text-emerald-500', bg: 'bg-emerald-50', stroke: 'stroke-emerald-500' };
    if (score >= 86) return { name: 'Informational', color: 'text-blue-500', bg: 'bg-blue-50', stroke: 'stroke-blue-500' };
    if (score >= 71) return { name: 'Low', color: 'text-green-400', bg: 'bg-green-50', stroke: 'stroke-green-400' };
    if (score >= 51) return { name: 'Medium', color: 'text-yellow-500', bg: 'bg-yellow-50', stroke: 'stroke-yellow-500' };
    if (score >= 36) return { name: 'High', color: 'text-red-500', bg: 'bg-red-50', stroke: 'stroke-red-500' };
    if (score >= 21) return { name: 'Very High', color: 'text-red-600', bg: 'bg-red-50', stroke: 'stroke-red-600' };
    return { name: 'Critical', color: 'text-red-900', bg: 'bg-red-50', stroke: 'stroke-red-900' };
  };

  const status = getStatus();

  return (
    <div className="relative flex items-center justify-center w-40 h-40">
      <svg className="w-full h-full transform rotate-180">
        <circle
          cx="80"
          cy="80"
          r={radius}
          stroke="currentColor"
          strokeWidth="10"
          fill="transparent"
          className="text-slate-100/50"
        />
        <motion.circle
          cx="80"
          cy="80"
          r={radius}
          stroke="currentColor"
          strokeWidth="10"
          fill="transparent"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.5, ease: "circOut" }}
          strokeLinecap="round"
          className={status.stroke}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-4xl font-black ${status.color}`}>{Math.round(score)}%</span>
        <span className="text-[10px] uppercase font-black tracking-widest text-slate-400">Safe</span>
        <span className={`text-[8px] uppercase font-black tracking-tighter px-2 py-0.5 rounded ${status.bg} ${status.color} mt-1`}>{status.name}</span>
      </div>
    </div>
  );
};

export default function App() {
  const [code, setCode] = useState(SAMPLE_CODE_RCE.trim());
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const editorRef = useRef<any>(null);

  const handleAnalyze = () => {
    setIsAnalyzing(true);
    setError(null);
    setTimeout(() => {
      try {
        const results = analyzeCode(code);
        setReport(results);
      } catch (err: any) {
        setError(err.message);
        setReport(null);
      } finally {
        setIsAnalyzing(false);
      }
    }, 800);
  };

  useEffect(() => {
    handleAnalyze();
  }, []);

  const jumpToLine = (line: number) => {
    if (editorRef.current) {
        editorRef.current.revealLineInCenter(line);
        editorRef.current.setPosition({ lineNumber: line, column: 1 });
        editorRef.current.focus();
    }
  };

  return (
    <div className="min-h-screen bg-[#FDFDFF] flex flex-col selection:bg-indigo-100">
      {/* Top Navigation */}
      <header className="h-16 px-6 bg-white border-b border-slate-200 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-200">
            <Shield className="text-white" size={20} />
          </div>
          <div>
            <h1 className="text-lg font-black text-slate-900 tracking-tight leading-none">SENTINEL<span className="text-indigo-600">JS</span></h1>
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Static Analysis System</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
            <div className="hidden md:flex flex-col items-end mr-4">
                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Engine Status</span>
                <span className="text-xs font-bold text-emerald-500 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    AST Scanner Active
                </span>
            </div>
            <button 
                onClick={handleAnalyze}
                disabled={isAnalyzing}
                className="h-10 px-6 bg-slate-900 hover:bg-black text-white rounded-xl font-bold flex items-center gap-2 transition-all active:scale-95 disabled:opacity-50 shadow-xl shadow-slate-200 group"
            >
                {isAnalyzing ? (
                <Zap size={18} className="animate-pulse text-yellow-400" />
                ) : (
                <Play size={16} fill="currentColor" />
                )}
                Analyze Security
            </button>
        </div>
      </header>

      <main className="flex-1 grid grid-cols-1 xl:grid-cols-[1fr,500px] gap-0">
        {/* Editor Side */}
        <div className="bg-[#1e1e1e] border-r border-slate-200 flex flex-col">
            <div className="h-12 bg-[#252526] flex items-center justify-between px-4">
                <div className="flex items-center gap-4">
                    <span className="flex items-center gap-2 text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                        <FileCode size={14} className="text-indigo-400" /> Source Input
                    </span>
                    <div className="flex bg-[#1e1e1e] p-0.5 rounded-lg border border-white/5">
                        {['RCE', 'XSS', 'CSRF', 'SECURE'].map((s) => (
                            <button
                                key={s}
                                onClick={() => {
                                    const sourceCode = s === 'RCE' ? SAMPLE_CODE_RCE : s === 'XSS' ? SAMPLE_CODE_XSS : s === 'CSRF' ? SAMPLE_CODE_CSRF : SECURE_CODE;
                                    setCode(sourceCode.trim());
                                    setTimeout(handleAnalyze, 100);
                                }}
                                className={`px-3 py-1 text-[10px] font-black uppercase rounded-md transition-all ${
                                    (s === 'SECURE' && code === SECURE_CODE.trim()) || 
                                    (s === 'RCE' && code === SAMPLE_CODE_RCE.trim()) ||
                                    (s === 'XSS' && code === SAMPLE_CODE_XSS.trim()) || 
                                    (s === 'CSRF' && code === SAMPLE_CODE_CSRF.trim())
                                    ? 'bg-indigo-600 text-white' : 'text-slate-500 hover:text-slate-300'
                                }`}
                            >
                                {s}
                            </button>
                        ))}
                    </div>
                </div>
                <button onClick={() => setCode('')} className="text-slate-500 hover:text-red-400 transition-colors">
                    <Trash2 size={16} />
                </button>
            </div>
            <div className="flex-1 min-h-[600px]">
                <Editor
                    height="100%"
                    defaultLanguage="javascript"
                    theme="vs-dark"
                    value={code}
                    onMount={(editor) => { editorRef.current = editor; }}
                    onChange={(val) => setCode(val || '')}
                    options={{
                        fontSize: 14,
                        fontFamily: "'JetBrains Mono', monospace",
                        minimap: { enabled: false },
                        scrollBeyondLastLine: false,
                        lineNumbers: 'on',
                        padding: { top: 20 },
                        automaticLayout: true,
                        bracketPairColorization: { enabled: true }
                    }}
                />
            </div>
        </div>

        {/* Report Side */}
        <div className="bg-white overflow-y-auto max-h-screen custom-scrollbar flex flex-col">
            <div className="p-8 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                <div>
                    <h2 className="text-xl font-black text-slate-900 tracking-tight mb-1">DASHBOARD</h2>
                    <p className="text-xs text-slate-500 font-bold uppercase tracking-widest flex items-center gap-2">
                        <ListChecks size={14} className="text-indigo-500" /> Taint Tracking Analysis
                    </p>
                </div>
                <div className="flex flex-col items-center">
                    {report && <ScoreCircle score={report.stats.score} />}
                </div>
            </div>

            <div className="p-8 space-y-8">
                {error && (
                    <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="p-4 bg-red-50 border border-red-100 rounded-2xl flex gap-3 items-start">
                        <AlertTriangle className="text-red-500 shrink-0" size={20} />
                        <div>
                            <h4 className="text-sm font-black text-red-900 uppercase">Engine Error</h4>
                            <p className="text-xs text-red-700 leading-relaxed mt-1">{error}</p>
                        </div>
                    </motion.div>
                )}

                {report && (
                    <div className="space-y-6">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-100">
                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest block mb-2">Critical Count</span>
                                <span className={`text-3xl font-black ${report.stats.critical > 0 ? 'text-red-900 underline decoration-red-500' : 'text-slate-300'}`}>{report.stats.critical}</span>
                            </div>
                            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-100">
                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest block mb-2">High Severity</span>
                                <span className="text-3xl font-black text-red-500">{report.stats.high}</span>
                            </div>
                        </div>

                        <div className="space-y-4">
                            <h3 className="text-xs font-black text-slate-400 uppercase tracking-[0.2em]">Detailed Findings</h3>
                            {report.issues.length === 0 ? (
                                <div className="p-12 text-center rounded-3xl border-4 border-dashed border-slate-50 flex flex-col items-center gap-4">
                                    <div className="w-16 h-16 bg-emerald-100 text-emerald-600 rounded-full flex items-center justify-center">
                                        <CheckCircle size={32} />
                                    </div>
                                    <p className="font-bold text-slate-800">System Secure</p>
                                    <p className="text-xs text-slate-500 max-w-[240px]">The analyzer found zero deterministic vulnerabilities in the scanned buffer.</p>
                                </div>
                            ) : (
                                report.issues.map((issue, i) => (
                                    <motion.div
                                        key={i}
                                        initial={{ opacity: 0, y: 20 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        transition={{ delay: i * 0.1 }}
                                        className="group p-6 bg-white border border-slate-200 rounded-3xl hover:border-indigo-500 transition-all shadow-sm hover:shadow-xl hover:shadow-indigo-50/50"
                                    >
                                        <div className="flex items-center justify-between mb-4">
                                            <div className="flex items-center gap-3">
                                                <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                                                    issue.risk === RiskLevel.CRITICAL ? 'bg-red-950 text-white' :
                                                    issue.type === VulnerabilityType.RCE ? 'bg-red-50 text-red-600' : 
                                                    issue.type === VulnerabilityType.XSS ? 'bg-amber-50 text-amber-600' : 'bg-blue-50 text-blue-600'
                                                }`}>
                                                    <AlertTriangle size={18} />
                                                </div>
                                                <div>
                                                    <h4 className="text-sm font-black text-slate-900 uppercase tracking-tight">{issue.type}</h4>
                                                    <button onClick={() => jumpToLine(issue.line)} className="text-[10px] font-bold text-indigo-500 hover:underline flex items-center gap-1 group">
                                                        {issue.location} <ChevronRight size={10} className="group-hover:translate-x-1 transition-transform" />
                                                    </button>
                                                </div>
                                            </div>
                                            <RiskBadge level={issue.risk} />
                                        </div>

                                        <p className="text-xs font-bold text-slate-800 mb-2 leading-relaxed">{issue.message}</p>
                                        <p className="text-xs text-slate-500 leading-relaxed mb-4 italic">{issue.explanation}</p>

                                        {issue.flow && issue.flow.length > 0 && (
                                            <div className="mb-4 p-4 bg-slate-50 rounded-2xl border border-slate-100">
                                                 <h5 className="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                                                    <Zap size={12} className="text-amber-500" /> Logical Detection Flow
                                                </h5>
                                                <div className="flex flex-wrap items-center gap-2">
                                                    {issue.flow.map((step, si) => (
                                                        <React.Fragment key={si}>
                                                            <div className={`px-2 py-1 rounded text-[10px] font-bold border shadow-sm ${
                                                                si === 0 ? 'bg-amber-50 text-amber-700 border-amber-200' :
                                                                si === issue.flow!.length - 1 ? 'bg-red-50 text-red-700 border-red-200' :
                                                                'bg-white text-slate-600 border-slate-200'
                                                            }`}>
                                                                {step}
                                                            </div>
                                                            {si < issue.flow!.length - 1 && (
                                                                <ChevronRight size={12} className="text-slate-300" />
                                                            )}
                                                        </React.Fragment>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        <div className="space-y-4">
                                            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
                                                <h5 className="text-[9px] font-black text-indigo-600 uppercase mb-3 flex items-center gap-2">
                                                    <Info size={12} /> Ordered Fix Steps
                                                </h5>
                                                <ul className="space-y-2">
                                                    {issue.fix_steps.map((step, si) => (
                                                        <li key={si} className="text-xs text-slate-600 flex items-start gap-2">
                                                            <span className="w-4 h-4 rounded-full bg-indigo-100 text-indigo-600 text-[8px] flex items-center justify-center font-black shrink-0 mt-0.5">{si+1}</span>
                                                            {step}
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                            <div className="bg-[#1e1e1e] p-4 rounded-2xl">
                                                <h5 className="text-[9px] font-black text-slate-500 uppercase mb-2">Remediation Snippet</h5>
                                                <pre className="text-[10px] text-emerald-400 font-mono whitespace-pre-wrap">{issue.fix_code}</pre>
                                            </div>
                                        </div>
                                    </motion.div>
                                ))
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
      </main>
      <footer className="py-8 px-6 bg-white border-t border-slate-100 text-center relative overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-64 h-px bg-gradient-to-r from-transparent via-indigo-500 to-transparent opacity-20" />
        <div className="relative z-10 flex flex-col items-center gap-1">
            <p className="text-[10px] font-black text-slate-400 uppercase tracking-[0.4em] mb-1">
                Made by <span className="text-slate-900 hover:text-indigo-600 transition-colors cursor-default">Tyrell Wellick</span> & <span className="text-slate-900 hover:text-indigo-600 transition-colors cursor-default">Joanna Wellick</span>
            </p>
            <div className="flex items-center gap-2 text-[8px] font-bold text-slate-300 uppercase tracking-[0.2em]">
                <span>E-CORP SECURITY DIVISION</span>
                <span className="w-1 h-1 rounded-full bg-slate-200" />
                <span className="italic font-medium">"Bonsoir, Elliot."</span>
            </div>
        </div>
      </footer>
    </div>
  );
}
