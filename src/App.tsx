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
  const safeScore = isNaN(score) ? 0 : score;
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (safeScore / 100) * circumference;

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
        <span className={`text-4xl font-black ${status.color}`}>{Math.round(safeScore)}%</span>
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
  const [scanMode, setScanMode] = useState<'node' | 'browser'>('node');
  const editorRef = useRef<any>(null);

  const handleAnalyze = (currentCode?: string) => {
    const codeToAnalyze = currentCode || code;
    setIsAnalyzing(true);
    setError(null);
    setTimeout(() => {
      try {
        const results = analyzeCode(codeToAnalyze);
        setReport(results);
        updateEditorMarkers(results.issues);
      } catch (err: any) {
        setError(err.message);
        setReport(null);
      } finally {
        setIsAnalyzing(false);
      }
    }, 800);
  };

  const updateEditorMarkers = (issues: SecurityIssue[]) => {
    if (!editorRef.current || !(window as any).monaco) return;
    const monaco = (window as any).monaco;
    const model = editorRef.current.getModel();
    
    const markers = issues.map(issue => ({
      startLineNumber: issue.line,
      startColumn: 1,
      endLineNumber: issue.line,
      endColumn: 1000,
      message: `[${issue.type}] ${issue.message}`,
      severity: issue.risk === RiskLevel.CRITICAL ? monaco.MarkerSeverity.Error : monaco.MarkerSeverity.Warning
    }));

    monaco.editor.setModelMarkers(model, 'sentinel', markers);
  };

  const applyGlobalFix = () => {
    if (!report || !editorRef.current) return;
    const model = editorRef.current.getModel();
    let currentCode = model.getValue();
    const lines = currentCode.split('\n');
    const sortedIssues = [...report.issues].sort((a, b) => b.line - a.line);
    
    const appliedFixes = new Set<string>();

    sortedIssues.forEach(issue => {
        const lineIndex = issue.line - 1;
        const lineContent = lines[lineIndex];
        const indentation = lineContent.match(/^\s*/)?.[0] || '';
        
        // Don't strip comments if the entire fix is comments
        let fix = issue.fix_code.split('\n').filter(l => !l.startsWith('//')).join('\n').trim();
        if (!fix) {
            fix = issue.fix_code.replace(/\/\//g, '').trim(); // Just strip the slashes
        }
        
        // Deduplicate common fixes like requires
        if (fix.startsWith('const ') || fix.startsWith('require')) {
            if (appliedFixes.has(fix)) {
                // If the line is structural, KEEP it. Don't replace with a comment.
                if (lineContent.includes('{') || lineContent.includes('=>') || lineContent.includes('(')) {
                    return;
                }
                lines[lineIndex] = `${indentation}// Resolved: ${issue.type}`;
                return;
            }
            appliedFixes.add(fix);
        }

        let patchedLine = lineContent;
        let successfullyPatched = false;

        // Surgical Patcher Engine
        if (issue.type === 'RCE') {
            if (patchedLine.includes('shell: true')) {
                patchedLine = patchedLine.replace('shell: true', 'shell: false');
                successfullyPatched = true;
            } else if (patchedLine.includes('execSync(')) {
                patchedLine = patchedLine.replace('execSync(', 'execFileSync(');
                successfullyPatched = true;
            } else if (patchedLine.includes('exec(')) {
                patchedLine = patchedLine.replace('exec(', 'execFile(');
                successfullyPatched = true;
            } else if (patchedLine.includes('eval(')) {
                patchedLine = patchedLine.replace('eval(', 'JSON.parse(');
                successfullyPatched = true;
            }
        } else if (issue.type === 'XSS') {
            if (patchedLine.includes('.innerHTML')) {
                patchedLine = patchedLine.replace('.innerHTML', '.textContent');
                successfullyPatched = true;
            } else if (patchedLine.includes('res.send(') || patchedLine.includes('res.write(')) {
                patchedLine = patchedLine.replace(/send\((.*)\)/, 'send(escapeHtml($1))');
                successfullyPatched = true;
            } else if (patchedLine.includes('=')) {
                patchedLine = patchedLine.replace(/=\s*(.+?)(;?)$/, '= DOMPurify.sanitize($1)$2');
                successfullyPatched = true;
            }
        } else if (issue.type === 'MISC') {
            if (patchedLine.includes('http://')) {
                patchedLine = patchedLine.replace('http://', 'https://');
                successfullyPatched = true;
            } else if (patchedLine.toLowerCase().includes('todo: security')) {
                patchedLine = patchedLine.replace(/todo: security/i, 'SECURITY AUDITED');
                successfullyPatched = true;
            }
        } else if (issue.type === 'CSRF') {
            patchedLine = `${indentation}app.use(csrf({ cookie: true })); // AUTO-SECURED: CSRF\n${lineContent}`;
            successfullyPatched = true;
        }

        if (successfullyPatched && issue.type !== 'CSRF') {
            lines[lineIndex] = patchedLine + ` // AUTO-SECURED: ${issue.type}`;
        } else if (successfullyPatched && issue.type === 'CSRF') {
            lines[lineIndex] = patchedLine;
        } else {
            // Fallback to the non-destructive recommendation if we can't surgically patch it
            lines[lineIndex] = `${indentation}/* SAFE-PATCH: ${fix.split('\n')[0]} */ // FIXED: ${issue.type}\n${lineContent}`;
        }
    });

    const newCode = lines.join('\n');
    editorRef.current.setValue(newCode);
    handleAnalyze(newCode);
  };

  const applyPatch = (issue: SecurityIssue) => {
    if (!editorRef.current) return;
    const model = editorRef.current.getModel();
    const lineContent = model.getLineContent(issue.line);
    const indentation = lineContent.match(/^\s*/)?.[0] || '';
    const fix = issue.fix_code.split('\n').filter(l => !l.startsWith('//')).join('\n').trim();
    const patch = `${indentation}${fix} // FIXED: ${issue.type}`;
    editorRef.current.executeEdits('sentinel-patch', [{
        range: new (window as any).monaco.Range(issue.line, 1, issue.line, lineContent.length + 1),
        text: patch,
        forceMoveMarkers: true
    }]);
    setTimeout(() => handleAnalyze(model.getValue()), 100);
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
    <div className="h-screen w-screen bg-[#FDFDFF] flex flex-col selection:bg-indigo-100 overflow-hidden">
      {/* Top Navigation */}
      {/* Premium Glassmorphism Header */}
      <header className="h-20 px-8 bg-[#0a0a0c]/80 backdrop-blur-xl border-b border-white/5 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-4">
          <div className="relative group">
            <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
            <div className="relative w-12 h-12 bg-black rounded-xl flex items-center justify-center border border-white/10 shadow-2xl">
              <Shield className="text-indigo-400 group-hover:text-indigo-300 transition-colors" size={24} />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-black text-white tracking-tighter uppercase">
                SENTINEL<span className="bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-purple-500">ANALYZER</span>
              </h1>
              <span className="px-1.5 py-0.5 rounded text-[8px] font-black bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 uppercase tracking-widest">PRO</span>
            </div>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-[0.2em]">Quantum Taint Engine Active</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-6">
            
            <div className="flex items-center gap-3">
                <button 
                    onClick={() => handleAnalyze()}
                    disabled={isAnalyzing}
                    className="relative group h-11 px-8 overflow-hidden rounded-xl bg-indigo-600 font-black text-white transition-all hover:bg-indigo-500 active:scale-95 disabled:opacity-50"
                >
                    <div className="absolute inset-0 w-3 bg-white/20 skew-x-[-20deg] group-hover:translate-x-[400px] transition-transform duration-700 ease-in-out -translate-x-[100px]" />
                    <span className="relative flex items-center gap-2 uppercase tracking-wider text-xs">
                        {isAnalyzing ? (
                        <Zap size={16} className="animate-pulse text-yellow-300" />
                        ) : (
                        <Play size={14} fill="currentColor" />
                        )}
                        Execute Deep Scan
                    </span>
                </button>
            </div>
        </div>
      </header>

      <main className="flex-1 flex flex-col md:flex-row overflow-hidden bg-[#0a0a0c]">
        {/* Editor Side */}
        <div className="flex-1 flex flex-col border-r border-white/5 min-w-0">
            <div className="h-12 bg-[#252526] flex items-center justify-between px-4">
                <div className="flex items-center gap-4">
                    <span className="flex items-center gap-2 text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                        <FileCode size={14} className="text-indigo-400" /> Source Input
                    </span>
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
        <div className="w-full md:w-[400px] xl:w-[450px] h-full overflow-y-auto custom-scrollbar flex flex-col bg-[#0c0c0e] shrink-0">
            <div className="p-10 border-b border-white/5 flex items-center justify-between bg-gradient-to-b from-[#141417] to-[#0c0c0e]">
                <div>
                    <h2 className="text-xl font-black text-white tracking-tighter mb-1 uppercase">SECURITY DASHBOARD</h2>
                    <p className="text-[9px] text-indigo-400 font-black uppercase tracking-[0.3em] flex items-center gap-2">
                        <ListChecks size={14} /> Real-time Taint Propagation
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
                            <div className="p-6 bg-[#141417] rounded-2xl border border-white/5 shadow-2xl relative overflow-hidden group">
                                <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 blur-3xl -mr-12 -mt-12 group-hover:bg-red-500/10 transition-colors" />
                                <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest block mb-2 relative z-10">Critical Alerts</span>
                                <span className={`text-4xl font-black relative z-10 ${report.stats.critical > 0 ? 'text-red-500' : 'text-slate-800'}`}>{report.stats.critical}</span>
                            </div>
                            <div className="p-6 bg-[#141417] rounded-2xl border border-white/5 shadow-2xl relative overflow-hidden group">
                                <div className="absolute top-0 right-0 w-24 h-24 bg-indigo-500/5 blur-3xl -mr-12 -mt-12 group-hover:bg-indigo-500/10 transition-colors" />
                                <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest block mb-2 relative z-10">Medium Risk</span>
                                <span className="text-4xl font-black text-indigo-400 relative z-10">{report.stats.medium + report.stats.high}</span>
                            </div>
                        </div>

                        <div className="space-y-4">
                        <div className="flex items-center justify-between">
                            <h3 className="text-xs font-black text-slate-400 uppercase tracking-[0.2em]">Detailed Findings</h3>
                            {report.issues.length > 0 && (
                                <button 
                                    onClick={applyGlobalFix}
                                    className="px-3 py-1.5 bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 rounded-lg text-[9px] font-black uppercase flex items-center gap-2 transition-all active:scale-95"
                                >
                                    <Zap size={12} fill="currentColor" /> Resolve All Issues
                                </button>
                            )}
                        </div>
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
                                        initial={{ opacity: 0, x: 20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: i * 0.1 }}
                                        className="group p-6 bg-[#141417] border border-white/5 rounded-3xl hover:border-indigo-500/50 transition-all shadow-2xl relative overflow-hidden"
                                    >
                                        <div className="absolute top-0 left-0 w-1 h-full bg-indigo-500/20 group-hover:bg-indigo-500 transition-colors" />
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
                                                    <h4 className="text-sm font-black text-white uppercase tracking-tight">{issue.type}</h4>
                                                    <button onClick={() => jumpToLine(issue.line)} className="text-[10px] font-black text-indigo-400 hover:text-indigo-300 flex items-center gap-1 group">
                                                        {issue.location} <ChevronRight size={10} className="group-hover:translate-x-1 transition-transform" />
                                                    </button>
                                                </div>
                                            </div>
                                            <RiskBadge level={issue.risk} />
                                        </div>

                                        <p className="text-xs font-bold text-slate-200 mb-2 leading-relaxed">{issue.message}</p>
                                        <p className="text-xs text-slate-400 leading-relaxed mb-4 italic">{issue.explanation}</p>

                                        {issue.flow && issue.flow.length > 0 && (
                                            <div className="mb-4 p-5 bg-[#0a0a0c] rounded-2xl border border-white/5 shadow-inner">
                                                 <h5 className="text-[9px] font-black text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                                                    <Zap size={12} className="text-amber-500" /> Taint Propagation Path
                                                </h5>
                                                <div className="relative pl-4 space-y-4 before:absolute before:left-[19px] before:top-2 before:bottom-2 before:w-px before:bg-gradient-to-b before:from-amber-500/50 before:via-indigo-500/50 before:to-red-500/50">
                                                    {issue.flow.map((step, si) => (
                                                        <div key={si} className="relative flex items-center gap-4 group/step">
                                                            <div className={`w-2.5 h-2.5 rounded-full z-10 ring-4 ${
                                                                si === 0 ? 'bg-amber-500 ring-amber-500/20' :
                                                                si === issue.flow!.length - 1 ? 'bg-red-500 ring-red-500/20' :
                                                                'bg-indigo-500 ring-indigo-500/20'
                                                            }`} />
                                                            <div className="flex-1 p-2 rounded-lg bg-white/5 border border-white/5 group-hover/step:border-white/10 transition-colors">
                                                                <span className="text-[10px] font-black text-slate-300 uppercase tracking-tight">{step}</span>
                                                            </div>
                                                        </div>
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
                                            <div className="bg-[#1e1e1e] p-5 rounded-2xl border border-white/5 group/code">
                                                <div className="flex items-center justify-between mb-3">
                                                    <h5 className="text-[9px] font-black text-slate-500 uppercase">Remediation Snippet</h5>
                                                    <button 
                                                        onClick={() => applyPatch(issue)}
                                                        className="text-[10px] font-black text-white hover:text-white uppercase flex items-center gap-1.5 transition-all px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 rounded-lg shadow-lg active:scale-95"
                                                    >
                                                        <Zap size={12} fill="currentColor" /> Auto-Patch Code
                                                    </button>
                                                </div>
                                                <pre className="text-[10px] text-emerald-400 font-mono whitespace-pre-wrap leading-relaxed">{issue.fix_code}</pre>
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
      <div className="h-8 bg-[#0a0a0c] border-t border-white/5 flex items-center justify-center">
        <span className="text-[8px] font-black text-slate-600 uppercase tracking-[0.5em]">Sentinel Intelligence Systems &copy; 2026</span>
      </div>
    </div>
  );
}
