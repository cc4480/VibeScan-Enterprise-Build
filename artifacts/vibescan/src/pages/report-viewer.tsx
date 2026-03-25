import { useGetReport, getGetReportQueryKey } from "@workspace/api-client-react";
import { useRoute, Link } from "wouter";
import { Shield, ShieldAlert, CheckCircle2, ArrowLeft, Loader2, Globe, Server, Lock, ExternalLink, Activity, Info } from "lucide-react";
import { cn, formatSeverity, getSeverityColors, getGradeColor } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";
import type { Vulnerability } from "@workspace/api-client-react";

function GradeRing({ grade, score }: { grade: string, score: number }) {
  // Simple CSS conic gradient for ring based on score
  const colorMap: Record<string, string> = {
    A: "#34d399", // emerald-400
    B: "#a3e635", // lime-400
    C: "#facc15", // yellow-400
    D: "#fb923c", // orange-400
    F: "#f87171", // red-400
  };
  const color = colorMap[grade] || "#94a3b8";
  
  return (
    <div className="relative w-48 h-48 flex items-center justify-center">
      <svg className="w-full h-full transform -rotate-90 absolute inset-0">
        <circle cx="96" cy="96" r="88" fill="none" stroke="currentColor" strokeWidth="8" className="text-secondary" />
        <circle 
          cx="96" cy="96" r="88" fill="none" stroke={color} strokeWidth="8" 
          strokeDasharray={`${2 * Math.PI * 88}`}
          strokeDashoffset={`${2 * Math.PI * 88 * (1 - score / 100)}`}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="flex flex-col items-center justify-center bg-background w-36 h-36 rounded-full border-4 border-card shadow-2xl z-10 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-white/5 to-transparent rounded-full" />
        <span className={cn("text-6xl font-black font-display leading-none", getGradeColor(grade))}>
          {grade}
        </span>
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-widest mt-1">
          Risk: {score}
        </span>
      </div>
    </div>
  );
}

function VulnCard({ vuln, index }: { vuln: Vulnerability, index: number }) {
  const [expanded, setExpanded] = useState(false);
  
  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 * index }}
      className="glass-card rounded-xl overflow-hidden border border-white/5"
    >
      <button 
        onClick={() => setExpanded(!expanded)}
        className="w-full p-5 flex items-start sm:items-center justify-between text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <span className={cn("px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider shrink-0 border", getSeverityColors(vuln.severity))}>
            {vuln.severity}
          </span>
          <h4 className="text-lg font-bold text-foreground">{vuln.name}</h4>
        </div>
        <div className="text-sm text-muted-foreground hidden md:block">
          {vuln.category}
        </div>
      </button>
      
      <AnimatePresence>
        {expanded && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="p-5 pt-0 border-t border-white/5 mt-2 bg-secondary/20">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-5">
                <div className="flex flex-col gap-4">
                  <div>
                    <h5 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">Description</h5>
                    <p className="text-sm text-foreground/90 leading-relaxed">{vuln.description}</p>
                  </div>
                  {vuln.evidence && (
                    <div>
                      <h5 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">Evidence</h5>
                      <div className="bg-background border border-white/10 rounded-lg p-3 text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                        {vuln.evidence}
                      </div>
                    </div>
                  )}
                </div>
                <div>
                  <h5 className="text-xs font-bold text-primary uppercase tracking-wider mb-2 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" /> Recommended Fix
                  </h5>
                  <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 text-sm text-foreground/90 leading-relaxed prose prose-invert max-w-none">
                    {/* Assuming solution might contain simple markdown-like structure, rendering as text for safety but retaining whitespace */}
                    <div className="whitespace-pre-wrap">{vuln.solution}</div>
                  </div>
                  
                  {(vuln.cweId || vuln.cvssScore) && (
                    <div className="mt-4 flex gap-3">
                      {vuln.cweId && <span className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded">{vuln.cweId}</span>}
                      {vuln.cvssScore && <span className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded">CVSS: {vuln.cvssScore}</span>}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function ReportViewer() {
  const [, params] = useRoute("/report/:id");
  const reportId = params?.id || "";
  const { data: report, isLoading, error } = useGetReport(reportId, {
    query: {
      queryKey: getGetReportQueryKey(reportId),
      enabled: !!params?.id,
    },
  });

  if (isLoading) return <div className="min-h-[80vh] flex items-center justify-center"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  if (error || !report) return <div className="min-h-[80vh] flex items-center justify-center text-red-400">Failed to load report.</div>;

  const { data: { summary, vulnerabilities, technologies, server, tlsGrade, aiAnalysis } } = report;

  const severityCounts = {
    critical: summary.critical,
    high: summary.high,
    medium: summary.medium,
    low: summary.low,
    info: summary.info
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pb-20">
      <div className="mb-8">
        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
      </div>

      {/* Header / Cover */}
      <div className="glass-panel p-8 md:p-12 rounded-3xl mb-12 relative overflow-hidden flex flex-col md:flex-row items-center gap-12">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] pointer-events-none" />
        
        <GradeRing grade={summary.grade} score={summary.riskScore} />
        
        <div className="flex-1 text-center md:text-left z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary border border-white/5 text-xs font-medium text-muted-foreground mb-6">
            <Globe className="w-3.5 h-3.5" /> {report.targetUrl}
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4">Security Report</h1>
          <p className="text-lg text-muted-foreground/80 leading-relaxed max-w-2xl">
            {summary.executiveSummary}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        {/* Left Col: Findings Summary */}
        <div className="lg:col-span-2 space-y-8">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <h2 className="text-2xl font-bold flex items-center gap-3">
              <ShieldAlert className="w-6 h-6 text-primary" /> 
              Identified Vulnerabilities
              <span className="bg-secondary text-foreground text-sm py-1 px-3 rounded-full ml-2">{summary.totalVulnerabilities}</span>
            </h2>
          </div>

          <div className="flex flex-wrap gap-3">
            {Object.entries(severityCounts).map(([sev, count]) => {
              if (count === 0) return null;
              return (
                <div key={sev} className={cn("px-4 py-2 rounded-lg border flex items-center gap-3", getSeverityColors(sev))}>
                  <span className="font-bold uppercase text-xs tracking-wider">{sev}</span>
                  <span className="w-6 h-6 rounded bg-black/20 flex items-center justify-center text-sm font-bold">{count}</span>
                </div>
              );
            })}
          </div>

          <div className="space-y-4">
            {vulnerabilities.map((v, i) => (
              <VulnCard key={v.id} vuln={v} index={i} />
            ))}
            {vulnerabilities.length === 0 && (
              <div className="text-center py-12 glass-card rounded-xl">
                <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-4" />
                <h3 className="text-xl font-bold mb-2">No vulnerabilities found</h3>
                <p className="text-muted-foreground">Excellent work. Your application appears secure based on our checks.</p>
              </div>
            )}
          </div>
        </div>

        {/* Right Col: AI & Tech Details */}
        <div className="space-y-8">
          {/* AI Analysis */}
          {aiAnalysis && (
            <div className="glass-card rounded-2xl p-6 border-t-4 border-t-primary">
              <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary" /> DeepSeek Analysis
              </h3>
              
              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Overall Risk</h4>
                  <p className="text-sm">{aiAnalysis.overallRisk}</p>
                </div>
                
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Top Priorities</h4>
                  <ul className="space-y-2">
                    {aiAnalysis.topPriorities.map((p, i) => (
                      <li key={i} className="text-sm flex items-start gap-2">
                        <span className="text-primary mt-0.5">•</span> <span>{p}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Quick Wins</h4>
                  <ul className="space-y-2">
                    {aiAnalysis.quickWins.map((w, i) => (
                      <li key={i} className="text-sm flex items-start gap-2">
                        <span className="text-emerald-400 mt-0.5">✓</span> <span>{w}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Tech Profile */}
          <div className="glass-card rounded-2xl p-6">
            <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
              <Server className="w-5 h-5 text-muted-foreground" /> Tech Profile
            </h3>
            
            <div className="space-y-4">
              {tlsGrade && (
                <div className="flex items-center justify-between py-2 border-b border-white/5">
                  <span className="text-sm text-muted-foreground flex items-center gap-2"><Lock className="w-4 h-4"/> SSL/TLS Grade</span>
                  <span className={cn("font-bold", getGradeColor(tlsGrade))}>{tlsGrade}</span>
                </div>
              )}
              {server && (
                <div className="flex items-center justify-between py-2 border-b border-white/5">
                  <span className="text-sm text-muted-foreground">Server</span>
                  <span className="text-sm font-medium">{server}</span>
                </div>
              )}
              <div>
                <span className="text-sm text-muted-foreground mb-3 block">Detected Technologies</span>
                <div className="flex flex-wrap gap-2">
                  {technologies.map((t, i) => (
                    <span key={i} className="px-2.5 py-1 bg-secondary text-xs rounded-md border border-white/5">{t}</span>
                  ))}
                  {technologies.length === 0 && <span className="text-xs text-muted-foreground">None detected</span>}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
