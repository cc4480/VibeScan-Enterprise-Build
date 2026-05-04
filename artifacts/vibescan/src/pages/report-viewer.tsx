import { useGetReport, getGetReportQueryKey } from "@workspace/api-client-react";
import { useRoute, Link } from "wouter";
import {
  Shield, ShieldAlert, CheckCircle2, ArrowLeft, Loader2, Globe, Server,
  Lock, Activity, Share2, Plus, Mail, GitBranch, KeyRound, Database,
  Terminal, ExternalLink, Package, RefreshCw, Eye, Code2, Wifi,
  AlertTriangle, Monitor, Info, Settings, Network, EyeOff, Filter, X,
  ArrowUpDown,
} from "lucide-react";
import { cn, formatSeverity, getSeverityColors, getGradeColor } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useMemo } from "react";
import type { Vulnerability } from "@workspace/api-client-react";

// ─── Category metadata ────────────────────────────────────────────────────────

interface CategoryMeta {
  label: string;
  icon: React.ReactNode;
  color: string;
}

const CATEGORY_META: Record<string, CategoryMeta> = {
  "Transport Security":              { label: "Transport Security",              icon: <Lock className="w-4 h-4" />,          color: "text-blue-400" },
  "Injection Defense":               { label: "Injection Defense",               icon: <Code2 className="w-4 h-4" />,         color: "text-orange-400" },
  "UI Security":                     { label: "UI Security",                     icon: <Monitor className="w-4 h-4" />,       color: "text-purple-400" },
  "Content Sniffing":                { label: "Content Sniffing",                icon: <Eye className="w-4 h-4" />,           color: "text-yellow-400" },
  "Information Disclosure":          { label: "Information Disclosure",          icon: <Info className="w-4 h-4" />,          color: "text-sky-400" },
  "Browser Feature Control":         { label: "Browser Feature Control",         icon: <Settings className="w-4 h-4" />,      color: "text-slate-400" },
  "CORS Misconfiguration":           { label: "CORS Misconfiguration",           icon: <Network className="w-4 h-4" />,       color: "text-red-400" },
  "Session Management":              { label: "Session Management",              icon: <KeyRound className="w-4 h-4" />,      color: "text-amber-400" },
  "CSRF Protection":                 { label: "CSRF Protection",                 icon: <RefreshCw className="w-4 h-4" />,     color: "text-cyan-400" },
  "Source Code Exposure":            { label: "Source Code Exposure",            icon: <GitBranch className="w-4 h-4" />,     color: "text-red-500" },
  "Credential Exposure":             { label: "Credential Exposure",             icon: <EyeOff className="w-4 h-4" />,        color: "text-rose-400" },
  "Data Exposure":                   { label: "Data Exposure",                   icon: <Database className="w-4 h-4" />,      color: "text-red-400" },
  "HTTP Security":                   { label: "HTTP Security",                   icon: <Terminal className="w-4 h-4" />,      color: "text-violet-400" },
  "Unvalidated Redirects":           { label: "Unvalidated Redirects",           icon: <ExternalLink className="w-4 h-4" />,  color: "text-orange-400" },
  "Supply Chain Security":           { label: "Supply Chain Security",           icon: <Package className="w-4 h-4" />,       color: "text-yellow-500" },
  "Brute Force Protection":          { label: "Brute Force Protection",          icon: <ShieldAlert className="w-4 h-4" />,   color: "text-orange-300" },
  "Email Security":                  { label: "Email Security",                  icon: <Mail className="w-4 h-4" />,          color: "text-emerald-400" },
  "DNS Security":                    { label: "DNS Security",                    icon: <Wifi className="w-4 h-4" />,          color: "text-teal-400" },
  "Exposed Secrets / Credentials":   { label: "Exposed Secrets",                icon: <AlertTriangle className="w-4 h-4" />, color: "text-red-500" },
  "Security Header Inconsistency":   { label: "Header Inconsistency",           icon: <AlertTriangle className="w-4 h-4" />, color: "text-amber-400" },
  "Outdated Software / Known CVE":   { label: "Outdated Software / CVE",        icon: <GitBranch className="w-4 h-4" />,     color: "text-red-400" },
  "Outdated Software":               { label: "Outdated Software",              icon: <GitBranch className="w-4 h-4" />,     color: "text-red-400" },
};

function getCategoryMeta(category: string): CategoryMeta {
  return CATEGORY_META[category] ?? {
    label: category,
    icon: <Globe className="w-4 h-4" />,
    color: "text-muted-foreground",
  };
}

// ─── Severity sort order ──────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

// ─── Grade ring ───────────────────────────────────────────────────────────────

function GradeRing({ grade, score }: { grade: string; score: number }) {
  const colorMap: Record<string, string> = {
    A: "#34d399", B: "#a3e635", C: "#facc15", D: "#fb923c", F: "#f87171",
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

// ─── Vuln card ────────────────────────────────────────────────────────────────

function VulnCard({ vuln, index }: { vuln: Vulnerability; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const meta = getCategoryMeta(vuln.category);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(0.05 * index, 0.4) }}
      className="glass-card rounded-xl overflow-hidden border border-white/5"
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-5 flex items-start sm:items-center justify-between text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex flex-col sm:flex-row sm:items-center gap-3 flex-1 min-w-0">
          <span className={cn("px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider shrink-0 border", getSeverityColors(vuln.severity))}>
            {vuln.severity}
          </span>
          <h4 className="text-base font-bold text-foreground leading-snug">{vuln.name}</h4>
        </div>
        <div className={cn("hidden md:flex items-center gap-1.5 text-xs font-medium shrink-0 ml-4", meta.color)}>
          {meta.icon}
          <span className="whitespace-nowrap">{meta.label}</span>
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
                  <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 text-sm text-foreground/90 leading-relaxed">
                    <div className="whitespace-pre-wrap">{vuln.solution}</div>
                  </div>

                  {(vuln.cweId || vuln.cvssScore) && (
                    <div className="mt-4 flex gap-3 flex-wrap">
                      {vuln.cweId && (
                        <a
                          href={`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace("CWE-", "")}.html`}
                          target="_blank" rel="noreferrer"
                          className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded hover:bg-secondary/80 transition-colors"
                        >
                          {vuln.cweId}
                        </a>
                      )}
                      {vuln.cvssScore != null && (
                        <span className={cn(
                          "text-xs px-2 py-1 rounded font-medium",
                          vuln.cvssScore >= 9 ? "bg-red-950 text-red-400" :
                          vuln.cvssScore >= 7 ? "bg-orange-950 text-orange-400" :
                          vuln.cvssScore >= 4 ? "bg-yellow-950 text-yellow-400" :
                          "bg-secondary text-muted-foreground",
                        )}>
                          CVSS {vuln.cvssScore.toFixed(1)}
                        </span>
                      )}
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

// ─── Category filter pill ─────────────────────────────────────────────────────

function CategoryPill({
  category, count, active, onClick,
}: { category: string; count: number; active: boolean; onClick: () => void }) {
  const meta = getCategoryMeta(category);
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all",
        active
          ? "bg-primary/15 border-primary/40 text-foreground"
          : "bg-secondary/50 border-white/5 text-muted-foreground hover:border-white/15 hover:text-foreground",
      )}
    >
      <span className={cn(active ? "text-primary" : meta.color)}>{meta.icon}</span>
      <span>{meta.label}</span>
      <span className={cn(
        "ml-1 rounded-full px-1.5 py-0.5 font-bold",
        active ? "bg-primary/20 text-primary" : "bg-white/10 text-muted-foreground",
      )}>{count}</span>
    </button>
  );
}

// ─── Summary new-findings callout ─────────────────────────────────────────────

const NEW_CATEGORY_LABELS: Record<string, string> = {
  "Email Security":                  "email spoofing risks",
  "Source Code Exposure":            "exposed source code",
  "Credential Exposure":             "exposed credentials",
  "Data Exposure":                   "exposed data files",
  "Exposed Secrets / Credentials":   "hardcoded secrets in JavaScript",
  "CORS Misconfiguration":           "CORS bypass issues",
  "Unvalidated Redirects":           "open redirect vulnerabilities",
  "HTTP Security":                   "dangerous HTTP methods",
  "Supply Chain Security":           "supply chain weaknesses",
  "Brute Force Protection":          "missing rate limiting",
  "DNS Security":                    "DNS security gaps",
  "Information Disclosure":          "information disclosure (robots.txt, error pages, exposed files)",
  "Transport Security":              "transport security issues (HTTP redirect, HSTS)",
  "UI Security":                     "UI security gaps (clickjacking protection)",
  "Security Header Inconsistency":   "header inconsistencies across pages",
  "Outdated Software / Known CVE":   "outdated software with known CVEs",
};

function SummaryNewFindings({ categories }: { categories: Record<string, number> }) {
  const notable = Object.entries(NEW_CATEGORY_LABELS)
    .filter(([cat]) => (categories[cat] ?? 0) > 0)
    .map(([, label]) => label);

  if (notable.length === 0) return null;

  return (
    <div className="mt-4 p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 text-sm text-amber-200/80 leading-relaxed">
      <span className="font-semibold text-amber-300">Also detected: </span>
      {notable.join(", ")}.
    </div>
  );
}

// ─── Share button ─────────────────────────────────────────────────────────────

function ShareButton({ reportId }: { reportId: string }) {
  const [copied, setCopied] = useState(false);

  const handleShare = async () => {
    const url = `${window.location.origin}${window.location.pathname.split("/report/")[0]}/report/${reportId}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      prompt("Copy this link:", url);
    }
  };

  return (
    <button
      onClick={handleShare}
      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors"
    >
      <Share2 className="w-4 h-4" />
      {copied ? "Link Copied!" : "Share Report"}
    </button>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ReportViewer() {
  const [, params] = useRoute("/report/:id");
  const reportId = params?.id || "";
  const { data: report, isLoading, error } = useGetReport(reportId, {
    query: {
      queryKey: getGetReportQueryKey(reportId),
      enabled: !!params?.id,
    },
  });

  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"severity" | "category">("severity");

  if (isLoading) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading report…</p>
      </div>
    );
  }
  if (error || !report) return <div className="min-h-[80vh] flex items-center justify-center text-red-400">Failed to load report.</div>;

  const { data: { summary, vulnerabilities, technologies, server, tlsGrade, aiAnalysis } } = report;

  const severityCounts = {
    critical: summary.critical,
    high: summary.high,
    medium: summary.medium,
    low: summary.low,
    info: summary.info,
  };

  // Sort vulnerabilities
  const sortedVulns = useMemo(() => {
    return [...vulnerabilities].sort((a, b) => {
      if (sortBy === "severity") {
        const sd = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
        if (sd !== 0) return sd;
        return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
      }
      const cd = a.category.localeCompare(b.category);
      if (cd !== 0) return cd;
      return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    });
  }, [vulnerabilities, sortBy]);

  // Per-category counts
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of vulnerabilities) {
      counts[v.category] = (counts[v.category] ?? 0) + 1;
    }
    return counts;
  }, [vulnerabilities]);

  const sortedCategories = useMemo(
    () => Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]).map(([c]) => c),
    [categoryCounts],
  );

  const filteredVulns = useMemo(
    () => activeCategory ? sortedVulns.filter((v) => v.category === activeCategory) : sortedVulns,
    [sortedVulns, activeCategory],
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-20">
      <div className="mb-8 flex items-center justify-between">
        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
        <ShareButton reportId={reportId} />
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
          <SummaryNewFindings categories={categoryCounts} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        {/* Left Col: Findings */}
        <div className="lg:col-span-2 space-y-8">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <h2 className="text-2xl font-bold flex items-center gap-3">
              <ShieldAlert className="w-6 h-6 text-primary" />
              Identified Vulnerabilities
              <span className="bg-secondary text-foreground text-sm py-1 px-3 rounded-full ml-2">
                {activeCategory ? `${filteredVulns.length} / ${summary.totalVulnerabilities}` : summary.totalVulnerabilities}
              </span>
            </h2>
          </div>

          {/* Severity badges */}
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

          {/* Sort toggle */}
          <div className="flex items-center gap-2">
            <ArrowUpDown className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-xs text-muted-foreground uppercase tracking-wider font-medium">Sort by</span>
            <div className="flex rounded-lg overflow-hidden border border-white/10 ml-1">
              {(["severity", "category"] as const).map((opt) => (
                <button
                  key={opt}
                  onClick={() => setSortBy(opt)}
                  className={cn(
                    "px-3 py-1.5 text-xs font-medium capitalize transition-colors",
                    sortBy === opt
                      ? "bg-primary/20 text-primary"
                      : "text-muted-foreground hover:text-foreground hover:bg-white/5",
                  )}
                >
                  {opt}
                </button>
              ))}
            </div>
          </div>

          {/* Category filter pills */}
          {sortedCategories.length > 1 && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Filter className="w-3.5 h-3.5" />
                <span className="uppercase tracking-wider font-medium">Filter by category</span>
                {activeCategory && (
                  <button
                    onClick={() => setActiveCategory(null)}
                    className="ml-auto flex items-center gap-1 text-primary hover:text-primary/80 transition-colors font-medium"
                  >
                    <X className="w-3 h-3" /> Clear
                  </button>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                {sortedCategories.map((cat) => (
                  <CategoryPill
                    key={cat}
                    category={cat}
                    count={categoryCounts[cat]}
                    active={activeCategory === cat}
                    onClick={() => setActiveCategory(activeCategory === cat ? null : cat)}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Vuln list */}
          <div className="space-y-4">
            <AnimatePresence mode="popLayout">
              {filteredVulns.map((v, i) => (
                <VulnCard key={v.id} vuln={v} index={i} />
              ))}
            </AnimatePresence>

            {filteredVulns.length === 0 && activeCategory && (
              <div className="text-center py-10 glass-card rounded-xl text-muted-foreground text-sm">
                No findings in this category.
              </div>
            )}

            {vulnerabilities.length === 0 && (
              <div className="text-center py-12 glass-card rounded-xl">
                <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-4" />
                <h3 className="text-xl font-bold mb-2">No vulnerabilities found</h3>
                <p className="text-muted-foreground">Excellent work. Your application appears secure based on our checks.</p>
              </div>
            )}
          </div>
        </div>

        {/* Right Col: Category sidebar + AI + Tech */}
        <div className="space-y-8">
          {/* Category breakdown */}
          {sortedCategories.length > 0 && (
            <div className="glass-card rounded-2xl p-6">
              <h3 className="text-sm font-bold mb-4 flex items-center gap-2 text-muted-foreground uppercase tracking-wider">
                <Filter className="w-4 h-4" /> Finding Categories
              </h3>
              <div className="space-y-1.5">
                <button
                  onClick={() => setActiveCategory(null)}
                  className={cn(
                    "w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors",
                    activeCategory === null
                      ? "bg-primary/20 text-primary border border-primary/30"
                      : "hover:bg-white/5 text-muted-foreground border border-transparent",
                  )}
                >
                  <span className="font-medium">All findings</span>
                  <span className="text-xs bg-secondary px-2 py-0.5 rounded-full">{vulnerabilities.length}</span>
                </button>
                {sortedCategories.map((cat) => {
                  const meta = getCategoryMeta(cat);
                  const count = categoryCounts[cat];
                  const isActive = activeCategory === cat;
                  return (
                    <button
                      key={cat}
                      onClick={() => setActiveCategory(isActive ? null : cat)}
                      className={cn(
                        "w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm transition-all text-left",
                        isActive
                          ? "bg-primary/10 border border-primary/30"
                          : "hover:bg-white/5 border border-transparent",
                      )}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className={meta.color}>{meta.icon}</span>
                        <span className={cn("truncate text-xs", isActive ? "text-foreground font-medium" : "text-muted-foreground")}>
                          {meta.label}
                        </span>
                      </div>
                      <span className={cn(
                        "shrink-0 text-xs font-bold rounded-full w-6 h-6 flex items-center justify-center",
                        isActive ? "bg-primary/20 text-primary" : "bg-secondary text-muted-foreground",
                      )}>{count}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* AI Analysis */}
          {aiAnalysis && (
            <div className="glass-card rounded-2xl p-6 border-t-4 border-t-primary">
              <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary" /> AI Analysis
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

                {aiAnalysis.complianceNotes && (
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Compliance Notes</h4>
                    <p className="text-sm text-muted-foreground/80 leading-relaxed">{aiAnalysis.complianceNotes}</p>
                  </div>
                )}
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
                  <span className="text-sm text-muted-foreground flex items-center gap-2"><Lock className="w-4 h-4" /> SSL/TLS Grade</span>
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

      {/* Bottom CTA */}
      <div className="glass-panel rounded-3xl p-8 md:p-12 text-center border border-primary/20 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
        <Shield className="w-12 h-12 text-primary mx-auto mb-4" />
        <h2 className="text-2xl md:text-3xl font-bold mb-3">Scan another website</h2>
        <p className="text-muted-foreground mb-8 max-w-md mx-auto">
          Check a different URL, a staging environment, or a client's site — each scan takes under 10 minutes.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] hover:-translate-y-1 transition-all duration-300"
          >
            <Plus className="w-5 h-5" /> New Scan
          </Link>
          <ShareButton reportId={reportId} />
        </div>
      </div>
    </div>
  );
}
