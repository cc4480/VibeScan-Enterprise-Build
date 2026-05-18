import {
  useGetReport, getGetReportQueryKey,
  useCreateReportShare, useListReportShares, useRevokeReportShare,
  getListReportSharesQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useRoute, Link } from "wouter";
import {
  Shield, ShieldAlert, CheckCircle2, ArrowLeft, Loader2, Globe, Server,
  Lock, Activity, Share2, Plus, Mail, GitBranch, KeyRound, Database,
  Terminal, ExternalLink, Package, RefreshCw, Eye, Code2, Wifi,
  AlertTriangle, Monitor, Info, Settings, Network, EyeOff, Filter, X,
  ArrowUpDown, HelpCircle, Download, Copy, Check, Bell, ChevronDown, Search, Minus, Flag, RotateCcw,
} from "lucide-react";
import { cn, formatSeverity, getSeverityColors, getGradeColor } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useMemo, useCallback, useEffect, createContext, useContext, useRef } from "react";
import type { Vulnerability } from "@workspace/api-client-react";

// ─── Dismissals context ───────────────────────────────────────────────────────

interface DismissalEntry {
  fingerprint: string;
  findingName: string;
  findingCategory: string;
}

// ─── Client-side fingerprint helpers (mirror server lib/fingerprint.ts) ────────

function normalizeEvidenceKeyClient(evidence?: string | null): string {
  if (!evidence) return "";
  return evidence
    .toLowerCase()
    .replace(/https?:\/\/[^\s]+/g, "url")
    .replace(/\b[0-9a-f]{8,}\b/gi, "hash")
    .replace(/\b\d[\d.]+\d\b/g, "N")
    .replace(/['"`;,]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 50);
}

async function computeVulnFp(
  category: string,
  name: string,
  evidence?: string | null,
): Promise<string> {
  const evidenceKey = normalizeEvidenceKeyClient(evidence);
  const input = evidenceKey
    ? `${category.toLowerCase().trim()}::${name.toLowerCase().trim()}::${evidenceKey}`
    : `${category.toLowerCase().trim()}::${name.toLowerCase().trim()}`;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 20);
}

function vulnUniqueKey(v: { category: string; name: string; evidence?: string | null }): string {
  return `${v.category}:${v.name}:${v.evidence ?? ""}`;
}

// ─── Dismissals context ──────────────────────────────────────────────────────

interface DismissalsCtx {
  dismissedFps: Set<string>;
  vulnFpMap: Map<string, string>;
  optimisticDismissKeys: Set<string>;
  dismiss: (vuln: Vulnerability, targetUrl: string) => Promise<void>;
  undismiss: (vuln: Vulnerability) => Promise<void>;
}

const DismissalsContext = createContext<DismissalsCtx>({
  dismissedFps: new Set(),
  vulnFpMap: new Map(),
  optimisticDismissKeys: new Set(),
  dismiss: async () => {},
  undismiss: async () => {},
});

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
  "Network Exposure":                { label: "Network Exposure",               icon: <Network className="w-4 h-4" />,       color: "text-red-400" },
};

// Maps a WSTG ID like "WSTG-CONF-07" to its OWASP Testing Guide URL path fragment
const WSTG_PATHS: Record<string, string> = {
  "WSTG-CONF-02": "02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
  "WSTG-CONF-04": "02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
  "WSTG-CONF-05": "02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
  "WSTG-CONF-06": "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
  "WSTG-CONF-07": "02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",
  "WSTG-CONF-10": "02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
  "WSTG-CONF-12": "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy",
  "WSTG-CRYP-01": "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
  "WSTG-INFO-01": "01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage",
  "WSTG-INFO-02": "01-Information_Gathering/02-Fingerprint_Web_Server",
  "WSTG-INFO-09": "01-Information_Gathering/09-Fingerprint_Web_Application_Framework",
  "WSTG-CLNT-01": "11-Client-Side_Testing/01-Testing_for_DOM-Based_Cross_Site_Scripting",
  "WSTG-CLNT-04": "11-Client-Side_Testing/04-Testing_for_Client-Side_URL_Redirect",
  "WSTG-CLNT-09": "11-Client-Side_Testing/09-Testing_for_Clickjacking",
  "WSTG-SESS-02": "06-Testing_for_Session_Management/02-Testing_for_Cookies_Attributes",
  "WSTG-SESS-10": "06-Testing_for_Session_Management/10-Testing_JSON_Web_Tokens",
  "WSTG-ATHN-03": "04-Testing_for_Authentication/03-Testing_for_Weak_Lock_Out_Mechanism",
  "WSTG-AUTHZ-01": "05-Testing_for_Authorization/01-Testing_Directory_Traversal_File_Include",
};

function wstgCategoryPath(id: string): string {
  return WSTG_PATHS[id] ?? "";
}

function getCategoryMeta(category: string): CategoryMeta {
  return CATEGORY_META[category] ?? {
    label: category,
    icon: <Globe className="w-4 h-4" />,
    color: "text-muted-foreground",
  };
}

// ─── Verification threshold ───────────────────────────────────────────────────
// Findings below this confidence score are shown in a separate "Needs Verification"
// section so confirmed findings stay trustworthy and nothing gets silently dropped.

const VERIFICATION_THRESHOLD = 65;

// Per-category explanation shown inside unverified finding cards
const VERIFICATION_NOTES: Record<string, string> = {
  "Outdated Software / Known CVE":
    "Detected by matching a version string in the HTTP response against known CVEs. CDNs and load balancers sometimes expose version headers from underlying infrastructure that isn't directly exploitable, or the version may be masked. Confirm the version is accurate and check whether the CVE applies to your specific deployment configuration.",
  "Outdated Software":
    "Detected by matching a version string against known CVEs. Verify the version is accurate and not a proxy artifact, then confirm whether this CVE is exploitable in your environment.",
  "DNS Security":
    "Detected via DNS lookups. Subdomain takeover findings require manual confirmation — verify the CNAME target is genuinely unclaimed and that a hostile party could register it.",
  "Supply Chain Security":
    "Detected by checking external script URLs for Subresource Integrity attributes. Confirm the CDN is trusted and whether your CSP already mitigates this risk.",
  "Exposed Secrets / Credentials":
    "Detected by regex pattern matching in JavaScript source. The scanner applies filters for common placeholders, but confirm the matched value is a live credential and not an example, test fixture, or already-rotated key.",
};

function getVerificationNote(category: string): string {
  return (
    VERIFICATION_NOTES[category] ??
    "This finding was detected using a heuristic or pattern-based method. Reproduce it manually with a raw HTTP request to confirm it is a real, exploitable issue before prioritising remediation."
  );
}

// ─── Tech version parsing ─────────────────────────────────────────────────────
// Technologies are stored as "jQuery 1.11.3" or "Nginx 1.18.0".
// Split on the last whitespace-separated token that starts with a digit.

function parseTechVersion(tech: string): { name: string; version: string | null } {
  // Space-separated: "jQuery 1.11.3" or "Nginx 1.18.0" (canonical scanner output)
  const spaceMatch = /^(.+?)\s+(\d[\w.\-]*)$/.exec(tech);
  if (spaceMatch) return { name: spaceMatch[1], version: spaceMatch[2] };
  // Slash-separated: "nginx/1.18.0" (raw header values surfaced directly)
  const slashMatch = /^(.+?)\/(\d[\w.\-]*)$/.exec(tech);
  if (slashMatch) return { name: slashMatch[1], version: slashMatch[2] };
  return { name: tech, version: null };
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

// ─── Inner-page source extractor ─────────────────────────────────────────────

const INNER_PAGE_CATEGORIES = new Set([
  "Security Header Inconsistency",
  "Session Management",
]);

/**
 * Tries to extract a non-root path from a finding's evidence field.
 * Only applies to "Security Header Inconsistency" and "Session Management" categories.
 *
 * Handles two evidence formats produced by the crawler:
 *   1. Session Management: "GET https://host/path\nSet-Cookie: ..."
 *      → extracts the pathname from the full URL
 *   2. Security Header Inconsistency: "Routes missing X:\n  • /path (crawled)\n..."
 *      → extracts the first bullet-list path
 *
 * Returns the pathname (e.g. "/api/v1") when it's a non-root inner page, else null.
 */
function extractInnerPageSource(
  evidence: string | null | undefined,
  rootUrl: string,
  category: string,
): string | null {
  if (!evidence || !INNER_PAGE_CATEGORIES.has(category)) return null;

  // Format 1: "GET https://host/path" — Session Management cookie findings
  // Also matches "[Direct probe] GET https://host/path" prefix variant
  const getMatch = /^(?:\[[^\]]*\]\s+)?GET\s+(https?:\/\/\S+)/m.exec(evidence);
  if (getMatch) {
    try {
      const url = new URL(getMatch[1]);
      const root = new URL(rootUrl);
      if (url.hostname !== root.hostname) return null;
      const path = url.pathname;
      if (!path || path === "/" || path === root.pathname) return null;
      return path;
    } catch {
      return null;
    }
  }

  // Format 2: "Routes missing X:\n  • /path (crawled)" — Security Header Inconsistency
  const bulletMatch = /•\s+(\/[^\s(]*)/.exec(evidence);
  if (bulletMatch) {
    const path = bulletMatch[1];
    try {
      const root = new URL(rootUrl);
      if (!path || path === "/" || path === root.pathname) return null;
    } catch {
      // ignore URL parse errors; still return the path
    }
    return path;
  }

  return null;
}

// ─── Vuln card ────────────────────────────────────────────────────────────────

function VulnCard({
  vuln,
  index,
  needsVerification,
  rootUrl,
}: {
  vuln: Vulnerability;
  index: number;
  needsVerification?: boolean;
  rootUrl?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const { dismiss, undismiss, dismissedFps, vulnFpMap, optimisticDismissKeys } = useContext(DismissalsContext);
  const vKey = vulnUniqueKey(vuln);
  const fp = vulnFpMap.get(vKey);
  const isDismissed = optimisticDismissKeys.has(vKey) || (fp !== undefined && dismissedFps.has(fp));
  const [dismissPending, setDismissPending] = useState(false);
  const meta = getCategoryMeta(vuln.category);

  // Extract the affected component for CVE / outdated-software findings.
  // Hoisted here so both the header chip and the expanded detail share the same value.
  const isCveCategory =
    vuln.category === "Outdated Software / Known CVE" ||
    vuln.category === "Outdated Software";
  const rawComponent = isCveCategory
    ? (/^(.+?)\s+—/.exec(vuln.name)?.[1] ??
       /^Detected:\s+(.+)$/m.exec(vuln.evidence ?? "")?.[1] ??
       null)
    : null;
  const { name: compName, version: compVersion } = rawComponent
    ? parseTechVersion(rawComponent)
    : { name: null, version: null };

  // Extract inner-page source path (e.g. "/api/v1") for crawler findings
  // Only shown for Security Header Inconsistency and Session Management categories
  const innerPageSource = rootUrl
    ? extractInnerPageSource(vuln.evidence, rootUrl, vuln.category)
    : null;

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
          <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 min-w-0">
            <h4 className="text-base font-bold text-foreground leading-snug">{vuln.name}</h4>
            {compName && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-yellow-500/10 border border-yellow-500/20 rounded text-[10px] font-mono leading-none text-yellow-400/80 shrink-0 self-start sm:self-auto">
                <Package className="w-2.5 h-2.5" />
                {compName}{compVersion ? `@${compVersion}` : ""}
              </span>
            )}
            {innerPageSource && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-sky-500/10 border border-sky-500/20 rounded text-[10px] font-mono leading-none text-sky-400/70 shrink-0 self-start sm:self-auto" title={`Found on inner page: ${innerPageSource}`}>
                <Globe className="w-2.5 h-2.5" />
                {innerPageSource}
              </span>
            )}
          </div>
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
              {needsVerification && (
                <div className="mt-4 mb-1 flex gap-3 p-3 rounded-lg bg-amber-500/8 border border-amber-500/25">
                  <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-semibold text-amber-300 mb-0.5">Manual verification recommended</p>
                    <p className="text-xs text-amber-200/70 leading-relaxed">{getVerificationNote(vuln.category)}</p>
                  </div>
                </div>
              )}
              {/* Detected component badge for CVE/outdated-software findings */}
              {compName && (
                <div className="mt-4 flex items-center gap-2">
                  <span className="text-xs text-muted-foreground font-medium">Detected component:</span>
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-secondary rounded-md border border-white/10 text-xs font-mono">
                    <Package className="w-3 h-3 text-yellow-400 shrink-0" />
                    <span className="font-medium text-foreground/90">{compName}</span>
                    {compVersion && (
                      <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] rounded border border-yellow-500/20 leading-none font-mono">
                        {compVersion}
                      </span>
                    )}
                  </span>
                </div>
              )}

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

                  {(vuln.cweId || vuln.cvssScore != null || vuln.wstgId || vuln.confidence != null) && (
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
                      {vuln.wstgId && (
                        <a
                          href={`https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/${wstgCategoryPath(vuln.wstgId)}`}
                          target="_blank" rel="noreferrer"
                          className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded hover:bg-secondary/80 transition-colors"
                        >
                          {vuln.wstgId}
                        </a>
                      )}
                      {vuln.confidence != null && (
                        <span
                          title="Confidence: how certain the scanner is this is a real finding, not a false positive"
                          className={cn(
                            "text-xs px-2 py-1 rounded font-medium",
                            vuln.confidence >= 85 ? "bg-emerald-950 text-emerald-400" :
                            vuln.confidence >= 70 ? "bg-teal-950 text-teal-400" :
                            vuln.confidence >= 55 ? "bg-yellow-950 text-yellow-500" :
                            "bg-secondary text-muted-foreground",
                          )}
                        >
                          {vuln.confidence}% confidence
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* False positive dismissal */}
            <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-between">
              <p className="text-xs text-muted-foreground">Not applicable to your setup?</p>
              {isDismissed ? (
                <button
                  onClick={async (e) => {
                    e.stopPropagation();
                    setDismissPending(true);
                    await undismiss(vuln);
                    setDismissPending(false);
                  }}
                  disabled={dismissPending}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
                >
                  <RotateCcw className="w-3 h-3" />
                  Undo dismissal
                </button>
              ) : (
                <button
                  onClick={async (e) => {
                    e.stopPropagation();
                    if (!rootUrl) return;
                    setDismissPending(true);
                    await dismiss(vuln, rootUrl);
                    setDismissPending(false);
                  }}
                  disabled={dismissPending || !rootUrl}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-secondary border border-white/10 text-muted-foreground hover:text-foreground hover:border-white/20 transition-colors disabled:opacity-50"
                >
                  <Flag className="w-3 h-3" />
                  Mark as false positive
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─── Recon card ───────────────────────────────────────────────────────────────

const DANGEROUS_RECON_PORTS = new Set([23, 445, 2375, 6379, 27017, 9200, 1433, 3306, 5432, 3389, 11211, 5984, 1521, 27018]);
const MEDIUM_RECON_PORTS = new Set([2376, 8888, 9000]);

interface ReconData {
  subdomains?: Array<{ subdomain: string; ip?: string | null; cname?: string | null; source: string }>;
  openPorts?: Array<{ port: number; service: string; banner?: string | null }>;
  dnsRecords?: Array<{ type: string; value: string; ttl?: number }>;
  reconDurationMs?: number;
}

function ReconCard({ recon }: { recon: ReconData }) {
  const [section, setSection] = useState<"ports" | "dns" | "subdomains">("ports");

  const portCount = recon.openPorts?.length ?? 0;
  const dnsCount = recon.dnsRecords?.length ?? 0;
  const subCount = recon.subdomains?.length ?? 0;

  if (portCount === 0 && dnsCount === 0 && subCount === 0) return null;

  const tabs = [
    { key: "ports" as const,      label: "Open Ports",  count: portCount,  show: true },
    { key: "dns" as const,        label: "DNS Records", count: dnsCount,   show: dnsCount > 0 },
    { key: "subdomains" as const, label: "Subdomains",  count: subCount,   show: subCount > 0 },
  ].filter((t) => t.show);

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between p-5 border-b border-white/5">
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Network className="w-4 h-4 text-violet-400" />
          Reconnaissance
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 font-medium leading-none">
            red team
          </span>
        </h3>
        {recon.reconDurationMs != null && (
          <span className="text-[10px] text-muted-foreground font-mono">
            {(recon.reconDurationMs / 1000).toFixed(1)}s
          </span>
        )}
      </div>

      {/* Tab nav */}
      <div className="flex border-b border-white/5">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setSection(tab.key)}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2 -mb-px",
              section === tab.key
                ? "border-violet-500 text-violet-400"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
            <span className={cn(
              "px-1.5 py-0.5 rounded-full text-[10px] font-bold",
              section === tab.key ? "bg-violet-500/20 text-violet-400" : "bg-secondary text-muted-foreground",
            )}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>

      <div className="p-4 max-h-72 overflow-y-auto">
        {/* Ports */}
        {section === "ports" && (
          portCount > 0 ? (
            <div className="space-y-1.5">
              {recon.openPorts!.map((p, i) => {
                const isDangerous = DANGEROUS_RECON_PORTS.has(p.port);
                const isMedium = MEDIUM_RECON_PORTS.has(p.port);
                return (
                  <div
                    key={i}
                    className={cn(
                      "flex items-start gap-3 p-2.5 rounded-lg text-xs border",
                      isDangerous ? "bg-red-500/5 border-red-500/20" :
                      isMedium   ? "bg-yellow-500/5 border-yellow-500/20" :
                                   "bg-secondary/40 border-white/5",
                    )}
                  >
                    <span className={cn(
                      "font-mono font-bold shrink-0 min-w-[3rem] text-right tabular-nums",
                      isDangerous ? "text-red-400" : isMedium ? "text-yellow-400" : "text-emerald-400",
                    )}>
                      {p.port}
                    </span>
                    <div className="flex-1 min-w-0">
                      <span className={cn(
                        "font-medium",
                        isDangerous ? "text-red-300" : isMedium ? "text-yellow-300" : "text-foreground/80",
                      )}>
                        {p.service}
                      </span>
                      {p.banner && (
                        <div className="mt-1 font-mono text-[10px] text-muted-foreground truncate" title={p.banner}>
                          {p.banner}
                        </div>
                      )}
                    </div>
                    {isDangerous && (
                      <span className="shrink-0 px-1.5 py-0.5 bg-red-500/15 text-red-400 border border-red-500/25 rounded text-[10px] font-bold leading-none">
                        !
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">
              No open ports detected in the scanned range.
            </div>
          )
        )}

        {/* DNS */}
        {section === "dns" && (
          dnsCount > 0 ? (
            <div className="space-y-0.5">
              {recon.dnsRecords!.map((r, i) => (
                <div key={i} className="flex items-start gap-2 py-1.5 border-b border-white/5 last:border-0 text-xs">
                  <span className="shrink-0 px-1.5 py-0.5 bg-teal-500/10 border border-teal-500/20 text-teal-400 rounded font-mono text-[10px] font-bold min-w-[3rem] text-center leading-none mt-0.5">
                    {r.type}
                  </span>
                  <span className="font-mono text-muted-foreground break-all leading-relaxed">{r.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">No DNS records found.</div>
          )
        )}

        {/* Subdomains */}
        {section === "subdomains" && (
          subCount > 0 ? (
            <div className="space-y-0.5">
              {recon.subdomains!.map((s, i) => (
                <div key={i} className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0 text-xs">
                  <Globe className="w-3 h-3 text-muted-foreground/50 shrink-0" />
                  <span className="font-mono text-foreground/80 truncate flex-1">{s.subdomain}</span>
                  {s.ip && (
                    <span className="font-mono text-muted-foreground text-[10px] shrink-0 tabular-nums">{s.ip}</span>
                  )}
                  <span className={cn(
                    "shrink-0 text-[9px] px-1 py-0.5 rounded font-medium border leading-none",
                    s.source === "crt.sh"
                      ? "bg-sky-500/10 text-sky-400/70 border-sky-500/20"
                      : "bg-secondary text-muted-foreground/50 border-white/5",
                  )}>
                    {s.source}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">No subdomains discovered.</div>
          )
        )}
      </div>
    </div>
  );
}

// ─── Agent Fix Prompt card ────────────────────────────────────────────────────

function AgentFixPromptCard({ prompt }: { prompt: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(prompt).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      // Clipboard API unavailable (insecure context or permission denied) — fail silently
    });
  }, [prompt]);

  return (
    <div className="glass-card rounded-2xl p-6 border-t-4 border-t-violet-500">
      <div className="flex items-start justify-between gap-4 mb-4">
        <h3 className="text-lg font-bold flex items-center gap-2">
          <Terminal className="w-5 h-5 text-violet-400" />
          Fix with your AI agent
        </h3>
        <button
          onClick={handleCopy}
          className={cn(
            "shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-200",
            copied
              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
              : "bg-violet-500/20 text-violet-300 border border-violet-500/30 hover:bg-violet-500/30",
          )}
        >
          {copied ? (
            <><Check className="w-4 h-4" /> Copied!</>
          ) : (
            <><Copy className="w-4 h-4" /> Copy prompt</>
          )}
        </button>
      </div>
      <p className="text-xs text-muted-foreground mb-3">
        Paste this prompt into Cursor, Claude, GitHub Copilot, or any coding agent to get all findings fixed at once.
      </p>
      <div className="bg-background border border-white/10 rounded-lg p-4 max-h-64 overflow-y-auto">
        <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap leading-relaxed">{prompt}</pre>
      </div>
    </div>
  );
}

// ─── Pages Scanned card ───────────────────────────────────────────────────────

function PagesScannedCard({
  rootUrl,
  pagesScanned,
  probedNotFound,
}: {
  rootUrl: string;
  pagesScanned: string[];
  probedNotFound?: string[];
}) {
  const [open, setOpen] = useState(false);

  const allPages = useMemo(() => {
    const pages: { label: string; url: string; isRoot: boolean }[] = [
      { label: rootUrl, url: rootUrl, isRoot: true },
    ];
    for (const url of pagesScanned) {
      try {
        const path = new URL(url).pathname;
        pages.push({ label: path, url, isRoot: false });
      } catch {
        pages.push({ label: url, url, isRoot: false });
      }
    }
    return pages;
  }, [rootUrl, pagesScanned]);

  const notFoundPages = useMemo(() => {
    return (probedNotFound ?? []).map((url) => {
      try { return { label: new URL(url).pathname, url }; }
      catch { return { label: url, url }; }
    });
  }, [probedNotFound]);

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-white/[0.02] transition-colors"
      >
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Search className="w-4 h-4 text-sky-400" />
          Pages Scanned
          <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground">{allPages.length}</span>
          {notFoundPages.length > 0 && (
            <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground/60">
              {notFoundPages.length} not found
            </span>
          )}
        </h3>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 border-t border-white/5 pt-3 space-y-1">
              <p className="text-xs text-muted-foreground mb-3">All URLs visited during this scan, including the root page and crawled inner pages.</p>
              {allPages.map((page, i) => (
                <div key={i} className="flex items-center gap-2 py-1">
                  <Globe className={cn("w-3 h-3 shrink-0", page.isRoot ? "text-sky-400" : "text-muted-foreground/50")} />
                  <a
                    href={page.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-muted-foreground hover:text-foreground transition-colors truncate"
                    title={page.url}
                  >
                    {page.label}
                  </a>
                  {page.isRoot && (
                    <span className="shrink-0 text-[9px] px-1 py-0.5 bg-sky-500/10 text-sky-400/70 border border-sky-500/20 rounded font-medium leading-none">
                      root
                    </span>
                  )}
                </div>
              ))}

              {notFoundPages.length > 0 && (
                <div className="mt-4 pt-3 border-t border-white/5">
                  <p className="text-xs text-muted-foreground/60 mb-2 font-medium">Probed (not found)</p>
                  {notFoundPages.map((page, i) => (
                    <div key={i} className="flex items-center gap-2 py-1">
                      <Minus className="w-3 h-3 shrink-0 text-muted-foreground/30" />
                      <span
                        className="text-xs font-mono text-muted-foreground/40 truncate"
                        title={page.url}
                      >
                        {page.label}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Software Inventory card ──────────────────────────────────────────────────

function SoftwareInventoryCard({
  technologies,
  vulnerabilities,
}: {
  technologies: string[];
  vulnerabilities: Vulnerability[];
}) {
  const versionedTechs = useMemo(() => {
    const seen = new Set<string>();
    return technologies
      .map(parseTechVersion)
      .filter((t) => {
        if (t.version === null) return false;
        const key = `${t.name.toLowerCase()}@${t.version.toLowerCase()}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  }, [technologies]);

  // Count CVEs per tech by matching vuln names like "jQuery 1.11.3 — Known Vulnerability ..."
  // or evidence lines like "Detected: jQuery 1.11.3" as a fallback
  const cveCountFor = useCallback(
    (name: string, version: string) => {
      const namePrefix = `${name.toLowerCase()} ${version.toLowerCase()} \u2014`; // em dash separator
      const evidenceTag = `detected: ${name.toLowerCase()} ${version.toLowerCase()}`;
      return vulnerabilities.filter((v) =>
        v.name.toLowerCase().startsWith(namePrefix) ||
        (v.evidence?.toLowerCase().includes(evidenceTag) ?? false)
      ).length;
    },
    [vulnerabilities],
  );

  const cveTotal = useMemo(
    () => versionedTechs.reduce((sum, t) => sum + cveCountFor(t.name, t.version!), 0),
    [versionedTechs, cveCountFor],
  );

  const [open, setOpen] = useState(() => cveTotal > 0);

  if (versionedTechs.length === 0) return null;

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 hover:bg-white/[0.02] transition-colors"
      >
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Package className="w-4 h-4 text-yellow-400" />
          Software Inventory
          <span className="px-1.5 py-0.5 bg-secondary text-xs rounded-full text-muted-foreground">{versionedTechs.length}</span>
          {cveTotal > 0 && (
            <span className="flex items-center gap-1 text-[11px] font-semibold text-red-400 bg-red-950/60 px-2 py-0.5 rounded-full border border-red-500/25 leading-none">
              <AlertTriangle className="w-3 h-3" />
              {cveTotal} CVE{cveTotal !== 1 ? "s" : ""}
            </span>
          )}
        </h3>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform", open && "rotate-180")} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-5 space-y-2 border-t border-white/5 pt-3">
              <p className="text-xs text-muted-foreground mb-3">Versioned components found during the scan that were checked for known CVEs.</p>
              {versionedTechs.map((t, i) => {
                const cveCount = cveCountFor(t.name, t.version!);
                return (
                  <div key={i} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-foreground/90">{t.name}</span>
                      <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] font-mono rounded border border-yellow-500/20 leading-none">
                        {t.version}
                      </span>
                    </div>
                    {cveCount > 0 ? (
                      <span className="flex items-center gap-1 text-xs font-semibold text-red-400 bg-red-950/50 px-2 py-0.5 rounded-full border border-red-500/20">
                        <AlertTriangle className="w-3 h-3" /> {cveCount} CVE{cveCount !== 1 ? "s" : ""}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">No CVEs found</span>
                    )}
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Grouped category section ─────────────────────────────────────────────────

function CategorySection({
  category,
  vulns,
  defaultOpen = true,
  needsVerification = false,
  globalIndex,
  rootUrl,
}: {
  category: string;
  vulns: Vulnerability[];
  defaultOpen?: boolean;
  needsVerification?: boolean;
  globalIndex: number;
  rootUrl?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = getCategoryMeta(category);

  const highestSeverity = vulns.reduce<string | null>((acc, v) => {
    if (acc === null) return v.severity;
    return (SEVERITY_ORDER[v.severity] ?? 99) < (SEVERITY_ORDER[acc] ?? 99) ? v.severity : acc;
  }, null);

  return (
    <div className="rounded-xl overflow-hidden border border-white/5 bg-secondary/10">
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={`${meta.label} — ${vulns.length} finding${vulns.length !== 1 ? "s" : ""}, ${open ? "collapse" : "expand"}`}
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.03] transition-colors text-left"
      >
        <span className={meta.color}>{meta.icon}</span>
        <span className="font-bold text-sm text-foreground flex-1">{meta.label}</span>
        {highestSeverity && (
          <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border shrink-0", getSeverityColors(highestSeverity))}>
            {highestSeverity}
          </span>
        )}
        <span className="text-xs font-bold bg-secondary rounded-full w-6 h-6 flex items-center justify-center text-muted-foreground shrink-0">
          {vulns.length}
        </span>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform shrink-0", open && "rotate-180")} />
      </button>

      {open && (
        <div className="px-3 pb-3 pt-1 space-y-2 border-t border-white/5">
          {vulns.map((v, i) => (
            <VulnCard
              key={v.id}
              vuln={v}
              index={globalIndex + i}
              needsVerification={needsVerification}
              rootUrl={rootUrl}
            />
          ))}
        </div>
      )}
    </div>
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
  "Session Management":              "JWT / session token weaknesses",
  "Brute Force Protection":          "missing rate limiting",
  "DNS Security":                    "DNS / subdomain takeover risks",
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

// ─── Severity emoji for print / markdown ─────────────────────────────────────

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪",
};

// ─── Print-friendly grade ring ────────────────────────────────────────────────

function PrintGradeRing({ grade, score }: { grade: string; score: number }) {
  const colorMap: Record<string, string> = {
    A: "#059669", B: "#16a34a", C: "#ca8a04", D: "#ea580c", F: "#dc2626",
  };
  const color = colorMap[grade] ?? "#6b7280";
  const r = 52;
  const circumference = 2 * Math.PI * r;
  const dash = circumference * (score / 100);

  return (
    <div style={{ position: "relative", width: 120, height: 120, flexShrink: 0 }}>
      <svg width="120" height="120" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="#e5e7eb" strokeWidth="6" />
        <circle
          cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${dash} ${circumference - dash}`}
          strokeLinecap="round"
        />
      </svg>
      <div style={{
        position: "absolute", inset: 0, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontSize: 36, fontWeight: 900, lineHeight: 1, color }}>{grade}</span>
        <span style={{ fontSize: 10, color: "#6b7280", marginTop: 2 }}>Risk: {score}</span>
      </div>
    </div>
  );
}

// ─── Print-friendly vuln card (used inside PrintableReport) ───────────────────

function PrintVulnCard({ vuln, index }: { vuln: Vulnerability; index: number }) {
  const borderColors: Record<string, string> = {
    critical: "border-red-300 bg-red-50",
    high:     "border-orange-300 bg-orange-50",
    medium:   "border-yellow-300 bg-yellow-50",
    low:      "border-blue-300 bg-blue-50",
    info:     "border-gray-300 bg-gray-50",
  };
  const headerColors: Record<string, string> = {
    critical: "text-red-800",
    high:     "text-orange-800",
    medium:   "text-yellow-800",
    low:      "text-blue-800",
    info:     "text-gray-700",
  };
  const emoji = SEVERITY_EMOJI[vuln.severity] ?? "•";
  const border = borderColors[vuln.severity] ?? "border-gray-300 bg-gray-50";
  const hdr = headerColors[vuln.severity] ?? "text-gray-700";

  return (
    <div className={`border rounded-lg overflow-hidden ${border}`} style={{ pageBreakInside: "avoid" }}>
      <div className={`px-4 py-2.5 flex items-center gap-3 border-b border-current/20 ${border}`}>
        <span className={`font-bold uppercase text-xs tracking-wider ${hdr}`}>{emoji} {vuln.severity}</span>
        <span className="font-semibold text-gray-900 text-sm">{index}. {vuln.name}</span>
        <span className="ml-auto text-xs text-gray-500 shrink-0">{vuln.category}</span>
      </div>
      <div className="px-4 py-3 bg-white space-y-3">
        <div>
          <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">Description</p>
          <p className="text-gray-800 text-sm leading-relaxed">{vuln.description}</p>
        </div>
        {vuln.evidence && (
          <div>
            <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">Evidence</p>
            <pre className="text-xs bg-gray-50 border border-gray-200 rounded p-2 whitespace-pre-wrap text-gray-600 font-mono">{vuln.evidence}</pre>
          </div>
        )}
        <div>
          <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">How to Fix</p>
          <div className="bg-emerald-50 border border-emerald-200 rounded p-3 text-sm text-gray-800 whitespace-pre-wrap">{vuln.solution}</div>
        </div>
        {(vuln.cweId || vuln.cvssScore != null || vuln.wstgId) && (
          <div className="flex gap-2 flex-wrap">
            {vuln.cweId && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">{vuln.cweId}</span>}
            {vuln.cvssScore != null && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">CVSS {vuln.cvssScore.toFixed(1)}</span>}
            {vuln.wstgId && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">{vuln.wstgId}</span>}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Full printable report (screen: hidden; print: visible) ───────────────────

function PrintableReport({
  targetUrl, scannedAt, summary, confirmedVulns, unverifiedVulns,
  technologies, server, tlsGrade, aiAnalysis, categoryCounts, pagesScanned,
}: {
  targetUrl: string;
  scannedAt: string | Date;
  summary: { grade: string; riskScore: number; executiveSummary: string; critical: number; high: number; medium: number; low: number; info: number; totalVulnerabilities: number };
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null } | null;
  categoryCounts: Record<string, number>;
  pagesScanned?: string[];
}) {
  const dateStr = new Date(scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const sortedCategories = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="text-gray-900 bg-white font-sans text-sm leading-relaxed max-w-4xl mx-auto py-4">
      {/* Cover */}
      <div className="mb-8 pb-6 border-b-2 border-gray-300">
        <div className="flex items-start gap-6 mb-4">
          <PrintGradeRing grade={summary.grade} score={summary.riskScore} />
          <div className="flex-1 pt-2">
            <h1 className="text-2xl font-bold text-gray-900 mb-1">Security Report</h1>
            <p className="text-gray-500 text-sm mb-3">{targetUrl}</p>
            <div className="flex flex-wrap gap-6 text-sm text-gray-600">
              <span><strong>Total Findings:</strong> {summary.totalVulnerabilities}</span>
              <span><strong>Scanned:</strong> {dateStr}</span>
              {tlsGrade && <span><strong>TLS Grade:</strong> {tlsGrade}</span>}
            </div>
          </div>
        </div>
      </div>

      {/* Severity summary */}
      <div className="mb-6 flex gap-3 flex-wrap">
        {summary.critical > 0 && <span className="px-3 py-1 bg-red-100 text-red-800 rounded text-sm font-medium border border-red-200">🔴 Critical: {summary.critical}</span>}
        {summary.high > 0 && <span className="px-3 py-1 bg-orange-100 text-orange-800 rounded text-sm font-medium border border-orange-200">🟠 High: {summary.high}</span>}
        {summary.medium > 0 && <span className="px-3 py-1 bg-yellow-100 text-yellow-800 rounded text-sm font-medium border border-yellow-200">🟡 Medium: {summary.medium}</span>}
        {summary.low > 0 && <span className="px-3 py-1 bg-blue-100 text-blue-800 rounded text-sm font-medium border border-blue-200">🔵 Low: {summary.low}</span>}
        {summary.info > 0 && <span className="px-3 py-1 bg-gray-100 text-gray-700 rounded text-sm font-medium border border-gray-200">⚪ Info: {summary.info}</span>}
      </div>

      {/* Category breakdown */}
      {sortedCategories.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-bold mb-3 text-gray-900">📋 Finding Categories</h2>
          <div className="grid grid-cols-2 gap-2">
            {sortedCategories.map(([cat, count]) => (
              <div key={cat} className="flex items-center justify-between px-3 py-2 bg-gray-50 border border-gray-200 rounded">
                <span className="text-sm text-gray-700">{getCategoryMeta(cat).label}</span>
                <span className="text-xs font-bold text-gray-500 bg-gray-200 px-2 py-0.5 rounded-full">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Executive Summary */}
      <div className="mb-8">
        <h2 className="text-lg font-bold mb-2 text-gray-900">Executive Summary</h2>
        <p className="text-gray-700 leading-relaxed">{summary.executiveSummary}</p>
      </div>

      {/* Pages Scanned */}
      {((): React.ReactNode => {
        const allPages = [targetUrl, ...Array.from(new Set(pagesScanned ?? []))];
        return (
          <div className="mb-8 pt-6 border-t-2 border-gray-200">
            <h2 className="text-lg font-bold mb-3 text-gray-900">🔍 Pages Scanned ({allPages.length})</h2>
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              {allPages.map((url, i) => (
                <div
                  key={i}
                  className={`px-3 py-2 font-mono text-xs text-gray-700 break-all ${i % 2 === 0 ? "bg-white" : "bg-gray-50"} border-b border-gray-100 last:border-b-0`}
                >
                  {url}
                  {i === 0 && <span className="ml-2 text-gray-400 font-sans not-italic">(root)</span>}
                </div>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Confirmed Findings */}
      {confirmedVulns.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-bold mb-4 text-emerald-700">✅ Confirmed Findings ({confirmedVulns.length})</h2>
          <div className="space-y-4">
            {confirmedVulns.map((v, i) => <PrintVulnCard key={v.id} vuln={v} index={i + 1} />)}
          </div>
        </div>
      )}

      {/* Needs Verification */}
      {unverifiedVulns.length > 0 && (
        <div className="mb-8 mt-8 pt-6 border-t-2 border-gray-200">
          <h2 className="text-lg font-bold mb-2 text-amber-700">⚠️ Needs Verification ({unverifiedVulns.length})</h2>
          <p className="text-sm text-gray-500 mb-4">These findings were detected using heuristics. Verify manually before prioritising remediation.</p>
          <div className="space-y-4">
            {unverifiedVulns.map((v, i) => <PrintVulnCard key={v.id} vuln={v} index={i + 1} />)}
          </div>
        </div>
      )}

      {/* AI Analysis */}
      {aiAnalysis && (
        <div className="mb-8 mt-8 pt-6 border-t-2 border-gray-200">
          <h2 className="text-lg font-bold mb-4 text-gray-900">🤖 AI Analysis</h2>
          <div className="space-y-4">
            <div>
              <h3 className="font-semibold text-gray-800 mb-1">Overall Risk</h3>
              <p className="text-gray-700">{aiAnalysis.overallRisk}</p>
            </div>
            {(aiAnalysis.topPriorities?.length ?? 0) > 0 && (
              <div>
                <h3 className="font-semibold text-gray-800 mb-2">Top Priorities</h3>
                <ol className="list-decimal list-inside space-y-1">
                  {aiAnalysis.topPriorities.map((p, i) => <li key={i} className="text-gray-700">{p}</li>)}
                </ol>
              </div>
            )}
            {(aiAnalysis.quickWins?.length ?? 0) > 0 && (
              <div>
                <h3 className="font-semibold text-gray-800 mb-2">Quick Wins</h3>
                <ul className="space-y-1">
                  {aiAnalysis.quickWins.map((w, i) => <li key={i} className="text-gray-700">✓ {w}</li>)}
                </ul>
              </div>
            )}
            {aiAnalysis.complianceNotes && (
              <div>
                <h3 className="font-semibold text-gray-800 mb-1">Compliance Notes</h3>
                <p className="text-gray-700">{aiAnalysis.complianceNotes}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tech Profile */}
      <div className="mb-6 mt-8 pt-6 border-t-2 border-gray-200">
        <h2 className="text-lg font-bold mb-3 text-gray-900">🖥️ Tech Profile</h2>
        {tlsGrade && <p className="text-gray-700 mb-1"><strong>TLS Grade:</strong> {tlsGrade}</p>}
        {server && <p className="text-gray-700 mb-1"><strong>Server:</strong> {server}</p>}
        {technologies.length > 0 && <p className="text-gray-700"><strong>Technologies:</strong> {technologies.join(", ")}</p>}
      </div>

      {/* Footer */}
      <div className="pt-4 border-t border-gray-200 text-center text-xs text-gray-400 mt-8">
        Generated by VibeScan — https://vibescan.app &nbsp;|&nbsp; {dateStr}
      </div>
    </div>
  );
}

// ─── Download PDF button (jspdf + html2canvas) ───────────────────────────────

export interface PrintableReportData {
  targetUrl: string;
  scannedAt: string | Date;
  summary: {
    grade: string;
    riskScore: number;
    executiveSummary: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    totalVulnerabilities: number;
  };
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null } | null;
  categoryCounts: Record<string, number>;
  pagesScanned?: string[];
}

function DownloadPDFButton({ data }: { data: PrintableReportData }) {
  const [generating, setGenerating] = useState(false);
  const [showOffscreen, setShowOffscreen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleDownload = async () => {
    if (generating) return;
    setGenerating(true);
    setShowOffscreen(true);
    // Wait for React to render the off-screen PrintableReport
    await new Promise<void>((r) => setTimeout(r, 300));

    try {
      const container = containerRef.current;
      if (!container) return;

      const [{ default: html2canvas }, { jsPDF }] = await Promise.all([
        import("html2canvas"),
        import("jspdf"),
      ]);

      const canvas = await html2canvas(container, {
        scale: 1.5,
        useCORS: true,
        logging: false,
        backgroundColor: "#ffffff",
        windowWidth: container.scrollWidth,
        windowHeight: container.scrollHeight,
      });

      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const pageW = pdf.internal.pageSize.getWidth();
      const pageH = pdf.internal.pageSize.getHeight();
      const imgHeightMm = (canvas.height / canvas.width) * pageW;

      let heightLeft = imgHeightMm;
      let yOffset = 0;

      pdf.addImage(imgData, "PNG", 0, yOffset, pageW, imgHeightMm);
      heightLeft -= pageH;

      while (heightLeft > 0) {
        yOffset -= pageH;
        pdf.addPage();
        pdf.addImage(imgData, "PNG", 0, yOffset, pageW, imgHeightMm);
        heightLeft -= pageH;
      }

      let filename = "vibescan-report.pdf";
      try {
        const host = new URL(data.targetUrl).hostname.replace(/^www\./, "");
        filename = `vibescan-${host}.pdf`;
      } catch {
        // keep default
      }
      pdf.save(filename);
    } finally {
      setShowOffscreen(false);
      setGenerating(false);
    }
  };

  return (
    <>
      {/* Off-screen container for PDF capture — visible to html2canvas but off-viewport */}
      {showOffscreen && (
        <div
          ref={containerRef}
          style={{
            position: "fixed",
            left: "-9999px",
            top: 0,
            width: "794px",
            backgroundColor: "#ffffff",
            zIndex: -1,
            pointerEvents: "none",
          }}
        >
          <PrintableReport {...data} />
        </div>
      )}

      <button
        onClick={() => void handleDownload()}
        disabled={generating}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors disabled:opacity-60"
      >
        {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
        {generating ? "Generating…" : "Download PDF"}
      </button>
    </>
  );
}

// ─── Copy report as markdown (for AI agents / no-code tools) ─────────────────

interface ReportCopyData {
  targetUrl: string;
  scannedAt: string | Date;
  summary: { grade: string; riskScore: number; executiveSummary: string; critical: number; high: number; medium: number; low: number; info: number; totalVulnerabilities: number };
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null } | null;
}

function formatReportMarkdown(d: ReportCopyData): string {
  const dateStr = new Date(d.scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const fmtVuln = (v: Vulnerability, i: number) => {
    const emoji = SEVERITY_EMOJI[v.severity] ?? "•";
    const refs = [v.cweId, v.cvssScore != null ? `CVSS ${v.cvssScore.toFixed(1)}` : null, v.wstgId].filter(Boolean).join(" | ");
    return [
      `#### ${emoji} ${v.severity.toUpperCase()} — ${v.name}`,
      `**Category:** ${v.category}`,
      ``,
      `**Description:** ${v.description}`,
      ``,
      v.evidence ? `**Evidence:**\n\`\`\`\n${v.evidence}\n\`\`\`` : null,
      `**How to Fix:** ${v.solution}`,
      refs ? `\n**References:** ${refs}` : null,
      `\n---`,
    ].filter((l) => l !== null).join("\n");
  };

  const lines: string[] = [
    `# VibeScan Security Report`,
    ``,
    `**Target:** ${d.targetUrl}`,
    `**Scanned:** ${dateStr}`,
    `**Security Grade:** ${d.summary.grade} | Risk Score: ${d.summary.riskScore}/100`,
    `**Total Findings:** ${d.summary.totalVulnerabilities}  (${d.summary.critical} critical · ${d.summary.high} high · ${d.summary.medium} medium · ${d.summary.low} low · ${d.summary.info} info)`,
    ``,
    `## Executive Summary`,
    ``,
    d.summary.executiveSummary,
    ``,
  ];

  if (d.confirmedVulns.length > 0) {
    lines.push(`## ✅ Confirmed Findings (${d.confirmedVulns.length})`, ``);
    d.confirmedVulns.forEach((v, i) => { lines.push(fmtVuln(v, i + 1), ``); });
  }

  if (d.unverifiedVulns.length > 0) {
    lines.push(`## ⚠️ Needs Verification (${d.unverifiedVulns.length})`, ``);
    lines.push(`> These findings used heuristic detection — verify manually before acting.`, ``);
    d.unverifiedVulns.forEach((v, i) => { lines.push(fmtVuln(v, i + 1), ``); });
  }

  if (d.aiAnalysis) {
    lines.push(`## 🤖 AI Analysis`, ``);
    lines.push(`### Overall Risk`, ``, d.aiAnalysis.overallRisk, ``);
    if (d.aiAnalysis.topPriorities?.length) {
      lines.push(`### Top Priorities`, ``);
      d.aiAnalysis.topPriorities.forEach((p, i) => lines.push(`${i + 1}. ${p}`));
      lines.push(``);
    }
    if (d.aiAnalysis.quickWins?.length) {
      lines.push(`### Quick Wins`, ``);
      d.aiAnalysis.quickWins.forEach((w) => lines.push(`- ✓ ${w}`));
      lines.push(``);
    }
    if (d.aiAnalysis.complianceNotes) {
      lines.push(`### Compliance Notes`, ``, d.aiAnalysis.complianceNotes, ``);
    }
  }

  lines.push(`## 🖥️ Tech Profile`, ``);
  if (d.tlsGrade) lines.push(`- **TLS Grade:** ${d.tlsGrade}`);
  if (d.server) lines.push(`- **Server:** ${d.server}`);
  if (d.technologies.length) lines.push(`- **Technologies:** ${d.technologies.join(", ")}`);
  lines.push(``, `---`, `*Generated by VibeScan — https://vibescan.app*`);

  return lines.join("\n");
}

function CopyReportButton({ data }: { data: ReportCopyData }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const text = formatReportMarkdown(data);
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      prompt("Copy this report (Ctrl+A, Ctrl+C):", text);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary/10 border border-primary/30 text-sm font-medium text-primary hover:bg-primary/20 transition-colors"
      title="Copy the full report as markdown — paste into ChatGPT, Claude, Cursor, Lovable, or any AI tool to get tailored fix recommendations"
    >
      {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      {copied ? "Copied!" : "Copy for AI"}
    </button>
  );
}

// ─── Share dialog ─────────────────────────────────────────────────────────────

interface ShareLink {
  id: string;
  token: string;
  expiresAt: string | null;
  createdAt: string;
  revokedAt: string | null;
}

function ShareButton({ reportId }: { reportId: string }) {
  const [open, setOpen] = useState(false);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<"7d" | "30d" | "never">("never");
  const queryClient = useQueryClient();

  const { data: shares = [], isLoading: loadingShares } = useListReportShares(reportId, {
    query: {
      queryKey: getListReportSharesQueryKey(reportId),
      enabled: open,
    },
  });

  const { mutate: createShare, isPending: creating } = useCreateReportShare({
    mutation: {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: getListReportSharesQueryKey(reportId) });
      },
    },
  });

  const { mutate: revokeShare, isPending: revoking } = useRevokeReportShare({
    mutation: {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: getListReportSharesQueryKey(reportId) });
      },
    },
  });

  const copyLink = async (token: string) => {
    const url = `${window.location.origin}/share/${token}`;
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      prompt("Copy this link:", url);
    }
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2000);
  };

  const handleCreate = () => {
    createShare({ id: reportId, data: { expiresIn } });
  };

  const handleRevoke = (token: string) => {
    revokeShare({ id: reportId, token });
  };

  const activeShares = (shares as ShareLink[]).filter((s) => !s.revokedAt);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors"
      >
        <Share2 className="w-4 h-4" />
        Share Report
      </button>

      {/* Dialog overlay */}
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}
        >
          <div
            className="relative w-full max-w-md bg-background border border-white/10 rounded-2xl shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between p-5 border-b border-white/5">
              <div className="flex items-center gap-2">
                <Share2 className="w-4 h-4 text-primary" />
                <h2 className="font-bold text-base">Share Report</h2>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="p-1.5 hover:bg-white/5 rounded-lg transition-colors"
              >
                <X className="w-4 h-4 text-muted-foreground" />
              </button>
            </div>

            {/* Body */}
            <div className="p-5 space-y-5">
              <p className="text-sm text-muted-foreground">
                Share links let anyone view this report without logging in. You can revoke them at any time.
              </p>

              {/* Create new link */}
              <div className="space-y-3">
                <label className="block text-xs font-bold text-muted-foreground uppercase tracking-wider">
                  Create New Link
                </label>
                <div className="flex gap-2">
                  <select
                    value={expiresIn}
                    onChange={(e) => setExpiresIn(e.target.value as "7d" | "30d" | "never")}
                    className="flex-1 px-3 py-2 rounded-lg bg-secondary border border-white/10 text-sm text-foreground focus:outline-none focus:border-primary/50"
                  >
                    <option value="never">Never expires</option>
                    <option value="7d">Expires in 7 days</option>
                    <option value="30d">Expires in 30 days</option>
                  </select>
                  <button
                    onClick={handleCreate}
                    disabled={creating}
                    className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-semibold hover:opacity-90 disabled:opacity-60 transition-all flex items-center gap-2 shrink-0"
                  >
                    {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    Create
                  </button>
                </div>
              </div>

              {/* Existing links */}
              <div className="space-y-2">
                <label className="block text-xs font-bold text-muted-foreground uppercase tracking-wider">
                  Active Links {activeShares.length > 0 && `(${activeShares.length})`}
                </label>

                {loadingShares ? (
                  <div className="py-4 flex justify-center">
                    <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                  </div>
                ) : activeShares.length === 0 ? (
                  <div className="py-4 text-center text-sm text-muted-foreground border border-dashed border-white/10 rounded-xl">
                    No active share links yet.
                  </div>
                ) : (
                  <div className="space-y-2 max-h-52 overflow-y-auto">
                    {activeShares.map((share) => {
                      const shortToken = share.token.slice(0, 12) + "…";
                      const expires = share.expiresAt
                        ? new Date(share.expiresAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
                        : "Never";
                      const isExpired = share.expiresAt ? new Date(share.expiresAt) < new Date() : false;

                      return (
                        <div
                          key={share.id}
                          className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-secondary/50 border border-white/5"
                        >
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-mono text-foreground/70 truncate">{shortToken}</p>
                            <p className={cn(
                              "text-[10px] mt-0.5",
                              isExpired ? "text-red-400" : "text-muted-foreground/60",
                            )}>
                              {isExpired ? "Expired" : `Expires: ${expires}`}
                            </p>
                          </div>
                          <button
                            onClick={() => void copyLink(share.token)}
                            title="Copy link"
                            className={cn(
                              "shrink-0 p-1.5 rounded-lg transition-all",
                              copiedToken === share.token
                                ? "bg-emerald-500/20 text-emerald-400"
                                : "hover:bg-white/10 text-muted-foreground hover:text-foreground",
                            )}
                          >
                            {copiedToken === share.token ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                          <button
                            onClick={() => handleRevoke(share.token)}
                            disabled={revoking}
                            title="Revoke link"
                            className="shrink-0 p-1.5 rounded-lg hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-all"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Footer note */}
            <div className="px-5 pb-4 text-xs text-muted-foreground/50">
              Recipients can view the report and download a PDF — they cannot modify findings or access your account.
            </div>
          </div>
        </div>
      )}
    </>
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
  const [viewMode, setViewMode] = useState<"grouped" | "flat">("grouped");

  const [dismissedFps, setDismissedFps] = useState<Set<string>>(new Set());
  const [vulnFpMap, setVulnFpMap] = useState<Map<string, string>>(new Map());
  const [optimisticDismissKeys, setOptimisticDismissKeys] = useState<Set<string>>(new Set());
  const [undoToast, setUndoToast] = useState<{ key: string; vuln: Vulnerability } | null>(null);
  const undoToastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!report?.targetUrl) return;
    fetch(`/api/dismissals?targetUrl=${encodeURIComponent(report.targetUrl)}`)
      .then((r) => (r.ok ? r.json() : []))
      .then((items: DismissalEntry[]) => {
        const fpSet = new Set<string>();
        for (const item of items) fpSet.add(item.fingerprint);
        setDismissedFps(fpSet);
      })
      .catch(() => {});
  }, [report?.targetUrl]);

  const dismissFinding = useCallback(async (vuln: Vulnerability, targetUrl: string) => {
    const vKey = vulnUniqueKey(vuln);

    // Optimistic hide via per-vuln unique key (stays until server fingerprint arrives)
    setOptimisticDismissKeys((prev) => new Set([...prev, vKey]));

    // Show external undo toast (per-card button is gone once the card is hidden)
    if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
    setUndoToast({ key: vKey, vuln });
    undoToastTimerRef.current = setTimeout(() => setUndoToast(null), 5000);

    try {
      const res = await fetch("/api/dismissals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetUrl,
          findingName: vuln.name,
          findingCategory: vuln.category,
          findingEvidence: vuln.evidence ?? undefined,
          reason: "false_positive",
        }),
      });
      if (!res.ok) {
        setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
        if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
        setUndoToast(null);
        return;
      }
      const { fingerprint } = (await res.json()) as { fingerprint: string };
      // Promote from optimistic key to confirmed fingerprint
      setVulnFpMap((prev) => new Map([...prev, [vKey, fingerprint]]));
      setDismissedFps((prev) => new Set([...prev, fingerprint]));
      setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
    } catch {
      setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
      if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
      setUndoToast(null);
    }
  }, []);

  const undismissFinding = useCallback(async (vuln: Vulnerability) => {
    const vKey = vulnUniqueKey(vuln);
    const fp = vulnFpMap.get(vKey);
    const tUrl = report?.targetUrl;
    // Optimistically show the finding again
    setDismissedFps((prev) => { const n = new Set(prev); if (fp) n.delete(fp); return n; });
    setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
    if (fp && tUrl) {
      try {
        const res = await fetch(
          `/api/dismissals/${fp}?targetUrl=${encodeURIComponent(tUrl)}`,
          { method: "DELETE" },
        );
        if (!res.ok) {
          setDismissedFps((prev) => new Set([...prev, fp]));
          return;
        }
        setVulnFpMap((prev) => { const n = new Map(prev); n.delete(vKey); return n; });
      } catch {
        setDismissedFps((prev) => new Set([...prev, fp]));
      }
    }
  }, [vulnFpMap, report?.targetUrl]);

  const vulnerabilities = report?.data?.vulnerabilities ?? [];
  const summary = report?.data?.summary;

  // Pre-compute per-vuln fingerprints using the same SHA-256 algorithm as the server.
  // Runs as a fast async batch whenever the vulnerability list changes.
  useEffect(() => {
    if (!vulnerabilities.length) return;
    let cancelled = false;
    Promise.all(
      vulnerabilities.map((v) =>
        computeVulnFp(v.category, v.name, v.evidence).then(
          (fp) => [vulnUniqueKey(v), fp] as [string, string],
        ),
      ),
    ).then((pairs) => {
      if (!cancelled) setVulnFpMap((prev) => {
        const next = new Map(prev);
        for (const [k, fp] of pairs) next.set(k, fp);
        return next;
      });
    });
    return () => { cancelled = true; };
  }, [vulnerabilities]);

  // All hooks must come before any early returns
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

  const visibleVulns = useMemo(
    () => sortedVulns.filter((v) => {
      const vKey = vulnUniqueKey(v);
      if (optimisticDismissKeys.has(vKey)) return false;
      const fp = vulnFpMap.get(vKey);
      return !fp || !dismissedFps.has(fp);
    }),
    [sortedVulns, dismissedFps, vulnFpMap, optimisticDismissKeys],
  );

  const dismissedCount = sortedVulns.length - visibleVulns.length;

  const filteredVulns = useMemo(
    () => activeCategory ? visibleVulns.filter((v) => v.category === activeCategory) : visibleVulns,
    [visibleVulns, activeCategory],
  );

  // Split into confirmed (confidence ≥ threshold) vs. needs verification
  const confirmedVulns = useMemo(
    () => filteredVulns.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD),
    [filteredVulns],
  );
  const unverifiedVulns = useMemo(
    () => filteredVulns.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD),
    [filteredVulns],
  );

  // Grouped confirmed/unverified vulns by category (for grouped view)
  const groupedConfirmedVulns = useMemo(() => {
    const groups: Map<string, Vulnerability[]> = new Map();
    for (const v of confirmedVulns) {
      if (!groups.has(v.category)) groups.set(v.category, []);
      groups.get(v.category)!.push(v);
    }
    return groups;
  }, [confirmedVulns]);

  const groupedUnverifiedVulns = useMemo(() => {
    const groups: Map<string, Vulnerability[]> = new Map();
    for (const v of unverifiedVulns) {
      if (!groups.has(v.category)) groups.set(v.category, []);
      groups.get(v.category)!.push(v);
    }
    return groups;
  }, [unverifiedVulns]);

  // Unfiltered splits — used for PDF/copy so nothing is omitted when a category filter is active
  const allConfirmedVulns = useMemo(
    () => visibleVulns.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD),
    [visibleVulns],
  );
  const allUnverifiedVulns = useMemo(
    () => visibleVulns.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD),
    [visibleVulns],
  );

  // Per-severity counts split by confidence — used for the header badges
  const confirmedSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of allConfirmedVulns) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    return counts;
  }, [allConfirmedVulns]);

  const unverifiedSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of allUnverifiedVulns) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    return counts;
  }, [allUnverifiedVulns]);

  if (isLoading) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading report…</p>
      </div>
    );
  }
  if (error || !report || !summary) return <div className="min-h-[80vh] flex items-center justify-center text-red-400">Failed to load report.</div>;

  const { data: { technologies, server, tlsGrade, aiAnalysis, pagesScanned, probedNotFound, recon } } = report;

  const severityCounts = {
    critical: summary.critical,
    high: summary.high,
    medium: summary.medium,
    low: summary.low,
    info: summary.info,
  };

  const copyData: ReportCopyData = {
    targetUrl: report.targetUrl,
    scannedAt: report.scannedAt,
    summary: {
      grade: summary.grade,
      riskScore: summary.riskScore,
      executiveSummary: summary.executiveSummary,
      critical: summary.critical,
      high: summary.high,
      medium: summary.medium,
      low: summary.low,
      info: summary.info,
      totalVulnerabilities: summary.totalVulnerabilities,
    },
    confirmedVulns: allConfirmedVulns,
    unverifiedVulns: allUnverifiedVulns,
    technologies: technologies ?? [],
    server: server ?? null,
    tlsGrade: tlsGrade ?? null,
    aiAnalysis: aiAnalysis ?? null,
  };

  return (
    <DismissalsContext.Provider
      value={{
        dismissedFps,
        vulnFpMap,
        optimisticDismissKeys,
        dismiss: dismissFinding,
        undismiss: undismissFinding,
      }}
    >
    <>
      {/* Print-only view — hidden on screen, shown only when printing */}
      <div className="hidden print:block">
        <PrintableReport
          targetUrl={report.targetUrl}
          scannedAt={report.scannedAt}
          summary={copyData.summary}
          confirmedVulns={allConfirmedVulns}
          unverifiedVulns={allUnverifiedVulns}
          technologies={technologies ?? []}
          server={server}
          tlsGrade={tlsGrade}
          aiAnalysis={aiAnalysis}
          categoryCounts={categoryCounts}
          pagesScanned={pagesScanned ?? []}
        />
      </div>

      {/* Interactive screen view — hidden when printing */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-20 print:hidden">
      <div className="mb-8 flex items-center justify-between">
        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
        <div className="flex items-center gap-2">
          <CopyReportButton data={copyData} />
          <DownloadPDFButton data={{
            targetUrl: report.targetUrl,
            scannedAt: report.scannedAt,
            summary: copyData.summary,
            confirmedVulns: allConfirmedVulns,
            unverifiedVulns: allUnverifiedVulns,
            technologies: technologies ?? [],
            server: server ?? null,
            tlsGrade: tlsGrade ?? null,
            aiAnalysis: aiAnalysis ?? null,
            categoryCounts,
            pagesScanned: pagesScanned ?? [],
          }} />
          <ShareButton reportId={reportId} />
        </div>
      </div>

      {/* Header / Cover */}
      <div className="glass-panel p-8 md:p-12 rounded-3xl mb-12 relative overflow-hidden flex flex-col md:flex-row items-center gap-12">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] pointer-events-none" />

        <GradeRing grade={summary.grade} score={summary.riskScore} />

        <div className="flex-1 text-center md:text-left z-10">
          <div className="flex flex-wrap items-center gap-2 mb-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary border border-white/5 text-xs font-medium text-muted-foreground">
              <Globe className="w-3.5 h-3.5" /> {report.targetUrl}
            </div>
            {pagesScanned != null && (
              <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-500/10 border border-sky-500/20 text-xs font-medium text-sky-400/80">
                <Search className="w-3 h-3" />
                Scanned {pagesScanned.length + 1} page{pagesScanned.length + 1 !== 1 ? "s" : ""}
              </div>
            )}
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4">Security Report</h1>
          <p className="text-lg text-muted-foreground/80 leading-relaxed max-w-2xl">
            {summary.executiveSummary}
          </p>
          <SummaryNewFindings categories={categoryCounts} />
          {allUnverifiedVulns.length > 0 && (
            <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/25 text-xs text-amber-300">
              <HelpCircle className="w-3.5 h-3.5 shrink-0" />
              Grade includes {allUnverifiedVulns.length} heuristic finding{allUnverifiedVulns.length !== 1 ? "s" : ""} — see "Needs Verification" below before acting
            </div>
          )}
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
                {activeCategory ? `${filteredVulns.length} / ${visibleVulns.length}` : visibleVulns.length}
              </span>
              {dismissedCount > 0 && (
                <span className="text-xs font-normal text-muted-foreground">
                  ({dismissedCount} dismissed as false positive{dismissedCount !== 1 ? "s" : ""})
                </span>
              )}
              {(report?.data as { autoSuppressedCount?: number } | undefined)?.autoSuppressedCount && (
                <span className="text-xs font-normal text-muted-foreground">
                  ({(report.data as { autoSuppressedCount?: number }).autoSuppressedCount} previously dismissed, hidden)
                </span>
              )}
            </h2>
          </div>

          {/* Severity badges — split confirmed vs unverified */}
          <div className="flex flex-wrap gap-3">
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
              const confirmed = confirmedSeverityCounts[sev] ?? 0;
              const unverified = unverifiedSeverityCounts[sev] ?? 0;
              if (confirmed + unverified === 0) return null;
              return (
                <div key={sev} className={cn("px-4 py-2 rounded-lg border flex items-center gap-2.5", getSeverityColors(sev))}>
                  <span className="font-bold uppercase text-xs tracking-wider">{sev}</span>
                  <span className="w-6 h-6 rounded bg-black/20 flex items-center justify-center text-sm font-bold">{confirmed + unverified}</span>
                  {unverified > 0 && (
                    <span className="text-xs text-amber-300/80 font-medium border-l border-current/20 pl-2.5">
                      {confirmed} confirmed
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Sort + View mode toggles */}
          <div className="flex items-center gap-4 flex-wrap">
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
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wider font-medium">View</span>
              <div className="flex rounded-lg overflow-hidden border border-white/10">
                {(["grouped", "flat"] as const).map((opt) => (
                  <button
                    key={opt}
                    onClick={() => setViewMode(opt)}
                    className={cn(
                      "px-3 py-1.5 text-xs font-medium capitalize transition-colors",
                      viewMode === opt
                        ? "bg-primary/20 text-primary"
                        : "text-muted-foreground hover:text-foreground hover:bg-white/5",
                    )}
                  >
                    {opt}
                  </button>
                ))}
              </div>
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

          {/* Accuracy bar */}
          {filteredVulns.length > 0 && (
            <div className="flex items-center gap-4 p-3 rounded-xl bg-secondary/40 border border-white/5 text-xs">
              <div className="flex items-center gap-1.5 text-emerald-400 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{confirmedVulns.length} confirmed</span>
              </div>
              {unverifiedVulns.length > 0 && (
                <>
                  <div className="w-px h-4 bg-white/10" />
                  <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>{unverifiedVulns.length} need{unverifiedVulns.length === 1 ? "s" : ""} verification</span>
                  </div>
                </>
              )}
              <div className="ml-auto text-muted-foreground">
                {filteredVulns.length === 0 ? "–" : `${Math.round((confirmedVulns.length / filteredVulns.length) * 100)}% high-confidence`}
              </div>
            </div>
          )}

          {/* Confirmed findings */}
          {confirmedVulns.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-sm font-bold text-emerald-400">Confirmed findings</span>
                <span className="ml-auto text-xs text-emerald-400/60 font-medium">{confirmedVulns.length} finding{confirmedVulns.length !== 1 ? "s" : ""} — high confidence, act on these</span>
              </div>
              {viewMode === "grouped" ? (
                <div className="space-y-2">
                  {Array.from(groupedConfirmedVulns.entries()).map(([cat, vulns]) => {
                    const priorCount = Array.from(groupedConfirmedVulns.entries())
                      .filter(([c]) => c < cat)
                      .reduce((sum, [, vs]) => sum + vs.length, 0);
                    return (
                      <CategorySection
                        key={cat}
                        category={cat}
                        vulns={vulns}
                        globalIndex={priorCount}
                        defaultOpen
                        rootUrl={report.targetUrl}
                      />
                    );
                  })}
                </div>
              ) : (
                <AnimatePresence mode="popLayout">
                  {confirmedVulns.map((v, i) => (
                    <VulnCard key={v.id} vuln={v} index={i} rootUrl={report.targetUrl} />
                  ))}
                </AnimatePresence>
              )}
            </div>
          )}

          {/* Needs verification */}
          {unverifiedVulns.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-amber-500/8 border border-amber-500/20">
                <HelpCircle className="w-4 h-4 text-amber-400 shrink-0" />
                <div className="min-w-0">
                  <span className="text-sm font-bold text-amber-400">Needs verification</span>
                  <span className="text-xs text-amber-400/60 ml-2 font-medium hidden sm:inline">— heuristic detections, confirm manually before acting</span>
                </div>
                <span className="ml-auto text-xs text-amber-400/60 font-medium shrink-0">{unverifiedVulns.length} finding{unverifiedVulns.length !== 1 ? "s" : ""}</span>
              </div>
              {viewMode === "grouped" ? (
                <div className="space-y-2">
                  {Array.from(groupedUnverifiedVulns.entries()).map(([cat, vulns]) => {
                    const priorCount = Array.from(groupedUnverifiedVulns.entries())
                      .filter(([c]) => c < cat)
                      .reduce((sum, [, vs]) => sum + vs.length, 0);
                    return (
                      <CategorySection
                        key={cat}
                        category={cat}
                        vulns={vulns}
                        globalIndex={priorCount}
                        needsVerification
                        defaultOpen
                        rootUrl={report.targetUrl}
                      />
                    );
                  })}
                </div>
              ) : (
                <AnimatePresence mode="popLayout">
                  {unverifiedVulns.map((v, i) => (
                    <VulnCard key={v.id} vuln={v} index={i} needsVerification rootUrl={report.targetUrl} />
                  ))}
                </AnimatePresence>
              )}
            </div>
          )}

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

          {/* Fix with your AI agent */}
          {aiAnalysis?.agentFixPrompt && (
            <AgentFixPromptCard prompt={aiAnalysis.agentFixPrompt} />
          )}

          {/* Software Inventory */}
          <SoftwareInventoryCard technologies={technologies ?? []} vulnerabilities={vulnerabilities} />

          {/* Pages Scanned */}
          <PagesScannedCard rootUrl={report.targetUrl} pagesScanned={pagesScanned ?? []} probedNotFound={probedNotFound ?? []} />

          {/* Reconnaissance */}
          {recon && <ReconCard recon={recon} />}

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
                  {technologies.map((t, i) => {
                    const { name, version } = parseTechVersion(t);
                    return (
                      <span key={i} className="inline-flex items-center gap-1 px-2.5 py-1 bg-secondary text-xs rounded-md border border-white/5">
                        <span>{name}</span>
                        {version && (
                          <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] font-mono rounded border border-yellow-500/20 leading-none">
                            {version}
                          </span>
                        )}
                      </span>
                    );
                  })}
                  {technologies.length === 0 && <span className="text-xs text-muted-foreground">None detected</span>}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Monitor CTA banner */}
      <div className="glass-panel rounded-2xl p-6 border border-indigo-500/25 bg-indigo-500/5 flex flex-col sm:flex-row items-center gap-6">
        <div className="w-12 h-12 rounded-xl bg-indigo-500/15 border border-indigo-500/25 flex items-center justify-center shrink-0">
          <Bell className="w-6 h-6 text-indigo-400" />
        </div>
        <div className="flex-1 text-center sm:text-left">
          <h3 className="font-bold text-lg mb-1">Keep watching this URL</h3>
          <p className="text-sm text-muted-foreground">
            Weekly automated rescans + instant CVE alerts when new vulnerabilities match your tech stack. <span className="text-indigo-400 font-semibold">$129/yr</span>
          </p>
        </div>
        <Link
          href="/monitor"
          className="shrink-0 px-6 py-3 bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-xl font-bold hover:bg-indigo-500/30 transition-all whitespace-nowrap flex items-center gap-2"
        >
          <Bell className="w-4 h-4" /> Start Monitoring
        </Link>
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
          <CopyReportButton data={copyData} />
          <DownloadPDFButton data={{
            targetUrl: report.targetUrl,
            scannedAt: report.scannedAt,
            summary: copyData.summary,
            confirmedVulns: allConfirmedVulns,
            unverifiedVulns: allUnverifiedVulns,
            technologies: technologies ?? [],
            server: server ?? null,
            tlsGrade: tlsGrade ?? null,
            aiAnalysis: aiAnalysis ?? null,
            categoryCounts,
            pagesScanned: pagesScanned ?? [],
          }} />
          <ShareButton reportId={reportId} />
        </div>
      </div>
      </div>

      {/* ── Timed undo toast ── shown for 5s after a finding is dismissed ── */}
      {undoToast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-background border border-border rounded-xl px-4 py-3 shadow-2xl text-sm animate-in slide-in-from-bottom-2 duration-200">
          <span className="text-muted-foreground">
            <span className="font-semibold text-foreground truncate max-w-[200px] inline-block align-bottom">{undoToast.vuln.name}</span>
            {" "}dismissed as false positive
          </span>
          <button
            onClick={async () => {
              if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
              const toastVuln = undoToast.vuln;
              setUndoToast(null);
              await undismissFinding(toastVuln);
            }}
            className="text-primary hover:text-primary/80 font-bold underline underline-offset-2 shrink-0"
          >
            Undo
          </button>
        </div>
      )}
    </>
    </DismissalsContext.Provider>
  );
}
