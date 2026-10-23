/** Shapes, lookups and constants shared by the report view: finding fingerprints, the dismissals context, category metadata, verification notes. */
import { ShieldAlert, Globe, Lock, Mail, GitBranch, KeyRound, Database, Terminal, ExternalLink, Package, RefreshCw, Eye, Code2, Wifi, AlertTriangle, Monitor, Info, Settings, Network, EyeOff } from "lucide-react";
import { categoryHex } from "@/lib/category-colors";
import { createContext } from "react";
import type { Vulnerability } from "@workspace/api-client-react";
import { type SharedReportData } from "./shared-report-components";

// The structured compliance mapping the worker freezes into report.data
// (see api-server lib/compliance.ts). Shared with the public report view so the
// owner report and the shared link render the same shape from one source.
export type ComplianceData = NonNullable<SharedReportData["data"]["compliance"]>;

// ─── Dismissals context ───────────────────────────────────────────────────────

export interface DismissalEntry {
  fingerprint: string;
  findingName: string;
  findingCategory: string;
}

// ─── Client-side fingerprint helpers (mirror server lib/fingerprint.ts) ────────

export function normalizeEvidenceKeyClient(evidence?: string | null): string {
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

export async function computeVulnFp(
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

export function vulnUniqueKey(v: { category: string; name: string; evidence?: string | null }): string {
  return `${v.category}:${v.name}:${v.evidence ?? ""}`;
}

// ─── Dismissals context ──────────────────────────────────────────────────────

export interface DismissalsCtx {
  dismissedFps: Set<string>;
  vulnFpMap: Map<string, string>;
  optimisticDismissKeys: Set<string>;
  dismiss: (vuln: Vulnerability, targetUrl: string) => Promise<void>;
  undismiss: (vuln: Vulnerability) => Promise<void>;
}

export const DismissalsContext = createContext<DismissalsCtx>({
  dismissedFps: new Set(),
  vulnFpMap: new Map(),
  optimisticDismissKeys: new Set(),
  dismiss: async () => {},
  undismiss: async () => {},
});

// ─── Category metadata ────────────────────────────────────────────────────────

export interface CategoryMeta {
  label: string;
  icon: React.ReactNode;
  color: string;
}

export const CATEGORY_META: Record<string, CategoryMeta> = {
  "Transport Security":              { label: "Transport Security",              icon: <Lock className="w-4 h-4" />,          color: "text-blue-400" },
  "Injection Defense":               { label: "Injection Defense",               icon: <Code2 className="w-4 h-4" />,         color: "text-orange-400" },
  "UI Security":                     { label: "UI Security",                     icon: <Monitor className="w-4 h-4" />,       color: "text-purple-400" },
  "Content Sniffing":                { label: "Content Sniffing",                icon: <Eye className="w-4 h-4" />,           color: "text-yellow-400" },
  "Information Disclosure":          { label: "Information Disclosure",          icon: <Info className="w-4 h-4" />,          color: "text-sky-400" },
  "Browser Feature Control":         { label: "Browser Feature Control",         icon: <Settings className="w-4 h-4" />,      color: "text-zinc-400" },
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
  "Email Security":                  { label: "Email Security",                  icon: <Mail className="w-4 h-4" />,          color: "text-green-400" },
  "DNS Security":                    { label: "DNS Security",                    icon: <Wifi className="w-4 h-4" />,          color: "text-green-400" },
  "Exposed Secrets / Credentials":   { label: "Exposed Secrets",                icon: <AlertTriangle className="w-4 h-4" />, color: "text-red-500" },
  "Security Header Inconsistency":   { label: "Header Inconsistency",           icon: <AlertTriangle className="w-4 h-4" />, color: "text-amber-400" },
  "Outdated Software / Known CVE":   { label: "Outdated Software / CVE",        icon: <GitBranch className="w-4 h-4" />,     color: "text-red-400" },
  "Outdated Software":               { label: "Outdated Software",              icon: <GitBranch className="w-4 h-4" />,     color: "text-red-400" },
  "Network Exposure":                { label: "Network Exposure",               icon: <Network className="w-4 h-4" />,       color: "text-red-400" },
  "Broken Access Control":           { label: "Broken Access Control",          icon: <ShieldAlert className="w-4 h-4" />,   color: "" },
  "API Security":                    { label: "API Security",                   icon: <Network className="w-4 h-4" />,       color: "" },
  "Database Security":               { label: "Database Security",              icon: <Database className="w-4 h-4" />,      color: "" },
  "Cloud Storage Misconfiguration":  { label: "Cloud Storage",                  icon: <Package className="w-4 h-4" />,       color: "" },
  "BaaS Misconfiguration":           { label: "BaaS Misconfiguration",          icon: <Database className="w-4 h-4" />,      color: "" },
  "Injection":                       { label: "Injection",                      icon: <Code2 className="w-4 h-4" />,         color: "" },
  "Insecure Deserialization":        { label: "Insecure Deserialization",       icon: <Code2 className="w-4 h-4" />,         color: "" },
  "Server-Side Request Forgery":     { label: "Server-Side Request Forgery",    icon: <Network className="w-4 h-4" />,       color: "" },
  "Vulnerable Components":           { label: "Vulnerable Components",          icon: <Package className="w-4 h-4" />,       color: "" },
  "Mail Transport Security":         { label: "Mail Transport Security",        icon: <Mail className="w-4 h-4" />,          color: "" },
  "Security Misconfiguration":        { label: "Security Misconfiguration",      icon: <Settings className="w-4 h-4" />,      color: "" },
  "Technology Fingerprint":          { label: "Technology Fingerprint",         icon: <Eye className="w-4 h-4" />,           color: "" },
  "Structured Data":                 { label: "Structured Data",                icon: <Info className="w-4 h-4" />,          color: "" },
  "Secret Exposed in Page HTML":     { label: "Secret in Page HTML",            icon: <EyeOff className="w-4 h-4" />,        color: "" },
};

// Maps a WSTG ID like "WSTG-CONF-07" to its OWASP Testing Guide URL path fragment
export const WSTG_PATHS: Record<string, string> = {
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

export function wstgCategoryPath(id: string): string {
  return WSTG_PATHS[id] ?? "";
}

export function getCategoryMeta(category: string): CategoryMeta {
  const known = CATEGORY_META[category];
  // The colour always comes from the shared palette (lib/category-colors.ts) so the
  // report and the scan terminal agree, and every category has one.
  return {
    label: known?.label ?? category,
    icon: known?.icon ?? <Globe className="w-4 h-4" />,
    color: categoryHex(category),
  };
}

// ─── Verification threshold ───────────────────────────────────────────────────
// Findings below this confidence score are shown in a separate "Needs Verification"
// section so confirmed findings stay trustworthy and nothing gets silently dropped.

export const VERIFICATION_THRESHOLD = 65;

// Per-category explanation shown inside unverified finding cards
export const VERIFICATION_NOTES: Record<string, string> = {
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

export function getVerificationNote(category: string): string {
  return (
    VERIFICATION_NOTES[category] ??
    "This finding was detected using a heuristic or pattern-based method. Reproduce it manually with a raw HTTP request to confirm it is a real, exploitable issue before prioritising remediation."
  );
}

// ─── Tech version parsing ─────────────────────────────────────────────────────
// Technologies are stored as "jQuery 1.11.3" or "Nginx 1.18.0".
// Split on the last whitespace-separated token that starts with a digit.

export function parseTechVersion(tech: string): { name: string; version: string | null } {
  // Space-separated: "jQuery 1.11.3" or "Nginx 1.18.0" (canonical scanner output)
  const spaceMatch = /^(.+?)\s+(\d[\w.\-]*)$/.exec(tech);
  if (spaceMatch) return { name: spaceMatch[1], version: spaceMatch[2] };
  // Slash-separated: "nginx/1.18.0" (raw header values surfaced directly)
  const slashMatch = /^(.+?)\/(\d[\w.\-]*)$/.exec(tech);
  if (slashMatch) return { name: slashMatch[1], version: slashMatch[2] };
  return { name: tech, version: null };
}

// ─── Severity sort order ──────────────────────────────────────────────────────

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

// ─── Inner-page source extractor ─────────────────────────────────────────────

export const INNER_PAGE_CATEGORIES = new Set([
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
export function extractInnerPageSource(
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

// ─── Severity emoji for print / markdown ─────────────────────────────────────

export const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪",
};
