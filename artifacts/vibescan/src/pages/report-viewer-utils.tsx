import {
  Shield, ShieldAlert, Mail, GitBranch, KeyRound, Database,
  Terminal, ExternalLink, Package, RefreshCw, Eye, Code2, Wifi,
  AlertTriangle, Monitor, Info, Settings, Network, EyeOff, Globe, Lock,
} from "lucide-react";

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
  return CATEGORY_META[category] ?? {
    label: category,
    icon: <Globe className="w-4 h-4" />,
    color: "text-muted-foreground",
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


export const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪",
};
