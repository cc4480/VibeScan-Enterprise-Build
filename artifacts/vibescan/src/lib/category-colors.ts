/**
 * One colour per kind of check, used everywhere a finding's category shows: the
 * scan terminal, the report's category headers and finding cards.
 *
 * The scanner uses 38 finding categories, far more than the eye can tell apart, so
 * related ones share a family (all the injection kinds are orange, all the data
 * stores indigo). A category not listed here gets the neutral slate, never an
 * error, so a new category renders before anyone remembers to colour it; a test
 * in the API package fails the build if the check catalog uses one that is missing.
 *
 * These colours mean "what kind of check". Severity is a different thing and keeps
 * its own colours (red to blue) on the badges.
 */

export interface CategoryFamily {
  label: string;
  hex: string;
}

export const FAMILIES = {
  browser: { label: "Headers and browser policy", hex: "#a78bfa" },
  transport: { label: "Transport and network", hex: "#22d3ee" },
  secrets: { label: "Secrets and credentials", hex: "#fb7185" },
  sessions: { label: "Sessions and authentication", hex: "#fbbf24" },
  access: { label: "Access control and APIs", hex: "#e879f9" },
  injection: { label: "Injection and redirects", hex: "#fb923c" },
  disclosure: { label: "Information disclosure", hex: "#38bdf8" },
  dns: { label: "Email and DNS", hex: "#2dd4bf" },
  datastores: { label: "Data stores and storage", hex: "#818cf8" },
  software: { label: "Software and supply chain", hex: "#a3e635" },
  notes: { label: "Metadata and coverage", hex: "#94a3b8" },
} as const satisfies Record<string, CategoryFamily>;

export type FamilyKey = keyof typeof FAMILIES;

export const CATEGORY_FAMILY: Record<string, FamilyKey> = {
  "HTTP Security": "browser",
  "Browser Feature Control": "browser",
  "Content Sniffing": "browser",
  "UI Security": "browser",
  "Security Header Inconsistency": "browser",
  "Security Misconfiguration": "browser",
  "CORS Misconfiguration": "browser",

  "Transport Security": "transport",
  "Mail Transport Security": "transport",
  "Network Exposure": "transport",

  "Credential Exposure": "secrets",
  "Exposed Secrets / Credentials": "secrets",
  "AI Feature Security": "secrets",
  "Secret Exposed in Page HTML": "secrets",

  "Session Management": "sessions",
  "CSRF Protection": "sessions",
  "Brute Force Protection": "sessions",

  "Broken Access Control": "access",
  "API Security": "access",
  "Server-Side Request Forgery": "access",
  "Business Logic": "access",

  "Injection": "injection",
  "Injection Defense": "injection",
  "Insecure Deserialization": "injection",
  "Unvalidated Redirects": "injection",

  "Information Disclosure": "disclosure",
  "Source Code Exposure": "disclosure",
  "Technology Fingerprint": "disclosure",
  "Data Exposure": "disclosure",

  "Email Security": "dns",
  "DNS Security": "dns",

  "Database Security": "datastores",
  "Cloud Storage Misconfiguration": "datastores",
  "BaaS Misconfiguration": "datastores",

  "Outdated Software": "software",
  "Outdated Software / Known CVE": "software",
  "Vulnerable Components": "software",
  "Supply Chain Security": "software",

  "Structured Data": "notes",
  "Scan Coverage": "notes",
};

/** The colour for a finding category. Unknown categories are slate, not an error. */
export function categoryHex(category: string | null | undefined): string {
  const family = category ? CATEGORY_FAMILY[category] : undefined;
  return FAMILIES[family ?? "notes"].hex;
}

/** The family a category belongs to, for legends. */
export function categoryFamily(category: string | null | undefined): FamilyKey {
  return (category ? CATEGORY_FAMILY[category] : undefined) ?? "notes";
}
