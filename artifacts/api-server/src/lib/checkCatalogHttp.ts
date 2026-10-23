/** The checks that read the target's own responses and DNS: headers, cookies, files, methods, mail. */
import { test, type CatalogTest } from "./checkCatalogTypes";

const SCANNER = "scanner.ts";
const PROBES = "probes.ts";

export const CATALOG_HTTP: CatalogTest[] = [
  test("response headers and cookies", "HTTP Security", SCANNER, [
    ["critical", "No HTTPS / Plaintext HTTP", "No HTTPS / Plaintext HTTP"],
    ["medium", "Missing HTTP Strict-Transport-Security (HSTS)", "Missing HTTP Strict-Transport-Security (HSTS)"],
    ["low", "HSTS max-age Too Short", "HSTS max-age Too Short"],
    ["high", "Missing Content-Security-Policy (CSP)", "Missing Content-Security-Policy (CSP)"],
    ["high", "CSP script-src Contains Wildcard", "CSP script-src Contains Wildcard"],
    ["medium", "Content-Security-Policy is report-only (not enforced)", "Content-Security-Policy is report-only (not enforced)"],
    ["medium", "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)", "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)"],
    ["info", "Content-Security-Policy Allows Inline Styles", "Content-Security-Policy Allows Inline Styles"],
    ["low", "CSP Missing object-src 'none' Directive", "CSP Missing object-src 'none' Directive"],
    ["low", "CSP Missing base-uri Directive", "CSP Missing base-uri Directive"],
    ["medium", "Missing Clickjacking Protection (X-Frame-Options)", "Missing Clickjacking Protection (X-Frame-Options)"],
    ["low", "Missing X-Content-Type-Options: nosniff", "Missing X-Content-Type-Options: nosniff"],
    ["info", "Missing Referrer-Policy Header", "Missing Referrer-Policy Header"],
    ["info", "Missing Permissions-Policy Header", "Missing Permissions-Policy Header"],
    ["info", "Missing Cross-Origin-Opener-Policy (COOP)", "Missing Cross-Origin-Opener-Policy (COOP)", "isolationHeaders.ts"],
    ["info", "Missing Cross-Origin-Embedder-Policy (COEP)", "Missing Cross-Origin-Embedder-Policy (COEP)", "isolationHeaders.ts"],
    ["info", "Missing Cross-Origin-Resource-Policy (CORP)", "Missing Cross-Origin-Resource-Policy (CORP)", "isolationHeaders.ts"],
    ["info", "Missing Cache-Control Headers", "Missing Cache-Control Headers"],
    ["info", "Permissive CORS Policy (Wildcard Origin)", "Permissive CORS Policy (Wildcard Origin)", undefined, "CORS Misconfiguration"],
    ["medium", "Mixed Content (HTTP Resources on HTTPS Page)", "Mixed Content (HTTP Resources on HTTPS Page)"],
    ["info", "Server Version Disclosure", "Server Version Disclosure", undefined, "Information Disclosure"],
    ["info", "X-Powered-By Header Discloses Technology Stack", "X-Powered-By Header Discloses Technology Stack", undefined, "Information Disclosure"],
    ["high", "Session Cookie Missing Secure Flag", "Session Cookie Missing Secure Flag", undefined, "Session Management"],
    ["medium", "Session Cookie Missing HttpOnly Flag", "Session Cookie Missing HttpOnly Flag", undefined, "Session Management"],
    ["low", "Session Cookie Missing SameSite Attribute", "Session Cookie Missing SameSite Attribute", undefined, "Session Management"],
    ["low", "Non-Session Cookie Missing Secure Flag", "Non-Session Cookie Missing Secure Flag", undefined, "Session Management"],
    ["info", "Non-Session Cookie Readable by JavaScript", "Non-Session Cookie Readable by JavaScript", undefined, "Session Management"],
    ["info", "Non-Session Cookie Missing SameSite Attribute", "Non-Session Cookie Missing SameSite Attribute", undefined, "Session Management"],
  ]),

  // The HTTP probes: each is its own ledger test, so each carries its own checks.
  test("sensitive file exposure", "Information Disclosure", PROBES, [
    ["varies", "Sensitive file or path publicly readable (81 paths)", "name: p.name"],
  ]),
  test("robots.txt disclosure", "Information Disclosure", PROBES, [
    ["low", "robots.txt Discloses Sensitive Application Paths", "robots.txt Discloses Sensitive Application Paths"],
  ]),
  test("subresource integrity", "Supply Chain Security", PROBES, [
    ["medium", "External Resources Missing Subresource Integrity (SRI)", "External Resources Missing Subresource Integrity (SRI)"],
    ["high", "Page Loads a Script From a Host Tied to a Known Supply-Chain Attack", "Page Loads a Script From a Host Tied to a Known Supply-Chain Attack", "compromisedScriptHosts.ts"],
  ]),
  test("verbose error pages", "Information Disclosure", PROBES, [
    ["medium", "Verbose Error Pages Expose Internal Application Details", "Verbose Error Pages Expose Internal Application Details"],
    ["critical", "Flask/Werkzeug Interactive Debugger Exposed", "Flask/Werkzeug Interactive Debugger Exposed"],
  ]),
  test("HTTP to HTTPS redirect", "Transport Security", PROBES, [
    ["high", "HTTP Traffic Not Redirected to HTTPS", "HTTP Traffic Not Redirected to HTTPS"],
  ]),
  test("rate-limit headers", "Brute Force Protection", PROBES, [
    ["low", "Rate Limiting Not Advertised in Response Headers", "Rate Limiting Not Advertised in Response Headers"],
  ]),
  test("clickjacking headers", "UI Security", PROBES, [
    ["medium", "X-Frame-Options Header Misconfigured", "X-Frame-Options Header Misconfigured"],
  ]),
  test("directory listing", "Information Disclosure", PROBES, [
    ["medium", "Directory Listing Enabled", "Directory Listing Enabled"],
  ]),
  test("security.txt", "Information Disclosure", PROBES, [
    ["info", "Missing security.txt (RFC 9116)", "Missing security.txt (RFC 9116)"],
  ]),
  test("HTTP methods", "HTTP Security", PROBES, [
    ["medium", "HTTP TRACE Method Enabled (Cross-Site Tracing)", "HTTP TRACE Method Enabled (Cross-Site Tracing)"],
    ["high", "Write HTTP Methods Advertised", "Write HTTP Methods Advertised"],
    ["medium", "HTTP CONNECT Method Enabled", "HTTP CONNECT Method Enabled"],
  ]),
  test("active CORS", "CORS Misconfiguration", PROBES, [
    ["high", "CORS Misconfiguration — Credentials Allowed from Arbitrary Origin", "CORS Misconfiguration — Credentials Allowed from Arbitrary Origin"],
    ["low", "CORS — Origin Reflected Without Credentials", "CORS — Origin Reflected Without Credentials"],
  ]),
  test("open redirect", "Unvalidated Redirects", PROBES, [
    ["medium", "Open Redirect Vulnerability", "Open Redirect Vulnerability"],
  ]),
  test("Supabase RLS", "Database Security", PROBES, [
    ["critical", "Supabase Tables Exposed — Row Level Security (RLS) Disabled", "Supabase Tables Exposed — Row Level Security (RLS) Disabled"],
    ["info", "Supabase Detected — Verify Row Level Security (RLS)", "Supabase Detected — Verify Row Level Security (RLS)"],
  ]),

  test("DNS and email authentication", "Email Security", "dnsChecks.ts", [
    ["high", "Missing SPF Record — Email Spoofing Possible", "Missing SPF Record — Email Spoofing Possible"],
    ["critical", "SPF Record Uses +all (Allows Any Sender)", "SPF Record Uses +all (Allows Any Sender)"],
    ["medium", "SPF Record Uses ?all (Neutral — No Enforcement)", "SPF Record Uses ?all (Neutral — No Enforcement)"],
    ["low", "SPF Record Exceeds DNS Lookup Limit", "SPF Record Exceeds DNS Lookup Limit"],
    ["high", "Missing DMARC Record — No Email Authentication Enforcement", "Missing DMARC Record — No Email Authentication Enforcement"],
    ["medium", "DMARC Policy Set to None (Monitoring Only — No Enforcement)", "DMARC Policy Set to None (Monitoring Only — No Enforcement)"],
    ["info", "DMARC Record Missing Aggregate Report Address (rua=)", "DMARC Record Missing Aggregate Report Address (rua=)"],
    ["low", "No DKIM Records Found Under Common Selectors", "No DKIM Records Found Under Common Selectors"],
    ["info", "DNSSEC Not Enabled", "DNSSEC Not Enabled", undefined, "DNS Security"],
  ]),
  test("mail transport security", "Mail Transport Security", "mailTls.ts", [
    ["medium", "Mail Server Does Not Offer STARTTLS", "Mail Server Does Not Offer STARTTLS"],
    ["high", "Mail Server TLS Certificate Expired", "Mail Server TLS Certificate Expired"],
    ["low", "Mail Server TLS Certificate Expiring Soon", "Mail Server TLS Certificate Expiring Soon"],
  ]),
  test("structured data and social metadata", "Structured Data", "structuredData.ts", [
    ["low", "Internal Hostname Exposed in Structured Data", "Internal Hostname Exposed in Structured Data"],
    ["low", "Social Preview Asset Referenced Over HTTP", "Social Preview Asset Referenced Over HTTP"],
    ["low", "Canonical URL Points to an External Domain", "Canonical URL Points to an External Domain"],
    ["info", "Malformed JSON-LD Structured Data", "Malformed JSON-LD Structured Data"],
    ["info", "Structured Data Missing @context or @type", "Structured Data Missing @context or @type"],
    ["info", "No Structured Data Found", "No Structured Data Found"],
    ["info", "Incomplete Open Graph Metadata", "Incomplete Open Graph Metadata"],
    ["info", "Twitter Card Metadata Absent", "Twitter Card Metadata Absent"],
    ["info", "Page Excluded From Search Indexes", "Page Excluded From Search Indexes"],
  ]),
];
