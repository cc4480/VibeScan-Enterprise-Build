import { analyzeCsp, extractMetaCsp, findMixedContent } from "./headerAnalysis.js";
import { headerVal, vuln, type ScanVulnerability, type PageContext } from "./scannerTypes";

/** Mixed content and caching checks that read the page as well as its headers. */
export function pageFindings({ finalUrl, html, rawHeaders, isHttps }: PageContext): ScanVulnerability[] {
  const vulnerabilities: ScanVulnerability[] = [];
  const csp = headerVal(rawHeaders, "content-security-policy") ?? extractMetaCsp(html) ?? undefined;

  // ── Mixed content ─────────────────────────────────────────────────────
  // Skipped when the CSP carries upgrade-insecure-requests: browsers rewrite those
  // http:// loads to https:// before requesting them.
  const mixed = isHttps && !(csp && analyzeCsp(csp).upgradeInsecureRequests)
    ? findMixedContent(html.slice(0, 100_000))
    : [];
  if (mixed.length > 0) {
    const activeMixed = mixed.some((m) => m.active);
    vulnerabilities.push(vuln({
      name: "Mixed Content (HTTP Resources on HTTPS Page)",
      // Browsers auto-upgrade or block passive (image/media) loads; scripts, styles and frames are the risk.
      severity: activeMixed ? "medium" : "low",
      category: "Transport Security",
      description: activeMixed
        ? "The HTTPS page references scripts, stylesheets or frames over plain HTTP. Browsers block these, which breaks the page, and where they are allowed the HTTP resources can be intercepted and modified by attackers."
        : "The HTTPS page references images or media over plain HTTP. Modern browsers upgrade or block these, but they can be intercepted and swapped on older clients.",
      evidence: `GET ${finalUrl}\nHTTP subresources on an HTTPS page (${mixed.length}):\n${mixed.slice(0, 5).map((m) => `<${m.tag}> ${m.url.slice(0, 200)}`).join("\n")}`,
      solution: "Update all resource URLs to use HTTPS. Use protocol-relative URLs (//example.com/resource) or absolute HTTPS URLs. Enable Content-Security-Policy: upgrade-insecure-requests",
      cweId: "CWE-311",
      cvssScore: activeMixed ? 5.9 : 3.1,
      wstgId: "WSTG-CRYP-01",
    }));
  }

  // X-XSS-Protection: 0 is intentionally NOT flagged.
  // Disabling the browser's legacy XSS auditor is the current OWASP/Google/Mozilla
  // recommendation — the auditor was deprecated, causes false positives, and has
  // introduced its own XSS vulnerabilities in some browsers. Setting it to 0 is correct.

  // ── Cache-Control on sensitive-looking pages ───────────────────────────
  const cacheControl = headerVal(rawHeaders, "cache-control");
  const pragma = headerVal(rawHeaders, "pragma");
  if (isHttps && !cacheControl && !pragma) {
    vulnerabilities.push(vuln({
      name: "Missing Cache-Control Headers",
      severity: "info",
      category: "Information Disclosure",
      description: "No Cache-Control or Pragma headers are set. Without explicit cache directives, proxies and shared caches may store sensitive page content, potentially serving it to other users or making it accessible after logout.",
      evidence: `GET ${finalUrl}\nCache-Control: (header absent)\nPragma: (header absent)`,
      solution: "Set Cache-Control: no-store, no-cache, must-revalidate on pages with sensitive or personalized content. Use Cache-Control: public, max-age=3600 only for truly static, non-sensitive resources.",
      cweId: "CWE-524",
      wstgId: "WSTG-CONF-07",
    }));
  }

  return vulnerabilities;
}
