/**
 * DNS security checks — uses Cloudflare DNS-over-HTTPS (no key required).
 * Checks email authentication (SPF, DMARC, DKIM) and DNSSEC.
 *
 * Missing email security records allow attackers to send phishing emails
 * that appear to come from your domain — one of the most common attack vectors.
 */

import type { ScanVulnerability } from "./scanner";
import { registrableDomain } from "./registrableDomain.js";
import { vuln, dnsQuery, statusLabel, ancestorDomains } from "./dnsChecksCore";
import { checkSpf, checkDmarc, checkDkim } from "./dnsChecksMail";
export { checkSpf, checkDmarc, COMMON_DKIM_SELECTORS, checkDkim } from "./dnsChecksMail";

// ─────────────────────────────────────────────────────────────────────────────
// DNSSEC CHECK
// ─────────────────────────────────────────────────────────────────────────────

export async function checkDnssec(hostname: string): Promise<ScanVulnerability[]> {
  // DNSSEC signs a ZONE, and DNSKEY lives at the zone apex. Asking a CNAMEd
  // www host returns the CNAME chain and no DNSKEY: www.nasa.gov answers with a
  // single CNAME while nasa.gov is properly signed. Before answers were matched
  // against the requested type, that CNAME was counted as a DNSKEY and the
  // check silently passed for the wrong reason — so this walk up the ancestors
  // has to land with the type filter, not after it.
  const checked: string[] = [];
  let firstStatus = -1;
  for (const domain of ancestorDomains(hostname)) {
    checked.push(domain);
    const { answers, status } = await dnsQuery(domain, "DNSKEY");
    if (checked.length === 1) firstStatus = status;
    if (status === -1) return [];
    if (answers.length > 0) return [];
  }

  return [vuln({
    name: "DNSSEC Not Enabled",
    severity: "info",
    category: "DNS Security",
    description: `DNSSEC is not configured for ${hostname}. Without DNSSEC, DNS responses can be forged or tampered with in transit (DNS cache poisoning / Kaminsky attack). Attackers can redirect your domain's traffic to malicious servers without users or servers being able to detect it.`,
    evidence: `No DNSKEY records found for ${checked.join(" or ")} (${statusLabel(firstStatus)}).`,
    solution: "Enable DNSSEC through your domain registrar. Most major registrars (Cloudflare, AWS Route 53, Google Domains) offer one-click DNSSEC. Your DNS hosting provider must also support signed zones. This requires coordination between your registrar and DNS provider.",
    // CWE-345, not CWE-350: this is unauthenticated DNS answers, not takeover.
    // CWE-350 maps to the ASVS subdomain-takeover control in lib/compliance.ts,
    // which cited a control this finding has no bearing on.
    cweId: "CWE-345",
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cloud-hosting platforms where the subdomain owner has NO DNS control.
 * The apex domain is managed by the platform, so DMARC/SPF/DKIM records
 * cannot be configured by the app owner — flagging their absence is a
 * false positive with zero actionability.
 *
 * Each entry is matched as a suffix: "foo.vercel.app" matches ".vercel.app".
 */
const UNCONTROLLED_DNS_PLATFORMS = [
  ".replit.app",
  ".replit.dev",
  ".repl.co",
  ".vercel.app",
  ".netlify.app",
  ".github.io",
  ".fly.dev",
  ".onrender.com",
  ".render.com",
  ".railway.app",
  ".up.railway.app",
  ".azurewebsites.net",
  ".azurestaticapps.net",
  ".workers.dev",
  ".pages.dev",
  ".web.app",
  ".firebaseapp.com",
  ".amplifyapp.com",
  ".surge.sh",
  ".glitch.me",
  ".codesandbox.io",
  ".stackblitz.io",
  ".cloudflare.dev",
  ".deno.dev",
  ".val.run",
  ".brev.sh",
];

/** Returns true when the hostname is a subdomain on a managed hosting platform. */
function isUncontrolledPlatformSubdomain(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return UNCONTROLLED_DNS_PLATFORMS.some((suffix) => lower.endsWith(suffix));
}

export async function checkDnsSecurity(targetUrl: string): Promise<ScanVulnerability[]> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return [];
  }

  // Don't run DNS checks on IP addresses
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname === "localhost") {
    return [];
  }

  // Skip email-auth checks for cloud-hosting subdomains where the app owner
  // has no DNS control.  Adding DMARC/SPF/DKIM records to these domains is
  // impossible — the findings would be unfixable false positives.
  if (isUncontrolledPlatformSubdomain(hostname)) {
    return [];
  }

  // SPF and DMARC live on the organisational domain rather than on the www host,
  // and checkSpf/checkDmarc now walk up the ancestor chain themselves, so they
  // take the hostname as scanned. Guessing the registrable domain from label
  // lengths — which is what used to happen here — reported GOV.UK as having
  // neither record.
  //
  // DKIM cannot walk: a selector probe is a specific name, so it uses the most
  // general ancestor, which is the apex for every host this scanner sees.
  // ancestorDomains() ends at "co.uk" for www.example.co.uk, so use the
  // registrable domain instead of the last ancestor.
  const emailDomain = registrableDomain(hostname);

  // Run SPF and DMARC first so we can decide whether to suppress DKIM brute-force.
  const [spf, dmarc] = await Promise.allSettled([
    checkSpf(hostname),
    checkDmarc(hostname),
  ]);

  const dmarcVulns = dmarc.status === "fulfilled" ? dmarc.value : [];

  // DMARC is "enforcing" when there is no "Missing DMARC" finding AND no
  // "p=none" finding.  An enforcing DMARC policy (p=quarantine or p=reject)
  // requires at least one aligned authentication mechanism — which means the
  // domain almost certainly has DKIM configured under a non-standard selector
  // (e.g. a date-based key like "20230601") that our brute-force list doesn't
  // cover.  Reporting "No DKIM found" in that case is a false positive.
  const dmarcIsEnforcing =
    !dmarcVulns.some((v) => v.name.includes("Missing DMARC")) &&
    !dmarcVulns.some((v) =>
      v.name.toLowerCase().includes("none") ||
      v.name.toLowerCase().includes("monitoring only"),
    );

  const [dkim, dnssec] = await Promise.allSettled([
    // Skip DKIM selector probing when DMARC is enforcing — the domain has DKIM
    // configured; we just can't discover the selector by brute-force.
    dmarcIsEnforcing ? Promise.resolve([]) : checkDkim(emailDomain),
    checkDnssec(hostname),
  ]);

  return [
    ...(spf.status === "fulfilled" ? spf.value : []),
    ...dmarcVulns,
    ...(dkim.status === "fulfilled" ? dkim.value : []),
    ...(dnssec.status === "fulfilled" ? dnssec.value : []),
  ];
}