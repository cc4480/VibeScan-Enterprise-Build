import { headerVal, vuln, type ScanVulnerability, type PageContext } from "./scannerTypes";
import { isHstsPreloaded } from "./scannerHstsPreload";
import { parseHsts } from "./hstsParse";

/** The finding for an address served without TLS: a fact about the address, whatever the response was. */
export const PLAINTEXT_FINDING_NAME = "No HTTPS / Plaintext HTTP";

/** Plaintext HTTP and Strict-Transport-Security checks on the first response. */
export async function transportFindings({ finalUrl, rawHeaders, isHttps }: PageContext): Promise<ScanVulnerability[]> {
  const vulnerabilities: ScanVulnerability[] = [];

  // ── TLS / HTTPS ───────────────────────────────────────────────────────
  if (!isHttps) {
    vulnerabilities.push(vuln({
      name: PLAINTEXT_FINDING_NAME,
      severity: "critical",
      category: "Transport Security",
      description: "The application is served over HTTP without TLS encryption. All data transmitted between the browser and the server—including passwords and session tokens—can be intercepted by any network observer.",
      evidence: `URL: ${finalUrl}\nProtocol: HTTP (no TLS)`,
      solution: "Obtain a TLS certificate (free from Let's Encrypt) and redirect all HTTP traffic to HTTPS. Set up HSTS once HTTPS is working.",
      cweId: "CWE-319",
      cvssScore: 9.1,
      wstgId: "WSTG-CRYP-01",
    }));
  }

  // ── HTTP Strict-Transport-Security ────────────────────────────────────
  const hsts = headerVal(rawHeaders, "strict-transport-security");
  if (!hsts && isHttps) {
    // Before flagging: check the HSTS preload list. Preloaded domains have HTTPS
    // enforced in browsers before the first request, so the header is optional.
    // This also prevents false positives when the scanner runs behind a
    // TLS-terminating proxy that strips security headers from HTTPS responses.
    const preloaded = await isHstsPreloaded(new URL(finalUrl).hostname).catch(() => false);
    if (!preloaded) {
      // Since we successfully fetched this site over HTTPS, it clearly HAS HTTPS.
      // A missing STS header means browsers won't cache the HTTPS preference, but
      // HTTPS itself is working. This is MEDIUM (not HIGH). HIGH is reserved for
      // sites with no HTTPS at all (handled above). A host on the preload list may
      // omit the header; a redirect from http:// to https:// does not make up for
      // it (the first visit is still plain HTTP), so it is not taken as a sign of preloading.
      vulnerabilities.push(vuln({
        name: "Missing HTTP Strict-Transport-Security (HSTS)",
        severity: "medium",
        category: "Transport Security",
        description: "HSTS is not configured via response header. Without it, browsers won't cache the HTTPS-only preference, leaving users vulnerable to downgrade attacks and SSL stripping on their first visit or after cache expiry. Note: some sites rely on HSTS preloading (browser built-in list) instead — verify at https://hstspreload.org.",
        evidence: `GET ${finalUrl}\nStrict-Transport-Security: (header absent from response)`,
        solution: "Add this header to all HTTPS responses: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\nFor the strongest protection, also submit your domain to the HSTS preload list at https://hstspreload.org",
        cweId: "CWE-523",
        cvssScore: 5.3,
        wstgId: "WSTG-CONF-07",
      }));
    }
  } else if (hsts) {
    // Check for weak HSTS config
    const maxAge = parseHsts(hsts).maxAge;
    if (maxAge === null) {
      // RFC 6797 section 6.1: a header with no usable max-age is ignored by browsers, so no HSTS policy is in effect.
      vulnerabilities.push(vuln({
        name: "HSTS Header Has No Usable max-age (Ignored by Browsers)",
        severity: "low",
        category: "Transport Security",
        description: "The Strict-Transport-Security header has no valid max-age directive, so browsers ignore it and no HSTS policy is in effect.",
        evidence: `GET ${finalUrl}\nStrict-Transport-Security: ${hsts}`,
        solution: "Set a complete header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        cweId: "CWE-523",
        cvssScore: 3.1,
        wstgId: "WSTG-CONF-07",
      }));
    } else if (maxAge === 0) {
      vulnerabilities.push(vuln({
        name: "HSTS Policy Is Being Removed (max-age=0)",
        severity: "low",
        category: "Transport Security",
        description: "The header sets max-age=0, which tells browsers to forget this host's HSTS policy. That is how a policy is withdrawn on purpose, so the site is not protected by HSTS. If this is not intended, restore a long max-age.",
        evidence: `GET ${finalUrl}\nStrict-Transport-Security: ${hsts}`,
        solution: "Serve a long max-age (Strict-Transport-Security: max-age=31536000; includeSubDomains) once the site works over HTTPS everywhere.",
        cweId: "CWE-523",
        cvssScore: 3.1,
        wstgId: "WSTG-CONF-07",
      }));
    } else if (maxAge < 15552000) { // less than 180 days
      vulnerabilities.push(vuln({
        name: "HSTS max-age Too Short",
        severity: "low",
        category: "Transport Security",
        description: `The HSTS max-age is set to ${maxAge} seconds (${Math.round(maxAge / 86400)} days), which is below the recommended minimum of 180 days (15552000 seconds). Short max-age values mean users lose HTTPS protection shortly after their browser cache expires.`,
        evidence: `GET ${finalUrl}\nStrict-Transport-Security: ${hsts}\n(max-age=${maxAge} — minimum recommended: 15552000)`,
        solution: "Set max-age to at least 15552000 (180 days). For preloading eligibility, use max-age=31536000; includeSubDomains; preload.",
        cweId: "CWE-523",
        cvssScore: 3.1,
        wstgId: "WSTG-CONF-07",
      }));
    }
  }

  return vulnerabilities;
}
