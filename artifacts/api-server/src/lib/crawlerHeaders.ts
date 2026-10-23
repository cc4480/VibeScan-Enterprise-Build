/** Header snapshots and the missing-header findings raised from them. */
import type { ScanVulnerability } from "./scanner";
import { vuln } from "./crawlerFetch";
import { cspRestrictsFraming } from "./headerAnalysis.js";

// ─────────────────────────────────────────────────────────────────────────────
// PER-PAGE HEADER CHECKS
// ─────────────────────────────────────────────────────────────────────────────

export interface HeaderSnapshot {
  hsts: boolean;
  csp: boolean;
  xfo: boolean;
  xcto: boolean;
  rp: boolean;
}

/**
 * Drop header gaps that a second request does not reproduce.
 *
 * A gap is reported at up to HIGH, so it has to survive being looked at twice.
 * Some origins emit a security header only intermittently: reddit answers the
 * SAME path through the scanner's own fetch layer with a 161-byte CSP on one
 * request and none on the next, seconds apart. A single observation of that is a
 * true statement about one response and a finding nobody can reproduce — the
 * customer re-checks by hand, sees the header, and concludes the scanner is
 * broken. FALSE-POSITIVE-AUDIT.md records that shape repeatedly as the worst
 * kind of finding to ship, because it argues against itself.
 *
 * This can only ever REMOVE a gap, so it cannot invent a finding. A path whose
 * header is genuinely absent — reddit's /live, github's /healthz, cloudflare's
 * locale routes — is absent on the retry too and still reports. When the retry
 * cannot be made at all (budget spent, network error, an error status) the
 * original observation stands: refusing to report an unconfirmable gap would
 * trade this false positive for a silent false negative, which is the trade this
 * audit has already regretted once.
 */
export async function confirmHeaderGaps(
  gapMap: Map<keyof HeaderSnapshot, string[]>,
  refetch: (url: string) => Promise<{ status: number; headers: Record<string, string> } | null>,
): Promise<void> {
  for (const [key, paths] of gapMap) {
    if (paths.length === 0) continue;
    const confirmed: string[] = [];
    for (const url of paths) {
      const again = await refetch(url);
      if (!again || again.status === 0 || again.status >= 400) {
        confirmed.push(url);
        continue;
      }
      if (!snapshotHeaders(again.headers)[key]) confirmed.push(url);
    }
    gapMap.set(key, confirmed);
  }
}

export function snapshotHeaders(headers: Record<string, string>): HeaderSnapshot {
  const h = (name: string) => {
    const k = Object.keys(headers).find((k) => k.toLowerCase() === name);
    return k ? headers[k] : undefined;
  };
  return {
    hsts: !!h("strict-transport-security"),
    csp:  !!h("content-security-policy"),
    xfo:  !!h("x-frame-options") || cspRestrictsFraming(h("content-security-policy")),
    xcto: h("x-content-type-options")?.toLowerCase() === "nosniff",
    rp:   !!h("referrer-policy"),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// AGGREGATE HEADER-GAP FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

export interface HeaderGapMeta {
  header: string;
  severity: ScanVulnerability["severity"];
  cweId: string;
  cvssScore: number;
  wstgId: string;
  description: string;
  solution: string;
}

export const HEADER_GAP_META: Record<keyof HeaderSnapshot, HeaderGapMeta> = {
  hsts: {
    header: "Strict-Transport-Security",
    // Low, unlike the other headers here, because HSTS is host-scoped rather
    // than per-response. Once any response from the host carries it — and this
    // finding only fires when the root page does — the browser enforces
    // HTTPS-only for the whole host until max-age expires. A route that omits
    // it is therefore only reachable over HTTP by someone whose very first
    // contact with the domain is that exact URL. Real, but defence-in-depth.
    //
    // Grading it High put robinhood.com at D over three sitemap pages, below
    // sites serving no CSP at all — a ranking that says more about the weight
    // than the risk. CSP and the rest stay High/Medium: those genuinely apply
    // per response, so a route missing one is unprotected on every visit.
    severity: "low",
    cweId: "CWE-523",
    cvssScore: 3.1,
    wstgId: "WSTG-CONF-07",
    description:
      "The root URL has HSTS configured, but the following internal routes respond without the header. Routes that bypass the CDN (e.g. API endpoints hitting origin directly) won't enforce HTTPS-only connections.",
    solution:
      "Ensure HSTS is set at the application layer, not just the CDN, so all responses include the header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  csp: {
    header: "Content-Security-Policy",
    severity: "high",
    cweId: "CWE-79",
    cvssScore: 7.2,
    wstgId: "WSTG-CONF-12",
    description:
      "CSP is present on the root URL but absent on some internal routes. API endpoints and authenticated pages often need CSP too — injected content on those pages can steal tokens.",
    solution:
      "Apply CSP at the application/middleware layer for all routes, not just the homepage. Use a base policy that works across your entire app.",
  },
  xfo: {
    header: "X-Frame-Options / frame-ancestors",
    severity: "medium",
    cweId: "CWE-1021",
    cvssScore: 4.3,
    wstgId: "WSTG-CLNT-09",
    description:
      "Clickjacking protection is set on the root URL but missing on some internal pages. Those pages can be embedded in malicious iframes.",
    solution:
      "Apply X-Frame-Options: DENY (or SAMEORIGIN) globally via middleware, not per-route.",
  },
  xcto: {
    header: "X-Content-Type-Options",
    severity: "medium",
    cweId: "CWE-16",
    cvssScore: 4.3,
    wstgId: "WSTG-CONF-07",
    description:
      "X-Content-Type-Options: nosniff is on the root page but missing on some internal routes, leaving those routes open to MIME-sniffing attacks.",
    solution: "Set X-Content-Type-Options: nosniff globally in your server/middleware.",
  },
  rp: {
    header: "Referrer-Policy",
    severity: "low",
    cweId: "CWE-200",
    cvssScore: 3.1,
    wstgId: "WSTG-CONF-07",
    description:
      "Referrer-Policy is set on the root URL but absent on some internal routes.",
    solution: "Set Referrer-Policy globally: strict-origin-when-cross-origin",
  },
};

// Exported for test: the query string is load-bearing in this evidence and a
// regression here is invisible until someone tries to verify a finding.
export function buildHeaderGapVulns(
  rootSnapshot: HeaderSnapshot,
  gapMap: Map<keyof HeaderSnapshot, string[]>,
  probedSet: Set<string>,
): ScanVulnerability[] {
  const results: ScanVulnerability[] = [];

  for (const [key, paths] of gapMap.entries()) {
    if (paths.length === 0) continue;
    const meta = HEADER_GAP_META[key];
    if (!meta) continue;

    // Only flag if root page HAD the header (makes this a regression, not a new issue)
    if (!rootSnapshot[key]) continue;

    // The QUERY STRING IS PART OF THE ROUTE, and dropping it produced evidence
    // that refuted itself. paypal.com links every internal page as
    // "…/giving?locale.x=en_US"; that URL answers with a 1818-byte CSP carrying
    // no frame-ancestors, while the bare "…/giving" answers with a different
    // 2277-byte CSP that has it. The crawl saw the former and was right. The
    // evidence printed the latter, so anyone verifying the finding the way the
    // audit requires — fetch the path, read the header — found the header
    // present and concluded the check was broken.
    //
    // Evidence that cannot be reproduced from what it prints is worse than no
    // evidence: it argues against a true finding.
    const displayPaths = paths.slice(0, 6).map((p) => {
      try {
        const u = new URL(p);
        const tag = probedSet.has(p) ? " (probed)" : " (crawled)";
        return u.pathname + u.search + tag;
      } catch { return p; }
    });

    results.push(vuln({
      name: `${meta.header} Missing on ${paths.length} Internal Route${paths.length > 1 ? "s" : ""}`,
      severity: meta.severity,
      category: "Security Header Inconsistency",
      description: meta.description,
      evidence: `Routes missing ${meta.header}:\n${displayPaths.map((p) => `  • ${p}`).join("\n")}${paths.length > 6 ? `\n  … and ${paths.length - 6} more` : ""}`,
      solution: meta.solution,
      cweId: meta.cweId,
      cvssScore: meta.cvssScore,
      wstgId: meta.wstgId,
    }));
  }

  return results;
}
