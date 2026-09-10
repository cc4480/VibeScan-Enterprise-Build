/**
 * Live false-positive runner.
 *
 * Points the PASSIVE pipeline at real, well-secured sites and prints what it
 * finds. On targets like these a good scan returns few findings and ZERO false
 * ones, so anything actionable is a false-positive candidate to be checked
 * against the live response by hand.
 *
 * This exists because its absence was expensive: a Set-Cookie parsing bug made
 * the scanner report HttpOnly missing on cookies that plainly had it, for any
 * cookie whose expires= preceded its security flags. Nothing caught it because
 * nobody was routinely pointing the scanner at known-good sites and reading the
 * output.
 *
 * Passive only. Active exploit probing is gated behind domain-ownership
 * verification in the product and must never be aimed at sites you do not own.
 *
 * Usage (DATABASE_URL only has to be set, not populated — the scanner module
 * imports the db layer at load time):
 *
 *   DATABASE_URL=postgres://localhost/whatever \
 *     npx tsx artifacts/api-server/scripts/live-scan.ts https://github.com
 */
import { runScan } from "../src/lib/scanner.js";

/**
 * Twenty targets chosen to exercise the suppression rules, not at random.
 *
 * A random sample mostly re-tests the easy path. These are sites whose real
 * shape has previously produced, or would produce, a specific false positive —
 * so a regression in any one rule shows up as an actionable finding here. The
 * comment on each is the rule it guards.
 *
 * The correct result for every one of these is ZERO actionable findings that
 * survive a hand check. Anything else is a candidate, to be verified against
 * the live response before anyone "fixes" the scanner.
 */
const DEFAULT_TARGETS = [
  // HSTS preload list + Content-Security-Policy-Report-Only + the NID cookie.
  // Graded D once, on findings that were all wrong.
  "https://google.com",
  // Multi-tenant catch-all: an arbitrary path segment renders a normal 200
  // page, so path probes false-positive without spaCatchAll. Also sets a
  // non-session "logged_in" marker cookie.
  "https://github.com",
  // A long CSP allowlist full of *.subdomain entries — the wildcard rule must
  // not read those as "script-src *".
  "https://www.cloudflare.com",
  // Both have answered 403 "Just a moment..." to this scanner. Tests that a
  // challenge page is withheld rather than attributed to them.
  "https://stackoverflow.com",
  "https://www.npmjs.com",
  // Served its real homepage under an edge that also fronts challenges; twelve
  // of eighteen findings once came from an interstitial it never served.
  "https://www.etsy.com",
  // Serves its REAL homepage under x-datadome: protected. The header must be
  // judged on its value, not its presence.
  "https://www.nytimes.com",
  // __Host-js_csrf: a CSRF token has to be readable by JavaScript, so demanding
  // HttpOnly on it is wrong.
  "https://www.dropbox.com",
  // Public-by-design keys in client JS (Stripe pk_live_, Mapbox, Sentry DSNs).
  "https://stripe.com",
  "https://www.mapbox.com",
  // Heavy SPAs — content only exists after JS runs, so the shell must not be
  // read as an empty or broken page.
  "https://vercel.com",
  "https://www.netlify.com",
  // Large cookie sets with a mix of session and analytics names.
  "https://www.linkedin.com",
  "https://www.reddit.com",
  // Deliberately minimal headers on a site that is nonetheless not broken.
  "https://www.wikipedia.org",
  // Preloaded, no STS header on some routes — the behavioural fallback fails
  // here, which is why the bundled list exists.
  "https://www.apple.com",
  // Long redirect chains before the real document.
  "https://www.microsoft.com",
  // Strict, well-configured reference targets: anything actionable here is
  // almost certainly ours.
  "https://www.mozilla.org",
  "https://www.paypal.com",
  "https://www.bbc.co.uk",
];

/**
 * `--json <path>` also writes the full result per target, so a run can be
 * aggregated rather than only read. The console output is unchanged — it is
 * what the audit procedure asks you to actually look at.
 */
function jsonDest(argv: string[]): string | null {
  const i = argv.indexOf("--json");
  if (i === -1) return null;
  const dest = argv[i + 1];
  if (!dest) throw new Error("--json needs a destination path");
  return dest;
}

/**
 * Domains this repository's owner controls, and the ONLY ones `--active` will
 * aim offensive traffic at.
 *
 * The product gates active probing on proven domain ownership
 * (lib/activeProbeGate.ts), and this script does not touch that gate. It is a
 * local test tool, so it carries its own hardcoded allowlist — the flag cannot
 * be pointed at somebody else's site by a typo or a stray argument. Extending
 * this means editing the list, deliberately.
 */
const OWNED_DOMAINS = new Set(["seclayer.app", "secscan.us"]);

function assertOwned(list: string[]): void {
  const foreign = list.filter((u) => {
    try {
      return !OWNED_DOMAINS.has(new URL(u).hostname.toLowerCase().replace(/^www\./, ""));
    } catch {
      return true;
    }
  });
  if (foreign.length) {
    console.error(
      "[live-scan] --active sends real attack traffic — injection payloads, path\n" +
        "            traversal and a port scan — so it is refused for anything\n" +
        "            outside the owned-domain allowlist in this file.\n\n" +
        `            Refused: ${foreign.join(", ")}\n` +
        `            Allowed: ${[...OWNED_DOMAINS].join(", ")}`,
    );
    process.exit(2);
  }
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const dest = jsonDest(argv);
  const active = argv.includes("--active");
  const targets = argv.filter(
    (a, i) => a !== "--json" && a !== "--active" && argv[i - 1] !== "--json",
  );
  const list = targets.length ? targets : DEFAULT_TARGETS;

  // --active is the only way this script sends offensive traffic. It must be
  // asked for explicitly, needs explicit targets, and is refused for anything
  // not owned. Without it the run is passive, which is what makes the twenty
  // third-party targets above legitimate to scan at all.
  if (active) {
    if (!targets.length) {
      console.error("[live-scan] --active needs explicit targets; it will not run the default third-party list.");
      process.exit(2);
    }
    assertOwned(list);
  }

  const collected: unknown[] = [];
  console.log(
    `[live-scan] ${active ? "ACTIVE (owned targets only)" : "Passive"} scan of ${list.length} target(s). ` +
      "Scrutinise every actionable finding.\n",
  );

  for (const url of list) {
    try {
      const started = Date.now();
      const r = await runScan(url, "deep", active, undefined, null);
      const actionable = r.vulnerabilities.filter((v) => v.severity !== "info");
      collected.push({
        url,
        finalUrl: r.finalUrl,
        statusCode: r.statusCode,
        server: r.server,
        tlsGrade: r.tlsGrade,
        technologies: r.technologies,
        pagesScanned: r.pagesScanned?.length ?? 0,
        renderedWithBrowser: r.renderedWithBrowser ?? false,
        elapsedMs: Date.now() - started,
        findings: r.vulnerabilities.map((v) => ({
          name: v.name,
          severity: v.severity,
          category: v.category,
          cweId: v.cweId ?? null,
          cvssScore: v.cvssScore ?? null,
          wstgId: v.wstgId ?? null,
          confidence: v.confidence ?? null,
          evidence: v.evidence ? String(v.evidence).slice(0, 600) : null,
        })),
      });
      console.log(`=== ${url} === ${r.vulnerabilities.length} findings, ${actionable.length} actionable`);
      for (const v of r.vulnerabilities) {
        const conf = v.confidence == null ? "--" : String(v.confidence);
        console.log(`  [${v.severity.toUpperCase().padEnd(8)}] conf=${conf.padStart(3)}  ${v.name}`);
        if (v.evidence) {
          console.log(`      ${String(v.evidence).replace(/\s+/g, " ").slice(0, 130)}`);
        }
      }
      console.log("");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      collected.push({ url, failed: message });
      console.log(`=== ${url} === SCAN FAILED: ${message}\n`);
    }
  }

  if (dest) {
    const { writeFileSync } = await import("node:fs");
    writeFileSync(dest, JSON.stringify({ scannedAt: new Date().toISOString(), results: collected }, null, 1));
    console.log(`[live-scan] Wrote ${dest} — ${collected.length} result(s).`);
  }
}

void main();
