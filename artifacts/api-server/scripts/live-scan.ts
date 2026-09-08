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

const DEFAULT_TARGETS = [
  "https://github.com",
  "https://www.cloudflare.com",
  "https://www.mozilla.org",
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

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const dest = jsonDest(argv);
  const targets = argv.filter((a, i) => a !== "--json" && argv[i - 1] !== "--json");
  const list = targets.length ? targets : DEFAULT_TARGETS;
  const collected: unknown[] = [];
  console.log(`[live-scan] Passive scan of ${list.length} target(s). Scrutinise every actionable finding.\n`);

  for (const url of list) {
    try {
      const started = Date.now();
      const r = await runScan(url, "deep", false, undefined, null);
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
