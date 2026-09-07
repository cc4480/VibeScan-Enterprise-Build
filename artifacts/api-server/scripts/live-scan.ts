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

async function main(): Promise<void> {
  const targets = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_TARGETS;
  console.log(`[live-scan] Passive scan of ${targets.length} target(s). Scrutinise every actionable finding.\n`);

  for (const url of targets) {
    try {
      const r = await runScan(url, "deep", false, undefined, null);
      const actionable = r.vulnerabilities.filter((v) => v.severity !== "info");
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
      console.log(`=== ${url} === SCAN FAILED: ${err instanceof Error ? err.message : String(err)}\n`);
    }
  }
}

void main();
