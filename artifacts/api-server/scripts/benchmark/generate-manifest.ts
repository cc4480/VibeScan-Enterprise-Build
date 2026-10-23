/**
 * Generate the PUBLIC fault manifest for the secscan-me benchmark target.
 *
 * This is the artefact that makes a public vulnerable target worth anything.
 * A scannable box with no published fault list is just a box; the manifest
 * is the denominator that lets a stranger run any scanner and score it
 * themselves without trusting our benchmark, our regexes, or our judges.
 *
 * Generated, not hand-written, from the SAME ground-truth.ts every other
 * scorer in this directory reads — so the publicly-promised fault count
 * cannot drift from what the app actually contains the way SCAN_CHECKS.md's
 * "50 passive runs" once drifted from the real total. See
 * check-index.mjs's own header for the shape of that failure.
 *
 * USAGE
 *   npx tsx artifacts/api-server/scripts/benchmark/generate-manifest.ts \
 *     [--app-version 1.0.0] [--out manifest.json]
 *
 * --app-version should be bumped whenever a route in vuln-fixture/src/server.ts
 * changes in a way that could move a fault (added, removed, or its behaviour
 * changed) — see the versioning note below.
 */
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { GROUND_TRUTH, CATEGORIES } from "./ground-truth";

// ESM: no __dirname. import.meta.url is the module's own location.
const HERE = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
const flag = (name: string, fallback: string): string => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1]! : fallback;
};

const APP_VERSION = flag("app-version", "0.1.0-unreleased");
// Default lands INSIDE the fixture's own source tree, not benchmark-out/, so
// GET /manifest.json (server.ts) can serve it straight off disk with no
// cross-package import from an app into this scripts/ directory.
const OUT = resolve(flag("out", resolve(HERE, "..", "..", "..", "vuln-fixture", "manifest.json")));

/**
 * A hash of the ground-truth CONTENT (ids, labels, categories — not the
 * regex matchers, which are scoring-tool-internal and not part of the public
 * claim). Two manifest builds from an unchanged ground-truth.ts always
 * produce the same hash, so a reader can tell whether "74 faults" today is
 * the same 74 as last week without diffing the whole file.
 */
function contentHash(): string {
  const stable = GROUND_TRUTH.map((f) => `${f.id}|${f.label}|${f.category}|${f.needs ?? ""}`).sort();
  return createHash("sha256").update(stable.join("\n")).digest("hex").slice(0, 16);
}

const manifest = {
  $schema: "https://secscan.me/manifest.schema.json",
  manifestVersion: "1.0",
  appVersion: APP_VERSION,
  contentHash: contentHash(),
  generatedAt: new Date().toISOString(),
  totalFaults: GROUND_TRUTH.length,
  categories: CATEGORIES,
  faults: GROUND_TRUTH.map((f) => ({
    id: f.id,
    label: f.label,
    category: f.category,
    // Present only for faults that need something beyond an anonymous
    // unauthenticated scan — stated up front so a scanner's non-detection of
    // these isn't misread as a miss. See ground-truth.ts's own note on this.
    ...(f.needs ? { requires: f.needs } : {}),
  })),
  notes: [
    "Every fault below is real and independently detectable: this is not a list of hints for a scanner that already knows the answer, it is the full ground truth a scanner's own report can be checked against.",
    "A fault tagged \"requires\" needs something an anonymous external scan does not have by default (credentials, an API spec, an out-of-band collector) — its absence from your scan's findings is not necessarily a miss.",
    "This manifest is generated from the same source file the project's own benchmark scorer reads (scripts/benchmark/ground-truth.ts). It cannot list a fault the app does not contain, or omit one the app does.",
    "contentHash changes only when a fault is added, removed, or its label/category changes — not on every rebuild. Compare it across two manifest fetches to confirm the target has not moved since you last scanned it.",
  ],
};

writeFileSync(OUT, JSON.stringify(manifest, null, 1) + "\n", "utf8");

console.log(`Wrote ${OUT}`);
console.log(`  appVersion:  ${manifest.appVersion}`);
console.log(`  contentHash: ${manifest.contentHash}`);
console.log(`  faults:      ${manifest.totalFaults}`);
