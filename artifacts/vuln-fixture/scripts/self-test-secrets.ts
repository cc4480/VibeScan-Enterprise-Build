/**
 * Regression check: every pattern in secret-pattern-data.ts must be REPORTED for SECRETS_JS, by the
 * scanner's own matching (scanContent: pattern, validate and the placeholder filter), not a
 * re-derived copy of it. A planted value that drifted out of shape, or went back to being filler
 * the scanner ignores on purpose (a run of zeros), fails here instead of silently going unverified.
 */
import { SECRET_PATTERNS } from "../../api-server/src/lib/secret-pattern-data.js";
import { scanContent } from "../../api-server/src/lib/jsScanner.js";
import { SECRETS_JS } from "../src/secrets.js";

const reported = new Set(scanContent(SECRETS_JS).map((f) => f.pattern.name));
let missed = 0;
for (const p of SECRET_PATTERNS) {
  if (reported.has(p.name)) {
    console.log(`[hit]  ${p.name}`);
  } else {
    missed++;
    console.log(`[MISS] ${p.name}  \u2014  not reported (no match, rejected by validate, or dropped as a placeholder)`);
  }
}
console.log(`\n${SECRET_PATTERNS.length - missed}/${SECRET_PATTERNS.length} patterns reported.`);
process.exit(missed > 0 ? 1 : 0);
