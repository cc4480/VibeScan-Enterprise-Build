/**
 * Regression check: every regex in secret-pattern-data.ts must match
 * something in SECRETS_JS, importing the real regex source rather than
 * re-deriving it. Faster than a full scan for catching a planted value that
 * drifted out of shape (e.g. a rename that breaks an exact-length regex).
 */
import { SECRET_PATTERNS } from "../../api-server/src/lib/secret-pattern-data.js";
import { SECRETS_JS } from "../src/secrets.js";

let missed = 0;
for (const p of SECRET_PATTERNS) {
  const hit = p.pattern.exec(SECRETS_JS);
  if (!hit) {
    missed++;
    console.log(`[MISS] ${p.name}  —  ${p.pattern}`);
  } else if (p.isPlaceholder?.(hit[0])) {
    missed++;
    console.log(`[SUPPRESSED as placeholder] ${p.name}`);
  } else {
    console.log(`[hit]  ${p.name}`);
  }
}
console.log(`\n${SECRET_PATTERNS.length - missed}/${SECRET_PATTERNS.length} patterns matched.`);
process.exit(missed > 0 ? 1 : 0);
