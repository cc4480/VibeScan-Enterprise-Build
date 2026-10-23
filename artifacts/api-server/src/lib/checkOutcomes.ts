/**
 * What became of each check inside a test, from what the ledger recorded.
 *
 * A ledger record says a TEST ran and how many findings it raised. Showing the
 * checks inside it means saying, for each one, whether it was clear, fired, or
 * could not be attributed. The rule is that a check is only ever shown as clear
 * when that is certain:
 *
 *   test did not run                      → not_run (skipped or failed, never a pass)
 *   test ran, raised nothing              → clear   (every check in it evaluated clean)
 *   test ran, findings all matched checks → those are "finding", the rest "clear"
 *   test ran, findings we cannot place    → "checked": it ran, but we will not claim clear
 *
 * Matching uses a check's literal name. Checks whose names are built from data
 * (a path from a table, a package version) have no literal to match; when exactly
 * one such check is left and unmatched findings remain, they belong to it.
 */
import { catalogFor } from "./checkCatalog";
import type { CatalogCheck, CheckSeverity } from "./checkCatalogTypes";
import type { TestRecord } from "./testLedger";

export type CheckOutcome = "clear" | "finding" | "checked" | "not_run";

export interface ResolvedCheck {
  name: string;
  severity: CheckSeverity;
  outcome: CheckOutcome;
  /** Set when the check's category differs from its test's. */
  category?: string;
}

export interface ResolvedTest extends TestRecord {
  /** Finding category, for colour. Null for a step with no findings of its own. */
  category: string | null;
  checks: ResolvedCheck[];
}

/** A needle that is a real piece of a finding name, not a source expression. */
const hasLiteral = (c: CatalogCheck) => {
  const needle = c.needle ?? c.name;
  return !needle.includes("${") && !needle.startsWith("name:");
};

export function resolveTest(record: TestRecord): ResolvedTest {
  const entry = catalogFor(record.name);
  if (!entry) return { ...record, category: null, checks: [] };

  const wrap = (c: CatalogCheck, outcome: CheckOutcome): ResolvedCheck => ({
    name: c.name,
    severity: c.severity,
    outcome,
    ...(c.category ? { category: c.category } : {}),
  });

  if (record.status !== "ran") {
    return { ...record, category: entry.category, checks: entry.checks.map((c) => wrap(c, "not_run")) };
  }
  if (record.findings === 0) {
    return { ...record, category: entry.category, checks: entry.checks.map((c) => wrap(c, "clear")) };
  }

  const found = record.found ?? [];
  const consumed = new Set<number>();
  const fired = new Set<CatalogCheck>();
  for (const c of entry.checks) {
    if (!hasLiteral(c)) continue;
    const needle = c.needle ?? c.name;
    found.forEach((f, i) => {
      if (f.includes(needle)) {
        consumed.add(i);
        fired.add(c);
      }
    });
  }

  // Findings we could not tie to a named check, and the checks with no name to tie them to.
  const unplaced = found.length < record.findings || consumed.size < found.length;
  const unnamed = entry.checks.filter((c) => !hasLiteral(c));

  const outcomeOf = (c: CatalogCheck): CheckOutcome => {
    if (fired.has(c)) return "finding";
    if (!unplaced) return "clear";
    // By elimination, and only when every finding name is known: otherwise a finding we cannot
    // see could be the one that fired, and "checked" is all we can honestly say.
    if (unnamed.length === 1 && unnamed[0] === c && found.length === record.findings) return "finding";
    return "checked";
  };
  return { ...record, category: entry.category, checks: entry.checks.map((c) => wrap(c, outcomeOf(c))) };
}
