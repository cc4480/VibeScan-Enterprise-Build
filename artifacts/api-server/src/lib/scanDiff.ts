/**
 * What changed between two scans of the same site: new findings, fixed findings,
 * and what could not be compared.
 *
 * The rule that keeps this honest: a finding disappearing is not the same as it being
 * fixed. If the test that would have raised it did not run this time (the domain was
 * unverified, a probe failed, a login expired), the finding simply was not looked for,
 * and calling it fixed would tell someone a hole is closed when nobody checked.
 *
 *   gone finding, its test ran again        → fixed
 *   gone finding, its test did not run now  → not re-checked
 *   new finding, its test ran last time too → new
 *   new finding, its test is newly run      → first seen (it could have been there before)
 *
 * A finding's test is found through the check catalog. When a finding cannot be mapped
 * to a test, it is judged by the whole ledger: it counts as fixed (or new) only if
 * every test that ran on one scan also ran on the other, so no test could have been
 * the one that differed.
 *
 * Scan-coverage notices ("active testing was skipped") are not security findings and
 * are never diffed.
 */
import { CATALOG, catalogFor } from "./checkCatalog";
import { findingFingerprint } from "./fingerprint";
import type { TestRecord } from "./testLedger";

export interface FindingRef {
  name: string;
  severity: string;
  category: string;
}

export interface ScanChanges {
  since: { scanId: string | null; scannedAt: string | null };
  /** Present in both scans. */
  unchanged: number;
  /** In this scan only, from a test that also ran last time. */
  added: FindingRef[];
  /** In this scan only, but its test did not run last time, so it may have been there all along. */
  firstSeen: FindingRef[];
  /** In the last scan only, and its test ran again: really gone. */
  fixed: FindingRef[];
  /** In the last scan only, but its test did not run this time: not checked, so not fixed. */
  notRechecked: FindingRef[];
  /** Tests that ran now and not before, and the reverse: why some of the above are labelled as they are. */
  newlyRun: string[];
  noLongerRun: string[];
  /** A login was used on one scan and not the other: they saw different parts of the site. */
  differentAccess: boolean;
}

interface Side {
  vulnerabilities: Array<Record<string, unknown>>;
  tests: TestRecord[];
}

const str = (v: unknown) => (typeof v === "string" ? v : "");
const isNotice = (v: Record<string, unknown>) => str(v["category"]) === "Scan Coverage";

function side(data: unknown): Side {
  const d = (typeof data === "object" && data !== null ? data : {}) as Record<string, unknown>;
  const vulns = Array.isArray(d["vulnerabilities"]) ? (d["vulnerabilities"] as Array<Record<string, unknown>>).filter((v) => typeof v === "object" && v !== null && !isNotice(v)) : [];
  const tests = Array.isArray(d["tests"]) ? (d["tests"] as TestRecord[]).filter((t) => t && typeof t.name === "string") : [];
  return { vulnerabilities: vulns, tests };
}

/** The catalog test key that raises a finding with this name, or null when it cannot be told. Exported for tests. */
export function testFor(findingName: string): string | null {
  let best: { test: string; len: number } | null = null;
  for (const t of CATALOG) {
    for (const c of t.checks) {
      const needle = c.needle ?? c.name;
      // Expressions like "name: p.name" are not text a finding name contains.
      if (needle.includes("${") || needle.startsWith("name:")) continue;
      if (findingName.includes(needle) && (!best || needle.length > best.len)) best = { test: t.test, len: needle.length };
    }
  }
  return best?.test ?? null;
}

const ranKeys = (tests: TestRecord[]): Set<string> => {
  const out = new Set<string>();
  for (const t of tests) if (t.status === "ran") out.add(catalogFor(t.name)?.test ?? t.name);
  return out;
};

const ref = (v: Record<string, unknown>): FindingRef => ({ name: str(v["name"]), severity: str(v["severity"]).toLowerCase(), category: str(v["category"]) });
const fp = (v: Record<string, unknown>) => findingFingerprint(str(v["category"]), str(v["name"]), str(v["evidence"]) || null);

export function diffScans(
  previous: { scanId: string | null; scannedAt: Date | string | null; data: unknown; credentialed?: boolean },
  current: { data: unknown; credentialed?: boolean },
): ScanChanges {
  const before = side(previous.data);
  const now = side(current.data);
  const ranBefore = ranKeys(before.tests);
  const ranNow = ranKeys(now.tests);

  const newlyRun = [...ranNow].filter((k) => !ranBefore.has(k)).sort();
  const noLongerRun = [...ranBefore].filter((k) => !ranNow.has(k)).sort();
  // With no ledger on either side (an old report) nothing can be ruled out, so nothing is called fixed.
  const haveLedgers = before.tests.length > 0 && now.tests.length > 0;

  const beforeFp = new Set(before.vulnerabilities.map(fp));
  const nowFp = new Set(now.vulnerabilities.map(fp));

  const added: FindingRef[] = [];
  const firstSeen: FindingRef[] = [];
  for (const v of now.vulnerabilities) {
    if (beforeFp.has(fp(v))) continue;
    const test = testFor(str(v["name"]));
    const couldHaveExisted = test ? !ranBefore.has(test) : newlyRun.length > 0 || !haveLedgers;
    (couldHaveExisted ? firstSeen : added).push(ref(v));
  }

  const fixed: FindingRef[] = [];
  const notRechecked: FindingRef[] = [];
  for (const v of before.vulnerabilities) {
    if (nowFp.has(fp(v))) continue;
    const test = testFor(str(v["name"]));
    const checkedAgain = haveLedgers && (test ? ranNow.has(test) : noLongerRun.length === 0);
    (checkedAgain ? fixed : notRechecked).push(ref(v));
  }

  const bySeverity = (a: FindingRef, b: FindingRef) => order(a.severity) - order(b.severity) || a.name.localeCompare(b.name);
  return {
    since: { scanId: previous.scanId, scannedAt: previous.scannedAt ? new Date(previous.scannedAt).toISOString() : null },
    unchanged: now.vulnerabilities.filter((v) => beforeFp.has(fp(v))).length,
    added: added.sort(bySeverity),
    firstSeen: firstSeen.sort(bySeverity),
    fixed: fixed.sort(bySeverity),
    notRechecked: notRechecked.sort(bySeverity),
    newlyRun,
    noLongerRun,
    differentAccess: Boolean(previous.credentialed) !== Boolean(current.credentialed),
  };
}

const ORDER = ["critical", "high", "medium", "low", "info"];
const order = (s: string) => (ORDER.includes(s) ? ORDER.indexOf(s) : ORDER.length);

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** "20 Sep", the same on every machine (toLocaleDateString differs by ICU version). UTC, like the stored time. */
export function shortDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}

/** One line for an email or a status: "2 new, 3 fixed since your last scan (20 Sep)". Empty when nothing changed. */
export function summariseChanges(c: ScanChanges): string {
  const parts: string[] = [];
  const newOnes = c.added.length + c.firstSeen.length;
  if (newOnes) parts.push(`${newOnes} new`);
  if (c.fixed.length) parts.push(`${c.fixed.length} fixed`);
  if (c.notRechecked.length) parts.push(`${c.notRechecked.length} not re-checked`);
  if (parts.length === 0) return "";
  const when = c.since.scannedAt ? ` (${shortDate(c.since.scannedAt)})` : "";
  return `${parts.join(", ")} since your last scan${when}`;
}
