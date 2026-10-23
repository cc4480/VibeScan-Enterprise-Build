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
import { SOURCE_TEST_NAME, type TestRecord } from "./testLedger";
import { CATALOG_REPO } from "./checkCatalogRepo";
import { NOT_THE_PROJECTS_OWN } from "./repoFinding";
import { isEnvFilePath } from "./repoCheckCode";

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
  // A repository scan runs its groups inside the one ledger test that reads the source, so that test running means each group ran.
  if (out.has(SOURCE_TEST_NAME)) for (const t of CATALOG_REPO) out.add(t.test);
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

  // Whether this scan read only part of the repository (the coverage notice is filtered out of `now`, so read raw).
  const partialNotice = rawVulnerabilities(current.data).find((v) => str(v["name"]) === REPO_PARTIAL_NOTICE);
  const repoPartial = partialNotice !== undefined;
  // The files a partial scan did open, when it recorded them (scans from before that was added did not).
  const listed = partialNotice?.["repoFilesRead"];
  const filesRead = Array.isArray(listed) ? new Set(listed.filter((p): p is string => typeof p === "string")) : null;

  const fixed: FindingRef[] = [];
  const notRechecked: FindingRef[] = [];
  for (const v of before.vulnerabilities) {
    if (nowFp.has(fp(v))) continue;
    const test = testFor(str(v["name"]));
    const checkedAgain = haveLedgers && (test ? ranNow.has(test) : noLongerRun.length === 0) && repoFileReadAgain(v, repoPartial, filesRead);
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

/** The repository scan's notice that it read only part of the repository (repoScan.ts). */
const REPO_PARTIAL_NOTICE = "GitHub source scan covered only part of the repository";

function rawVulnerabilities(data: unknown): Array<Record<string, unknown>> {
  const d = (typeof data === "object" && data !== null ? data : {}) as Record<string, unknown>;
  return Array.isArray(d["vulnerabilities"]) ? (d["vulnerabilities"] as Array<Record<string, unknown>>).filter((v) => typeof v === "object" && v !== null) : [];
}

/**
 * For a finding read from a repository's source, the test running again is not enough to call it fixed: the FILE has
 * to have been read again. It was not when the repository scan now leaves that file out (a test fixture, say, after
 * the rule changed), or when this scan read only part of the repository, so nobody can say the file was opened.
 * Findings not from a repository are unaffected. Exported for tests.
 */
export function repoFileReadAgain(finding: Record<string, unknown>, repoPartial: boolean, filesRead: ReadonlySet<string> | null = null): boolean {
  const evidence = str(finding["evidence"]);
  if (!evidence.startsWith("Repository: ")) return true;
  const file = /^File: (.+)$/m.exec(evidence)?.[1]?.trim() ?? "";
  if (file && file !== "(repository)" && NOT_THE_PROJECTS_OWN.test(file) && !isEnvFilePath(file)) return false;
  if (!repoPartial) return true;
  // A partial scan still opened some files: if this finding's file is one of them, it was read again.
  return filesRead !== null && file !== "" && file !== "(repository)" && filesRead.has(file);
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

export type VerifyVerdict = "fixed" | "still_present" | "not_rechecked";

/**
 * The verdict on ONE finding after someone says they fixed it and a new scan has run.
 * Same rule as the comparison above, applied to a single finding:
 *
 *   still in the new scan                                   → still_present
 *   gone, and the test that raises it ran again             → fixed
 *   gone, but that test did not run (or nothing can tell)   → not_rechecked
 *
 * "Gone" alone never counts as fixed: a finding also disappears when a test is
 * skipped, fails, or is blocked. not_rechecked tells the person exactly that.
 */
export function verdictFor(
  previousData: unknown,
  currentData: unknown,
  finding: { name: string; category: string; evidence?: string | null },
): VerifyVerdict {
  const before = side(previousData);
  const now = side(currentData);
  const key = findingFingerprint(finding.category, finding.name, finding.evidence || null);
  if (now.vulnerabilities.some((v) => fp(v) === key)) return "still_present";

  const test = testFor(finding.name);
  const ranNow = ranKeys(now.tests);
  const ranBefore = ranKeys(before.tests);
  if (test) return ranNow.has(test) ? "fixed" : "not_rechecked";
  // An unmappable finding is judged by the whole ledger: fixed only if every test that ran before ran again.
  const everythingRanAgain = before.tests.length > 0 && now.tests.length > 0 && [...ranBefore].every((k) => ranNow.has(k));
  return everythingRanAgain ? "fixed" : "not_rechecked";
}
