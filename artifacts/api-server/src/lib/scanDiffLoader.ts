/**
 * Finds the scan a report should be compared with, and compares them (lib/scanDiff.ts
 * holds the rules). The previous scan is this user's most recent earlier report of the
 * SAME site (canonical URL: scheme and host case, trailing slash ignored). Nothing is
 * stored: it is computed when a report is read or an email is built, so it also works
 * for reports made before this existed, and a report's history can never disagree with
 * the reports themselves.
 */
import { db, reportsTable, scansTable } from "@workspace/db";
import { and, desc, eq, inArray, lt } from "drizzle-orm";
import { canonicalizeTargetUrl } from "./fingerprint";
import { diffScans, type ScanChanges } from "./scanDiff";

/** How far back to look for an earlier scan of the same site. */
const LOOKBACK = 25;

export interface CurrentReport {
  scanId: string | null;
  targetUrl: string;
  scannedAt: Date;
  data: unknown;
}

export async function changesForReport(userId: string, current: CurrentReport): Promise<ScanChanges | null> {
  const wanted = canonicalizeTargetUrl(current.targetUrl);
  const earlier = await db
    .select({ scanId: reportsTable.scanId, targetUrl: reportsTable.targetUrl, scannedAt: reportsTable.scannedAt, data: reportsTable.data })
    .from(reportsTable)
    .where(and(eq(reportsTable.userId, userId), lt(reportsTable.scannedAt, current.scannedAt)))
    .orderBy(desc(reportsTable.scannedAt))
    .limit(LOOKBACK);
  const previous = earlier.find((r) => canonicalizeTargetUrl(r.targetUrl) === wanted);
  if (!previous) return null;

  // A scan made with a login sees more of a site than one without; say so rather than compare silently.
  const authorised = await db
    .select({ id: scansTable.id, at: scansTable.credentialsAuthorizedAt })
    .from(scansTable)
    .where(inArray(scansTable.id, [previous.scanId, current.scanId].filter((id): id is string => typeof id === "string")));
  const credentialed = (id: string | null) => authorised.some((s) => s.id === id && s.at !== null);

  return diffScans(
    { scanId: previous.scanId, scannedAt: previous.scannedAt, data: previous.data, credentialed: credentialed(previous.scanId) },
    { data: current.data, credentialed: credentialed(current.scanId) },
  );
}
