/**
 * "I fixed this": re-check one finding and say, honestly, whether it is gone.
 *
 * The re-check is an ordinary scan of the same site (origin "verify") judged against
 * the report that held the finding. The verdict comes from scanDiff.verdictFor, whose
 * one rule matters most: a finding that is gone is only "fixed" if the test that
 * raises it ran again. Otherwise it is "not_rechecked", which says so.
 *
 * A verification does not spend a free scan, plan scan or credit: what is being paid
 * for is knowing a fix worked, and charging for a scan that repeats one you already
 * bought would punish exactly the behaviour this exists to encourage. It is bounded
 * instead: ten a day per account, one at a time per finding, and only for findings in
 * your own reports.
 *
 * Findings that were found with a login cannot be re-checked this way: the login was
 * deleted when that scan ended. Those say so, and point at re-running the scan.
 */
import { db, findingVerificationsTable, reportsTable, scansTable } from "@workspace/db";
import { and, desc, eq, gte, sql } from "drizzle-orm";
import { enqueueScan } from "./queue";
import { verdictFor, type VerifyVerdict } from "./scanDiff";

export const DAILY_VERIFICATIONS = 10;
const DAY_MS = 24 * 60 * 60_000;

export type Verdict = VerifyVerdict | "pending" | "failed";

export interface StartResult {
  ok: true;
  verificationId: string;
  scanId: string;
}
export type StartOutcome = StartResult | { ok: false; status: 404 | 409 | 429 | 503; code: string; message: string };

type Stored = Record<string, unknown>;
const isRecord = (v: unknown): v is Stored => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : "");

/** The finding with this id in a stored report, or null. Scan-coverage notices are not findings. */
export function findingIn(data: unknown, findingId: string): { name: string; category: string; evidence: string } | null {
  const vulns = isRecord(data) && Array.isArray(data["vulnerabilities"]) ? data["vulnerabilities"] : [];
  const hit = vulns.find((v) => isRecord(v) && v["id"] === findingId && str(v["category"]) !== "Scan Coverage");
  return isRecord(hit) ? { name: str(hit["name"]), category: str(hit["category"]), evidence: str(hit["evidence"]) } : null;
}

export async function startVerification(input: { userId: string; userEmail: string; reportId: string; findingId: string }): Promise<StartOutcome> {
  const [report] = await db
    .select({ id: reportsTable.id, scanId: reportsTable.scanId, targetUrl: reportsTable.targetUrl, data: reportsTable.data })
    .from(reportsTable)
    .where(and(eq(reportsTable.id, input.reportId), eq(reportsTable.userId, input.userId)))
    .limit(1);
  // Someone else's report is indistinguishable from one that does not exist.
  if (!report || !findingIn(report.data, input.findingId)) return { ok: false, status: 404, code: "not_found", message: "That finding was not found in your report." };

  if (report.scanId) {
    const [scan] = await db.select({ at: scansTable.credentialsAuthorizedAt }).from(scansTable).where(eq(scansTable.id, report.scanId)).limit(1);
    if (scan?.at) {
      return { ok: false, status: 409, code: "needs_login", message: "This was found with a login, and that login was deleted when the scan ended. Run a new scan with your login to check it." };
    }
  }

  // The pending check, the daily count and the two inserts run as one transaction under a per-user
  // advisory lock, the same pattern as insertScanRow in lib/freeTrial.ts. Without it, parallel
  // requests all count the same rows and all insert, going past the daily cap.
  type Claim =
    | { kind: "existing"; verificationId: string; scanId: string }
    | { kind: "limit" }
    | { kind: "created"; verificationId: string; scanId: string };
  const claim: Claim = await db.transaction(async (tx): Promise<Claim> => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`verify-fix:${input.userId}`}))`);

    const [pending] = await tx
      .select({ id: findingVerificationsTable.id, scanId: findingVerificationsTable.scanId })
      .from(findingVerificationsTable)
      .where(and(eq(findingVerificationsTable.reportId, input.reportId), eq(findingVerificationsTable.findingId, input.findingId), eq(findingVerificationsTable.verdict, "pending")))
      .limit(1);
    if (pending) return { kind: "existing", verificationId: pending.id, scanId: pending.scanId };

    const [{ n } = { n: 0 }] = await tx
      .select({ n: sql<number>`count(*)::int` })
      .from(findingVerificationsTable)
      .where(and(eq(findingVerificationsTable.userId, input.userId), gte(findingVerificationsTable.createdAt, new Date(Date.now() - DAY_MS))));
    if (n >= DAILY_VERIFICATIONS) return { kind: "limit" };

    const [scan] = await tx
      .insert(scansTable)
      .values({ userId: input.userId, userEmail: input.userEmail, targetUrl: report.targetUrl, tier: "deep", status: "queued", origin: "verify" })
      .returning({ id: scansTable.id });
    const [row] = await tx
      .insert(findingVerificationsTable)
      .values({ userId: input.userId, reportId: input.reportId, findingId: input.findingId, scanId: scan!.id })
      .returning({ id: findingVerificationsTable.id });
    return { kind: "created", verificationId: row!.id, scanId: scan!.id };
  });

  if (claim.kind === "existing") return { ok: true, verificationId: claim.verificationId, scanId: claim.scanId };
  if (claim.kind === "limit") {
    return { ok: false, status: 429, code: "rate_limited", message: `You can check ${DAILY_VERIFICATIONS} fixes a day. Try again tomorrow, or run a full scan.` };
  }

  const { scanId, verificationId } = claim;
  try {
    await enqueueScan({ scanId, userId: input.userId, targetUrl: report.targetUrl, tier: "deep", verificationId });
  } catch {
    await db.update(scansTable).set({ status: "failed", error: "Could not be queued" }).where(eq(scansTable.id, scanId));
    await db.update(findingVerificationsTable).set({ verdict: "failed", completedAt: new Date() }).where(eq(findingVerificationsTable.id, verificationId));
    return { ok: false, status: 503, code: "unavailable", message: "Could not start the check. Please try again." };
  }
  return { ok: true, verificationId, scanId };
}

/** Called by the worker once the verification scan's report is saved. */
export async function completeVerification(verificationId: string, newReportData: unknown): Promise<Verdict | null> {
  const [v] = await db.select().from(findingVerificationsTable).where(eq(findingVerificationsTable.id, verificationId)).limit(1);
  if (!v) return null;
  const [previous] = await db.select({ data: reportsTable.data }).from(reportsTable).where(eq(reportsTable.id, v.reportId)).limit(1);
  const finding = previous ? findingIn(previous.data, v.findingId) : null;
  // The report it was judged against is gone: say it could not be checked rather than guess.
  const verdict: Verdict = previous && finding ? verdictFor(previous.data, newReportData, finding) : "failed";
  await db.update(findingVerificationsTable).set({ verdict, completedAt: new Date() }).where(eq(findingVerificationsTable.id, verificationId));
  return verdict;
}

/** The scan behind a verification failed, so the verification did too. A no-op for any other scan. */
export async function failVerificationForScan(scanId: string): Promise<void> {
  await db
    .update(findingVerificationsTable)
    .set({ verdict: "failed", completedAt: new Date() })
    .where(and(eq(findingVerificationsTable.scanId, scanId), eq(findingVerificationsTable.verdict, "pending")));
}

export interface VerificationStatus {
  findingId: string;
  verdict: Verdict;
  scanId: string;
  createdAt: Date;
  completedAt: Date | null;
}

/** The most recent verification of each finding in a report. */
export async function latestVerifications(userId: string, reportId: string): Promise<VerificationStatus[]> {
  const rows = await db
    .select({ findingId: findingVerificationsTable.findingId, verdict: findingVerificationsTable.verdict, scanId: findingVerificationsTable.scanId, createdAt: findingVerificationsTable.createdAt, completedAt: findingVerificationsTable.completedAt })
    .from(findingVerificationsTable)
    .where(and(eq(findingVerificationsTable.userId, userId), eq(findingVerificationsTable.reportId, reportId)))
    .orderBy(desc(findingVerificationsTable.createdAt));
  const seen = new Set<string>();
  return rows.filter((r) => (seen.has(r.findingId) ? false : (seen.add(r.findingId), true)));
}
