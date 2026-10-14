import { createHmac } from "node:crypto";
import { db, scansTable, usersTable, deletedAccountTrialsTable } from "@workspace/db";
import { and, count, eq, gte, lt, or, sql } from "drizzle-orm";

/** Either the pool or an open transaction. */
type Executor = Pick<typeof db, "select" | "insert" | "delete">;

/**
 * The free-scan allowance, and the one place that decides whether it is spent.
 *
 * Every account gets FREE_TRIAL_SCAN_LIMIT scans each calendar month (UTC),
 * renewing on the 1st. It used to be a one-time total, which gave someone who
 * tried the product no reason to come back; rivals give a few scans every month
 * (decision 2026-09-24). A plan or credits are spent only after the month's free
 * scans (see chargeScan in billing.ts), so a paying customer is never capped here.
 *
 * This lives in lib/ rather than in the scans route because the monitor routes
 * need the identical gate — subscribing schedules recurring scans, and an
 * on-demand rescan is a scan somebody asked for, so leaving those ungated made
 * monitoring an unlimited-scan bypass around the cap.
 */
export const FREE_TRIAL_SCAN_LIMIT = Number(process.env["FREE_TRIAL_SCAN_LIMIT"] ?? 3);

// Two wordings, chosen by whether this deployment can take payment. Telling
// someone to buy what cannot be bought is the dead end this message used to be
// the other way round ("coming soon") once checkout existed.
export const TRIAL_LIMIT_MESSAGE = process.env["STRIPE_SECRET_KEY"]
  ? `You've used this month's ${FREE_TRIAL_SCAN_LIMIT} free scans. They renew on the 1st, or subscribe for unlimited scans to keep scanning now.`
  : `You've used this month's ${FREE_TRIAL_SCAN_LIMIT} free scans. They renew on the 1st of next month.`;

/** Midnight UTC on the 1st of the current month: the start of this month's allowance. */
export function freeScanPeriodStart(now: Date = new Date()): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

/** When the free scans next renew: midnight UTC on the 1st of next month. */
export function freeScansResetAt(now: Date = new Date()): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
}

/**
 * Sent alongside the message so the client can recognise this specific refusal
 * without matching on prose. The copy above is written for a person and will be
 * reworded; a UI keyed to it would break silently and show a generic error at
 * the exact moment someone was ready to pay.
 */
export const TRIAL_LIMIT_CODE = "trial_exhausted";

/**
 * Scans this user started themselves this calendar month (UTC).
 *
 * Monitor rows are excluded deliberately. The scheduler rescans on its own
 * timetable — as often as every 3 days at grade F, plus an hourly CVE sweep — so
 * counting those would spend a subscriber's allowance on scans they never asked
 * for and then lock them out with a message claiming they used their free
 * scans themselves. `scans.origin` is what separates the two.
 */
export async function trialScansUsedBy(userId: string, now: Date = new Date(), exec: Executor = db): Promise<number> {
  const [row] = await exec
    .select({ n: count() })
    .from(scansTable)
    // A scan the user started, OR any scan paid for with a free scan — so a
    // non-subscriber's monitor baseline and "Scan now" draw on the same two
    // free scans as the scan form, instead of being a way around them.
    .where(
      and(
        eq(scansTable.userId, userId),
        or(eq(scansTable.origin, "user"), eq(scansTable.paidWith, "free")),
        gte(scansTable.createdAt, freeScanPeriodStart(now)),
      ),
    );
  return (row?.n ?? 0) + (await carriedUsage(userId, now, exec));
}

/**
 * A keyed hash of an address, for remembering a deleted account's usage without keeping the
 * address. Keyed with ENCRYPTION_KEY so the table cannot be matched against a list of emails.
 */
export function trialEmailKey(email: string): string {
  return createHmac("sha256", process.env["ENCRYPTION_KEY"] ?? "secscan-trial").update(email.trim().toLowerCase()).digest("hex");
}

/** Drop remembered usage from months that are over. Run daily, so nothing outlives the month it applies to. */
export async function purgeStaleTrialUsage(): Promise<void> {
  await db.delete(deletedAccountTrialsTable).where(lt(deletedAccountTrialsTable.periodStart, freeScanPeriodStart()));
}

/** Free scans an earlier, since-deleted account at this address already used this month. */
async function carriedUsage(userId: string, now: Date, exec: Executor): Promise<number> {
  const [user] = await exec.select({ email: usersTable.email }).from(usersTable).where(eq(usersTable.id, userId));
  if (!user?.email) return 0;
  const [row] = await exec
    .select({ used: deletedAccountTrialsTable.scansUsed, periodStart: deletedAccountTrialsTable.periodStart })
    .from(deletedAccountTrialsTable)
    .where(eq(deletedAccountTrialsTable.emailHash, trialEmailKey(user.email)));
  return row && row.periodStart.getTime() === freeScanPeriodStart(now).getTime() ? row.used : 0;
}

/**
 * Called as an account is deleted, inside the deletion's transaction and before its rows go: keeps
 * how many free scans this month's allowance has already spent, so deleting and registering again
 * does not reset it. Earlier months' entries are dropped, since they no longer affect anything.
 */
export async function carryTrialUsage(tx: Executor, userId: string, email: string | null | undefined): Promise<void> {
  const now = new Date();
  await tx.delete(deletedAccountTrialsTable).where(lt(deletedAccountTrialsTable.periodStart, freeScanPeriodStart(now)));
  if (!email) return;
  const used = await trialScansUsedBy(userId, now, tx);
  if (used <= 0) return;
  await tx
    .insert(deletedAccountTrialsTable)
    .values({ emailHash: trialEmailKey(email), periodStart: freeScanPeriodStart(now), scansUsed: Math.min(used, FREE_TRIAL_SCAN_LIMIT) })
    .onConflictDoUpdate({ target: deletedAccountTrialsTable.emailHash, set: { periodStart: freeScanPeriodStart(now), scansUsed: Math.min(used, FREE_TRIAL_SCAN_LIMIT) } });
}

export async function trialScansExhausted(userId: string): Promise<boolean> {
  return (await trialScansUsedBy(userId)) >= FREE_TRIAL_SCAN_LIMIT;
}

/** Thrown by insertScanRow when the free allowance ran out between chargeScan and the insert. */
export class TrialExhaustedError extends Error {
  constructor() {
    super(TRIAL_LIMIT_CODE);
    this.name = "TrialExhaustedError";
  }
}

/** Thrown by insertScanRow when the account's daily scan limit was reached by requests arriving together. */
export class DailyLimitError extends Error {
  constructor() {
    super("daily_limit");
    this.name = "DailyLimitError";
  }
}

/**
 * Create a scan row, holding the free allowance and the daily limit to their limits.
 *
 * chargeScan decides "free" by counting scan rows, and the daily limit is a count too, but the row
 * is written some time later, so requests arriving together all counted the same rows and all
 * inserted. Where either limit applies this takes a per-user advisory lock, counts again, and
 * inserts under that lock; the next request for the same user waits for the commit and counts this
 * row. The lock is transaction-scoped, so it cannot outlive the insert, and per user, so no one
 * else waits.
 *
 * Throws TrialExhaustedError or DailyLimitError. For a free scan nothing was taken, so there is
 * nothing to refund; for a credit or included scan the caller refunds, as for any other refusal.
 */
export async function insertScanRow(
  values: typeof scansTable.$inferInsert,
  opts: { dailyMax?: number } = {},
): Promise<typeof scansTable.$inferSelect> {
  const isFree = values.paidWith === "free";
  if (!isFree && opts.dailyMax === undefined) {
    const [row] = await db.insert(scansTable).values(values).returning();
    return row!;
  }
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`free-scan:${values.userId}`}))`);
    if (isFree && (await trialScansUsedBy(values.userId, new Date(), tx)) >= FREE_TRIAL_SCAN_LIMIT) {
      throw new TrialExhaustedError();
    }
    if (opts.dailyMax !== undefined) {
      const since = new Date(Date.now() - 24 * 60 * 60_000);
      const [today] = await tx
        .select({ n: count() })
        .from(scansTable)
        .where(and(eq(scansTable.userId, values.userId), gte(scansTable.createdAt, since)));
      if ((today?.n ?? 0) >= opts.dailyMax) throw new DailyLimitError();
    }
    const [row] = await tx.insert(scansTable).values(values).returning();
    return row!;
  });
}
