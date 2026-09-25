import { db, scansTable } from "@workspace/db";
import { and, count, eq, gte, or } from "drizzle-orm";

/**
 * The free-scan allowance, and the one place that decides whether it is spent.
 *
 * Every account gets FREE_TRIAL_SCAN_LIMIT scans each calendar month (UTC),
 * renewing on the 1st. It used to be a one-time total, which gave someone who
 * tried the product no reason to come back; rivals give a few scans every month
 * (decision 2026-09-24). Plans and credits are spent only after the month's free
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
  ? `You've used this month's ${FREE_TRIAL_SCAN_LIMIT} free scans. They renew on the 1st, or subscribe or buy scan credits to keep scanning now.`
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
export async function trialScansUsedBy(userId: string, now: Date = new Date()): Promise<number> {
  const [row] = await db
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
  return row?.n ?? 0;
}

export async function trialScansExhausted(userId: string): Promise<boolean> {
  return (await trialScansUsedBy(userId)) >= FREE_TRIAL_SCAN_LIMIT;
}
