import { db, scansTable } from "@workspace/db";
import { and, count, eq } from "drizzle-orm";

/**
 * The free-scan allowance, and the one place that decides whether it is spent.
 *
 * Temporary, pending checkout: everyone — anonymous or registered — gets a
 * fixed number of scans in total, not per day, so people can try the product
 * before paying. It is meant to be replaced by pack_5 purchases (see PRICE_MAP
 * in lib/stripe.ts) once Checkout Session creation exists. Delete this module
 * when that ships rather than raising the number: a paying customer must not be
 * capped by it.
 *
 * This lives in lib/ rather than in the scans route because the monitor routes
 * need the identical gate — subscribing schedules recurring scans, and an
 * on-demand rescan is a scan somebody asked for, so leaving those ungated made
 * monitoring an unlimited-scan bypass around the cap.
 */
export const FREE_TRIAL_SCAN_LIMIT = Number(process.env["FREE_TRIAL_SCAN_LIMIT"] ?? 5);

export const TRIAL_LIMIT_MESSAGE =
  `You've used all ${FREE_TRIAL_SCAN_LIMIT} free scans. Paid scans are ` +
  "coming soon — check back shortly.";

/**
 * Scans this user started themselves, across all time.
 *
 * Monitor rows are excluded deliberately. The scheduler rescans on its own
 * timetable — as often as every 3 days at grade F, plus a daily CVE sweep — so
 * counting those would spend a subscriber's allowance on scans they never asked
 * for and then lock them out with a message claiming they used all five
 * themselves. `scans.origin` is what separates the two.
 */
export async function trialScansUsedBy(userId: string): Promise<number> {
  const [row] = await db
    .select({ n: count() })
    .from(scansTable)
    .where(and(eq(scansTable.userId, userId), eq(scansTable.origin, "user")));
  return row?.n ?? 0;
}

export async function trialScansExhausted(userId: string): Promise<boolean> {
  return (await trialScansUsedBy(userId)) >= FREE_TRIAL_SCAN_LIMIT;
}
