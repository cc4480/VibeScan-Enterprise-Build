import { db, scansTable } from "@workspace/db";
import { and, count, eq, or } from "drizzle-orm";

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
export const FREE_TRIAL_SCAN_LIMIT = Number(process.env["FREE_TRIAL_SCAN_LIMIT"] ?? 2);

// Two wordings, chosen by whether this deployment can take payment. Telling
// someone to buy what cannot be bought is the dead end this message used to be
// the other way round ("coming soon") once checkout existed.
export const TRIAL_LIMIT_MESSAGE = process.env["STRIPE_SECRET_KEY"]
  ? `You've used all ${FREE_TRIAL_SCAN_LIMIT} free scans. Subscribe to SecScan Pro or buy scan credits to keep scanning.`
  : `You've used all ${FREE_TRIAL_SCAN_LIMIT} free scans. Paid scans are coming soon — check back shortly.`;

/**
 * Sent alongside the message so the client can recognise this specific refusal
 * without matching on prose. The copy above is written for a person and will be
 * reworded; a UI keyed to it would break silently and show a generic error at
 * the exact moment someone was ready to pay.
 */
export const TRIAL_LIMIT_CODE = "trial_exhausted";

/**
 * Scans this user started themselves, across all time.
 *
 * Monitor rows are excluded deliberately. The scheduler rescans on its own
 * timetable — as often as every 3 days at grade F, plus an hourly CVE sweep — so
 * counting those would spend a subscriber's allowance on scans they never asked
 * for and then lock them out with a message claiming they used their free
 * scans themselves. `scans.origin` is what separates the two.
 */
export async function trialScansUsedBy(userId: string): Promise<number> {
  const [row] = await db
    .select({ n: count() })
    .from(scansTable)
    // A scan the user started, OR any scan paid for with a free scan — so a
    // non-subscriber's monitor baseline and "Scan now" draw on the same two
    // free scans as the scan form, instead of being a way around them.
    .where(and(eq(scansTable.userId, userId), or(eq(scansTable.origin, "user"), eq(scansTable.paidWith, "free"))));
  return row?.n ?? 0;
}

export async function trialScansExhausted(userId: string): Promise<boolean> {
  return (await trialScansUsedBy(userId)) >= FREE_TRIAL_SCAN_LIMIT;
}
