/** Guards and lookups shared by the checkout routes. */
import { db, billingSubscriptionsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { CREDITS_MAP, PACKS_ON_SALE } from "../lib/stripe";

/**
 * Refuse checkout to an identity that has no email — the browser-only accounts
 * the site still creates for first-time visitors.
 *
 * Anything bought on one lives only as long as that browser's storage: clear
 * it, switch device, and the paid credits or subscription are unreachable, with
 * no address to recover them or to cancel a subscription that keeps charging.
 * Registering converts the same row in place (routes/account.ts), so asking
 * first loses the visitor nothing — their free scans come with them.
 */
export function refuseUnregistered(req: { user: { email?: string | null } }, res: { status: (n: number) => { json: (b: unknown) => void } }): boolean {
  if (req.user.email) return false;
  res.status(403).json({
    error: "Create an account before buying, so your purchase isn't tied to this browser.",
    code: "account_required",
  });
  return true;
}

/** The packs that may be bought. Anything outside CREDITS_MAP grants nothing, so it is excluded here too. */
export const BUYABLE = PACKS_ON_SALE.filter((tier) => tier in CREDITS_MAP);

/** The user's plan row, or null. */
export async function currentPlan(userId: string) {
  const [row] = await db
    .select()
    .from(billingSubscriptionsTable)
    .where(eq(billingSubscriptionsTable.userId, userId))
    .limit(1);
  return row ?? null;
}
