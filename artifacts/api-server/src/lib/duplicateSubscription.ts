/**
 * Undo a second subscription that was paid for while one was already live.
 *
 * subscriptions.ts refuses to write it onto the plan row (hasOtherLiveSubscription).
 * That alone would leave the customer paying for a plan we never activated, so
 * this ends it at Stripe: cancel it with no further invoices, then refund what
 * it charged. Runs after the database commit, and never throws: a Stripe outage
 * here must not fail the webhook and roll back the event that recorded the
 * duplicate. It logs loudly instead, because an unrefunded duplicate is money
 * that has to be returned by hand.
 */
import { stripe } from "./stripe";
import { logger } from "./logger";

const idOf = (v: string | { id: string } | null | undefined): string | null =>
  typeof v === "string" ? v : (v?.id ?? null);

export async function dropDuplicateSubscription(stripeSubscriptionId: string): Promise<void> {
  if (!stripe) return;
  const log = logger.child({ stripeSubscriptionId });
  try {
    const sub = await stripe.subscriptions.retrieve(stripeSubscriptionId);
    if (sub.status !== "canceled") {
      await stripe.subscriptions.cancel(stripeSubscriptionId, { invoice_now: false, prorate: false });
    }

    const invoiceId = idOf(sub.latest_invoice);
    if (!invoiceId) return;
    const payments = await stripe.invoicePayments.list({ invoice: invoiceId, status: "paid" });
    for (const p of payments.data) {
      const paymentIntent = idOf(p.payment.payment_intent);
      if (!paymentIntent) continue;
      await stripe.refunds.create({ payment_intent: paymentIntent, reason: "duplicate" }, { idempotencyKey: `dup-sub-${stripeSubscriptionId}-${paymentIntent}` });
    }
    log.warn("Duplicate subscription cancelled and refunded");
  } catch (err) {
    log.error({ err }, "DUPLICATE SUBSCRIPTION NOT FULLY UNDONE: cancel and refund it in the Stripe dashboard");
  }
}
