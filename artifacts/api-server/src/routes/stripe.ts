/**
 * Stripe webhook — where money becomes credits and plans.
 *
 * Three rules this handler exists to keep, each of which the previous version
 * broke:
 *
 *  1. EXACTLY ONCE. Stripe delivers every event at least once and redelivers
 *     on any slow or failed acknowledgement. Each event id is claimed in the
 *     stripe_events ledger inside the same transaction as its effect: a
 *     duplicate applies nothing, and a failure rolls both back so the retry
 *     applies it once. Previously a redelivered checkout.session.completed
 *     credited the account again.
 *
 *  2. ATOMIC. Balances and allowances change in single statements (see
 *     lib/billing.ts), never read-then-write — which lost a purchase that
 *     landed while a credit was being spent.
 *
 *  3. ONLY FOR MONEY TAKEN. checkout.session.completed fires for delayed
 *     payment methods too, with payment_status "unpaid" — the money has not
 *     arrived and may never. Credits are granted only when it is "paid", or on
 *     checkout.session.async_payment_succeeded when a delayed payment clears.
 *     Subscription scans follow invoice.paid, not the checkout page closing.
 *
 * Side effects that must not repeat — receipt emails — run after commit, and
 * only for an event this delivery actually applied.
 */
import { Router, type IRouter, type Request, type Response } from "express";
import type Stripe from "stripe";
import { db } from "@workspace/db";
import { stripe, CREDITS_MAP, PRICE_MAP } from "../lib/stripe";
import { sendPurchaseReceiptEmail } from "../lib/mailer";
import {
  claimStripeEvent,
  addCredits,
  activateSubscription,
  applyPaidInvoice,
  syncSubscription,
} from "../lib/billing";
import { planByKey } from "../lib/plans";
import { dropDuplicateSubscription } from "../lib/duplicateSubscription";

const router: IRouter = Router();

type AfterCommit = () => Promise<void>;

export interface EventOutcome {
  /** True when this event id had already been applied — nothing was done. */
  duplicate: boolean;
  /** What was applied, for the log line. */
  applied: string | null;
  /** Work to run once the transaction has committed (receipts). */
  after: AfterCommit[];
}

const toDate = (unixSeconds: number | null | undefined): Date | null =>
  typeof unixSeconds === "number" ? new Date(unixSeconds * 1000) : null;

const idOf = (v: string | { id: string } | null | undefined): string | null =>
  typeof v === "string" ? v : (v?.id ?? null);

/** Grant a paid credit-pack purchase. Shared by the two events that can mean "the money arrived". */
async function grantCreditPack(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  session: Stripe.Checkout.Session,
  after: AfterCommit[],
): Promise<string | null> {
  const meta = session.metadata ?? {};
  const userId = meta["user_id"];
  const tier = meta["tier"];
  if (!userId || !tier) return null;

  const credits = CREDITS_MAP[tier] ?? 0;
  if (credits === 0) return null;

  await addCredits(tx, userId, credits);

  const payerEmail = session.customer_details?.email ?? session.customer_email ?? null;
  if (payerEmail) {
    after.push(() =>
      sendPurchaseReceiptEmail({
        toEmail: payerEmail,
        productName: PRICE_MAP[tier]?.name ?? "SecScan credit pack",
        amountCents: session.amount_total ?? 0,
        creditsAdded: credits,
      }),
    );
  }
  return `credits+${credits} for ${userId}`;
}

/**
 * Apply one verified Stripe event. Exported for tests: the rules above are
 * what they pin, and they should not need a signed HTTP request to run.
 */
export async function processStripeEvent(event: Stripe.Event): Promise<EventOutcome> {
  return db.transaction(async (tx) => {
    if (!(await claimStripeEvent(tx, event))) {
      return { duplicate: true, applied: null, after: [] };
    }

    const after: AfterCommit[] = [];
    let applied: string | null = null;

    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const meta = session.metadata ?? {};

        if (session.mode === "subscription" && meta["type"] === "subscription") {
          const userId = meta["user_id"];
          const subscriptionId = idOf(session.subscription);
          if (userId && subscriptionId) {
            // The plan row only. The included scans arrive with invoice.paid.
            const started = await activateSubscription(tx, {
              userId,
              stripeCustomerId: idOf(session.customer),
              stripeSubscriptionId: subscriptionId,
              currentPeriodEnd: null,
              // Absent on sessions from before there were two plans: Pro.
              plan: planByKey(meta["plan"]) ?? undefined,
            });
            if (started === "duplicate") {
              // Already on a plan from another subscription: end this one, do not overwrite.
              after.push(() => dropDuplicateSubscription(subscriptionId));
              applied = `duplicate subscription ${subscriptionId} for ${userId}: cancelled and refunded`;
            } else {
              applied = `subscription started for ${userId}`;
            }
          }
        } else if (meta["type"] === "credits") {
          // "unpaid" = a delayed payment method that has not cleared. Wait for
          // async_payment_succeeded rather than hand out credits for money that
          // may never arrive.
          if (session.payment_status === "paid") {
            applied = await grantCreditPack(tx, session, after);
          } else {
            applied = `credits deferred: payment_status=${session.payment_status}`;
          }
        }
        break;
      }

      case "checkout.session.async_payment_succeeded": {
        const session = event.data.object as Stripe.Checkout.Session;
        if ((session.metadata ?? {})["type"] === "credits") {
          applied = await grantCreditPack(tx, session, after);
        }
        break;
      }

      case "invoice.paid": {
        const invoice = event.data.object as Stripe.Invoice;
        const details = invoice.parent?.subscription_details ?? null;
        const subscriptionId = idOf(details?.subscription ?? null);
        if (!subscriptionId) break; // not a subscription invoice

        // The billing period this payment covers. Lines carry it; the first
        // subscription line is the plan itself.
        const periodEnd = toDate(invoice.lines?.data?.[0]?.period?.end);

        const result = await applyPaidInvoice(tx, {
          stripeSubscriptionId: subscriptionId,
          stripeCustomerId: idOf(invoice.customer),
          userId: details?.metadata?.["user_id"] ?? null,
          currentPeriodEnd: periodEnd,
          plan: planByKey(details?.metadata?.["plan"]) ?? undefined,
        });
        if (result === "duplicate") after.push(() => dropDuplicateSubscription(subscriptionId));
        applied =
          result === "applied"
            ? `period started: plan allowance granted for ${subscriptionId}`
            : result === "stale"
              ? `invoice for cancelled subscription ${subscriptionId}: ignored`
            : result === "duplicate"
              ? `invoice for duplicate subscription ${subscriptionId}: cancelled and refunded`
              : `invoice for unknown subscription ${subscriptionId}`;
        break;
      }

      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const sub = event.data.object as Stripe.Subscription;
        await syncSubscription(tx, {
          stripeSubscriptionId: sub.id,
          // A deleted subscription arrives with status "canceled" already, but
          // the event type is the authoritative signal.
          stripeStatus: event.type === "customer.subscription.deleted" ? "canceled" : sub.status,
          currentPeriodEnd: toDate(sub.items?.data?.[0]?.current_period_end),
        });
        applied = `subscription ${sub.id} -> ${event.type === "customer.subscription.deleted" ? "canceled" : sub.status}`;
        break;
      }

      default:
        break;
    }

    return { duplicate: false, applied, after };
  });
}

router.post(
  "/scan/webhook",
  async (req: Request, res: Response): Promise<void> => {
    if (!stripe) {
      res.status(503).json({ error: "Stripe not configured" });
      return;
    }

    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) {
      req.log.error("STRIPE_WEBHOOK_SECRET is not set");
      res.status(503).json({ error: "Webhook not configured" });
      return;
    }

    const sig = req.headers["stripe-signature"];
    if (!sig) {
      res.status(400).json({ error: "Missing stripe-signature header" });
      return;
    }

    let event: Stripe.Event;
    try {
      event = stripe.webhooks.constructEvent(req.body as Buffer, sig, webhookSecret);
    } catch (err) {
      req.log.warn({ err }, "Stripe webhook signature verification failed");
      res.status(400).json({ error: "Invalid webhook signature" });
      return;
    }

    let outcome: EventOutcome;
    try {
      outcome = await processStripeEvent(event);
    } catch (err) {
      // Rolled back, ledger row included — so Stripe's retry is a clean re-run.
      req.log.error({ err, eventId: event.id, eventType: event.type }, "Error processing Stripe webhook");
      res.status(500).json({ error: "Webhook processing error" });
      return;
    }

    req.log.info(
      { eventId: event.id, type: event.type, duplicate: outcome.duplicate, applied: outcome.applied },
      outcome.duplicate ? "Stripe webhook: duplicate delivery, ignored" : "Stripe webhook applied",
    );

    // Acknowledge first: Stripe retries a slow ack, and a receipt is not worth
    // a redelivery. Each runs once, because a duplicate returns no work.
    res.json({ received: true });
    for (const job of outcome.after) {
      job().catch((err) => req.log.error({ err, eventId: event.id }, "Post-commit webhook task failed"));
    }
  },
);

export default router;
