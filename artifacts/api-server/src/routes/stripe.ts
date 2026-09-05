import { Router, type IRouter, type Request, type Response } from "express";
import { db, scansTable, creditsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { stripe, CREDITS_MAP, PRICE_MAP } from "../lib/stripe";
import { sendPurchaseReceiptEmail } from "../lib/mailer";
import { enqueueScan } from "../lib/queue";

const router: IRouter = Router();

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

    let event: import("stripe").Stripe.Event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body as Buffer,
        sig,
        webhookSecret,
      );
    } catch (err) {
      req.log.warn({ err }, "Stripe webhook signature verification failed");
      res.status(400).json({ error: "Invalid webhook signature" });
      return;
    }

    req.log.info({ type: event.type }, "Stripe webhook received");

    try {
      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object as import("stripe").Stripe.Checkout.Session;
          const meta = session.metadata ?? {};

          // Stripe only knows the address the customer paid with; that is the
          // one entitled to the receipt, and for a guest scan it is the only
          // address we have at all.
          const payerEmail = session.customer_details?.email ?? session.customer_email ?? null;

          if (meta.type === "scan") {
            const scanId = meta.scan_id;
            if (!scanId) break;

            const [scan] = await db
              .select()
              .from(scansTable)
              .where(eq(scansTable.id, scanId));

            if (!scan) {
              req.log.warn({ scanId }, "Scan not found for completed checkout");
              break;
            }

            // pending → paid (so UI can show payment confirmed)
            await db
              .update(scansTable)
              .set({
                status: "paid",
                stripePaymentIntentId:
                  typeof session.payment_intent === "string"
                    ? session.payment_intent
                    : (session.payment_intent?.id ?? null),
              })
              .where(eq(scansTable.id, scanId));

            // paid → queued (after enqueue succeeds)
            await enqueueScan({
              scanId: scan.id,
              userId: scan.userId,
              targetUrl: scan.targetUrl,
              tier: scan.tier,
            });

            await db
              .update(scansTable)
              .set({ status: "queued", startedAt: new Date() })
              .where(eq(scansTable.id, scanId));

            if (payerEmail) {
              // Not awaited: Stripe retries a webhook that is slow to ack, and a
              // duplicate delivery would charge nothing twice but would mail twice.
              void sendPurchaseReceiptEmail({
                toEmail: payerEmail,
                productName: PRICE_MAP[scan.tier]?.name ?? "SecScan scan",
                amountCents: session.amount_total ?? 0,
              });
            }

            req.log.info({ scanId }, "Scan paid and enqueued");
          } else if (meta.type === "credits") {
            const userId = meta.user_id;
            const tier = meta.tier;
            if (!userId || !tier) break;

            const creditsToAdd = CREDITS_MAP[tier] ?? 0;
            if (creditsToAdd === 0) break;

            const [existing] = await db
              .select()
              .from(creditsTable)
              .where(eq(creditsTable.userId, userId));

            if (existing) {
              await db
                .update(creditsTable)
                .set({ balance: existing.balance + creditsToAdd })
                .where(eq(creditsTable.userId, userId));
            } else {
              await db.insert(creditsTable).values({
                userId,
                balance: creditsToAdd,
              });
            }

            if (payerEmail) {
              void sendPurchaseReceiptEmail({
                toEmail: payerEmail,
                productName: PRICE_MAP[tier]?.name ?? "SecScan credit pack",
                amountCents: session.amount_total ?? 0,
                creditsAdded: creditsToAdd,
              });
            }

            req.log.info({ userId, creditsToAdd }, "Credits added after pack purchase");
          }
          break;
        }

        case "checkout.session.expired": {
          const expiredSession = event.data.object as import("stripe").Stripe.Checkout.Session;
          const meta = expiredSession.metadata ?? {};
          if (meta.type === "scan" && meta.scan_id) {
            await db
              .update(scansTable)
              .set({ status: "failed", error: "Checkout session expired" })
              .where(eq(scansTable.id, meta.scan_id));
            req.log.info({ scanId: meta.scan_id }, "Scan failed: checkout expired");
          }
          break;
        }

        case "payment_intent.payment_failed": {
          // Metadata is propagated from the Checkout Session via payment_intent_data.metadata
          const failedIntent = event.data.object as import("stripe").Stripe.PaymentIntent;
          const meta = failedIntent.metadata ?? {};
          if (meta.type === "scan" && meta.scan_id) {
            await db
              .update(scansTable)
              .set({ status: "failed", error: "Payment failed" })
              .where(eq(scansTable.id, meta.scan_id));
            req.log.info({ scanId: meta.scan_id }, "Scan failed: payment declined");
          }
          break;
        }

        default:
          break;
      }
    } catch (err) {
      req.log.error({ err, eventType: event.type }, "Error processing Stripe webhook");
      res.status(500).json({ error: "Webhook processing error" });
      return;
    }

    res.json({ received: true });
  },
);

export default router;
