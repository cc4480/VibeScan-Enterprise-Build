/**
 * Checkout Session creation — the half of payments that was missing.
 *
 * The receiving half already existed: routes/stripe.ts verifies the webhook
 * signature and credits an account on checkout.session.completed. Nothing
 * created a session, so nothing could ever reach it, and lib/stripe.ts said so
 * in a comment rather than in code.
 *
 * Credit packs only. Per-scan checkout is not offered: the Basic/Deep tier
 * split it priced against is retired — routes/scans.ts pins every scan to the
 * full run — so a per-scan price would be charging for a distinction the
 * product no longer makes. Packs also match how the free cap actually runs out:
 * someone who has spent their free scans wants more scans, not one scan.
 *
 * The session's metadata is the contract with the webhook. It must carry
 * `type: "credits"`, `user_id` and a `tier` present in CREDITS_MAP, or the
 * webhook will verify the payment and credit nobody.
 */

import { Router, type IRouter } from "express";
import { stripe, PRICE_MAP, CREDITS_MAP, getOrigin } from "../lib/stripe";
import { DEFAULT_PLAN, SOLD_PLANS, isUnlimitedPlan } from "../lib/plans";
import { creditBalance } from "../lib/credits";
import { scanLimitsForPricing } from "../lib/fairUse";
import { trialScansUsedBy, FREE_TRIAL_SCAN_LIMIT, freeScansResetAt } from "../lib/freeTrial";
import { refuseUnregistered, BUYABLE, currentPlan } from "./checkoutShared";

const router: IRouter = Router();

router.get("/checkout/packs", (_req, res): void => {
  // Priced in one place, so the page cannot advertise a number the session
  // will not charge.
  res.json({
    packs: BUYABLE.map((tier) => ({
      tier,
      credits: CREDITS_MAP[tier] ?? 0,
      amountCents: PRICE_MAP[tier]?.amount ?? 0,
      name: PRICE_MAP[tier]?.name ?? tier,
      description: PRICE_MAP[tier]?.description ?? "",
    })),
    // The subscriptions, priced from the same place the session reads.
    plans: SOLD_PLANS.map((p) => ({
      key: p.key,
      name: p.name,
      amountCents: p.amountCents,
      interval: "month",
      urlLimit: p.urlLimit,
      includedScans: p.includedScans,
      unlimitedScans: p.unlimitedScans,
      description: p.description,
    })),
    // The per-account caps an unlimited plan is still subject to, shown beside "unlimited".
    scanLimits: scanLimitsForPricing(),
    enabled: stripe !== null,
  });
});

router.post("/checkout/credits", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  if (refuseUnregistered(req, res)) return;

  // A deployment with no key is not broken, it just does not sell anything.
  // Say so plainly rather than failing somewhere further in.
  if (!stripe) {
    res.status(503).json({ error: "Payments are not configured on this deployment." });
    return;
  }

  const tier = typeof req.body?.tier === "string" ? req.body.tier : "";
  const price = PRICE_MAP[tier];
  const credits = CREDITS_MAP[tier];

  // Checked against CREDITS_MAP, not just PRICE_MAP: PRICE_MAP still carries
  // the retired per-scan entries, and one of those would take money and grant
  // zero credits, because the webhook looks the tier up in CREDITS_MAP.
  // Also on sale: a withdrawn pack still grants credits when an old payment arrives, but it
  // cannot be bought any more.
  if (!price || !credits || !BUYABLE.includes(tier)) {
    res.status(400).json({ error: "Unknown pack." });
    return;
  }

  const origin = getOrigin(req as unknown as { headers: Record<string, string | string[] | undefined> });

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "usd",
            unit_amount: price.amount,
            product_data: { name: price.name, description: price.description },
          },
        },
      ],
      // Stripe is the only place the card is handled; we never see it. The
      // address is collected so a receipt has somewhere to go.
      customer_email: req.user.email ?? undefined,
      metadata: { type: "credits", user_id: req.user.id, tier },
      // Mirrored onto the PaymentIntent so a later payment_intent.payment_failed
      // still knows what it was for — the webhook reads metadata from the
      // intent, not the session, on that event.
      payment_intent_data: {
        metadata: { type: "credits", user_id: req.user.id, tier },
      },
      success_url: `${origin}/dashboard?purchase=success`,
      cancel_url: `${origin}/dashboard?purchase=cancelled`,
    });

    if (!session.url) {
      req.log.error({ sessionId: session.id }, "Stripe returned a session with no URL");
      res.status(502).json({ error: "Could not start checkout. Please try again." });
      return;
    }

    req.log.info({ tier, credits, sessionId: session.id }, "Checkout session created");
    res.status(201).json({ checkoutUrl: session.url });
  } catch (err) {
    // Never surface Stripe's message: it can name internal configuration.
    req.log.error({ err, tier }, "Failed to create a checkout session");
    res.status(502).json({ error: "Could not start checkout. Please try again." });
  }
});

/**
 * Start a monthly subscription: body { plan: "starter" | "pro" }.
 *
 * The price is built inline (price_data with a monthly recurring interval)
 * rather than referencing a Price created in the Stripe dashboard, for the same
 * reason the packs are: the amount lives in exactly one place in this repo, so
 * the pricing page cannot advertise a number the session will not charge.
 *
 * user_id is set on BOTH the session and the subscription. The session's copy
 * reaches checkout.session.completed; the subscription's copy is snapshotted
 * onto every invoice, which is how invoice.paid finds the customer even when it
 * arrives before checkout.session.completed does.
 */
router.post("/checkout/subscription", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (!stripe) {
    res.status(503).json({ error: "Payments are not configured on this deployment." });
    return;
  }

  if (refuseUnregistered(req, res)) return;

  // One plan per user (billing_subscriptions.user_id is unique). Someone who
  // already has a live one is sent to manage it, not charged a second time.
  const existing = await currentPlan(req.user.id);
  if (existing && existing.status !== "cancelled") {
    res.status(409).json({ error: "You already have an active subscription.", code: "already_subscribed" });
    return;
  }

  // Omitted means the plan on sale, so a client written before plans had keys still works.
  const requested = (req.body as { plan?: unknown } | undefined)?.plan;
  // Only a plan that is on sale: Starter and Pro still resolve elsewhere (a row carrying one
  // keeps its allowance) but cannot be bought by naming them.
  const plan = requested === undefined ? DEFAULT_PLAN : (SOLD_PLANS.find((p) => p.key === requested) ?? null);
  if (!plan) {
    res.status(400).json({ error: "Unknown plan.", code: "unknown_plan" });
    return;
  }

  const origin = getOrigin(req as unknown as { headers: Record<string, string | string[] | undefined> });
  const metadata = { type: "subscription", user_id: req.user.id, plan: plan.key };

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "usd",
            unit_amount: plan.amountCents,
            recurring: { interval: "month" },
            // Stripe Tax needs a product tax code; without one checkout is refused as an invalid line item.
            // txcd_10103001 is Stripe's code for SaaS, business use.
            product_data: { name: plan.name, description: plan.description, tax_code: "txcd_10103001" },
          },
        },
      ],
      // A returning subscriber reuses their Stripe customer, so their payment
      // history and card stay in one place.
      ...(existing?.stripeCustomerId
        ? { customer: existing.stripeCustomerId }
        : { customer_email: req.user.email ?? undefined }),
      metadata,
      subscription_data: { metadata },
      success_url: `${origin}/dashboard?purchase=subscribed`,
      cancel_url: `${origin}/dashboard?purchase=cancelled`,
    });

    if (!session.url) {
      req.log.error({ sessionId: session.id }, "Stripe returned a subscription session with no URL");
      res.status(502).json({ error: "Could not start checkout. Please try again." });
      return;
    }
    req.log.info({ sessionId: session.id }, "Subscription checkout session created");
    res.status(201).json({ checkoutUrl: session.url });
  } catch (err) {
    req.log.error({ err }, "Failed to create a subscription checkout session");
    res.status(502).json({ error: "Could not start checkout. Please try again." });
  }
});

/**
 * Stripe's hosted customer portal: cancel, change card, download invoices.
 * Built by Stripe rather than here, so cancelling is never harder than
 * subscribing — and the webhook hears about whatever the customer does there.
 */
router.post("/billing/portal", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (!stripe) {
    res.status(503).json({ error: "Payments are not configured on this deployment." });
    return;
  }
  const existing = await currentPlan(req.user.id);
  if (!existing?.stripeCustomerId) {
    res.status(404).json({ error: "No subscription to manage." });
    return;
  }
  try {
    const origin = getOrigin(req as unknown as { headers: Record<string, string | string[] | undefined> });
    const portal = await stripe.billingPortal.sessions.create({
      customer: existing.stripeCustomerId,
      return_url: `${origin}/dashboard`,
    });
    res.status(201).json({ url: portal.url });
  } catch (err) {
    req.log.error({ err }, "Failed to create a billing portal session");
    res.status(502).json({ error: "Could not open billing. Please try again." });
  }
});

/**
 * Everything the account page needs to say what someone can do next: free
 * scans left, included scans left, credits, and the plan's state.
 */
router.get("/billing/status", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  try {
    const [row, credits, used] = await Promise.all([
      currentPlan(req.user.id),
      creditBalance(req.user.id),
      trialScansUsedBy(req.user.id),
    ]);
    res.json({
      freeScansRemaining: Math.max(0, FREE_TRIAL_SCAN_LIMIT - used),
      freeScanLimit: FREE_TRIAL_SCAN_LIMIT,
      // The free scans renew monthly; this is when the current ones reset.
      freeScansResetAt: freeScansResetAt().toISOString(),
      credits,
      subscription: row
        ? {
            plan: row.plan,
            status: row.status,
            includedScansRemaining: row.includedScansRemaining,
            // The counter means nothing on an unlimited plan; the page reads this instead.
            unlimitedScans: isUnlimitedPlan(row.plan),
            urlLimit: row.urlLimit,
            currentPeriodEnd: row.currentPeriodEnd?.toISOString() ?? null,
            canManage: row.stripeCustomerId !== null,
          }
        : null,
      paymentsEnabled: stripe !== null,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to read billing status");
    res.status(500).json({ error: "Failed to read billing status" });
  }
});

export default router;