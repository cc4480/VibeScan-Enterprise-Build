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

const router: IRouter = Router();

/** The packs that may be bought. Anything outside CREDITS_MAP grants nothing. */
const BUYABLE = Object.keys(CREDITS_MAP);

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
    enabled: stripe !== null,
  });
});

router.post("/checkout/credits", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

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
  if (!price || !credits) {
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

export default router;
