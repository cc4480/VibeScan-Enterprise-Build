import Stripe from "stripe";
import { APP_ORIGIN } from "./appOrigin";

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("STRIPE_SECRET_KEY is not set — Stripe features will be unavailable");
}

export const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: "2026-09-30.endive" })
  : null;

export const PRICE_MAP: Record<string, { amount: number; name: string; description: string }> = {
  basic: {
    amount: 900,
    name: "SecScan Basic",
    description: "Black-box security scan — headers, SSL/TLS, tech fingerprint, and Supabase RLS check",
  },
  deep: {
    amount: 1900,
    name: "SecScan Deep",
    description: "Retired tier — not sold",
  },
  // Retired 2026-09-24, never sold (payments were not yet switched on). Kept
  // named so an old link cannot resolve to a different product; they are not in
  // CREDITS_MAP, so they grant nothing and cannot be bought.
  single: { amount: 1200, name: "SecScan Scan Credit", description: "Retired pack — not sold" },
  pack_5: { amount: 5000, name: "SecScan 5-Scan Pack", description: "Retired pack — not sold" },
  pack_20: { amount: 16000, name: "SecScan 20-Scan Pack", description: "Retired pack — not sold" },
  // Withdrawn from sale 2026-10-03 with the move to one unlimited plan (see plans.ts): not
  // in PACKS_ON_SALE, so they cannot be bought. They were priced above the old plans per
  // scan, so a pack never undercut a subscription; with unlimited scans that argument is
  // gone. Still in CREDITS_MAP, deliberately: a checkout opened before the change and paid
  // after it must still be credited.
  pack_10: {
    amount: 1200,
    name: "SecScan 10-Scan Pack",
    description: "10 scan credits — the full scan, use any time, never expire",
  },
  pack_50: {
    amount: 4900,
    name: "SecScan 50-Scan Pack",
    description: "50 scan credits — the full scan, never expire",
  },
};

/**
 * What a PAID credit-pack session grants. This is the grant table, not the shop window: a
 * payment that arrives for a listed pack is always credited, even if the pack has since been
 * withdrawn, because the customer paid for it when it was on sale.
 */
export const CREDITS_MAP: Record<string, number> = {
  pack_10: 10,
  pack_50: 50,
};

/**
 * The packs that may be bought now. Empty since 2026-10-03: the one plan sold is unlimited,
 * so a pack has nothing to offer. A credit balance already held still spends (see chargeScan).
 * Every entry must also be in CREDITS_MAP, or it would take money and grant nothing.
 */
export const PACKS_ON_SALE: readonly string[] = [];

export function getOrigin(req: { headers: Record<string, string | string[] | undefined> }): string {
  // Always the configured origin (APP_ORIGIN, defaulting to the production site). These URLs are
  // where Stripe sends a paying customer back to, and the request's own headers are client-influenced:
  // a forged X-Forwarded-Host would bounce them somewhere else after they paid. The parameter is kept
  // so callers need no change.
  void req;
  return APP_ORIGIN;
}

/**
 * Refuse to stay quiet about a payment setup that takes money it cannot credit.
 *
 * With STRIPE_SECRET_KEY set, checkout works and customers can pay. Without
 * STRIPE_WEBHOOK_SECRET, the webhook refuses every event (503) — so the money
 * is taken and the credits or plan never arrive. That is the worst state
 * payments can be in, and nothing else would surface it until a customer did.
 *
 * (This replaced a warning written before checkout existed, which said that
 * DISABLE_PAYMENTS=false was a lie because "no checkout flow exists". Both
 * halves exist now; DISABLE_PAYMENTS is read by nothing and never was.)
 */
export function warnIfPaymentsMisconfigured(
  log: { warn: (obj: object, msg: string) => void; error?: (obj: object, msg: string) => void },
): void {
  const hasKey = !!process.env["STRIPE_SECRET_KEY"];
  const hasWebhookSecret = !!process.env["STRIPE_WEBHOOK_SECRET"];

  if (hasKey && !hasWebhookSecret) {
    const fields = { STRIPE_SECRET_KEY: "set", STRIPE_WEBHOOK_SECRET: "MISSING" };
    const msg =
      "Checkout is live but the Stripe webhook secret is not set: customers can pay, " +
      "and every payment webhook will be refused, so no credits or plans will be granted. " +
      "Set STRIPE_WEBHOOK_SECRET from the Stripe dashboard's webhook endpoint.";
    // Called as methods, never detached: pino's log functions need their `this`.
    if (log.error) log.error(fields, msg);
    else log.warn(fields, msg);
  }
  if (process.env["DISABLE_PAYMENTS"] !== undefined) {
    log.warn(
      { setting: "DISABLE_PAYMENTS" },
      "DISABLE_PAYMENTS is set but nothing reads it. Payments are on exactly when " +
        "STRIPE_SECRET_KEY is set; remove the variable to avoid implying otherwise.",
    );
  }
}
