import Stripe from "stripe";

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("STRIPE_SECRET_KEY is not set — Stripe features will be unavailable");
}

export const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: "2026-02-25.clover" })
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
  // Priced per scan above both plans ($0.95 Starter, $0.49 Pro), so a pack never
  // undercuts a subscription; credits cost a little more because they never
  // expire and need no commitment. $1.20 and $0.98 a scan.
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

/** The packs on sale, and the credits each grants. Anything not here cannot be bought. */
export const CREDITS_MAP: Record<string, number> = {
  pack_10: 10,
  pack_50: 50,
};

export function getOrigin(req: { headers: Record<string, string | string[] | undefined> }): string {
  // The configured origin wins. The headers below are client-influenced, and
  // this builds the URLs Stripe sends a paying customer back to — a forged
  // X-Forwarded-Host would bounce them somewhere else after they paid.
  const configured = process.env["APP_ORIGIN"]?.trim().replace(/\/+$/, "");
  if (configured) return configured;
  const proto = req.headers["x-forwarded-proto"] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers["host"] || "localhost";
  return `${proto}://${host}`;
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
