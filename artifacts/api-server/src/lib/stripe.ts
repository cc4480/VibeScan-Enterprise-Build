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
    name: "Seclayer Basic",
    description: "Black-box security scan — headers, SSL/TLS, tech fingerprint, and Supabase RLS check",
  },
  deep: {
    amount: 1900,
    name: "Seclayer Deep",
    description: "Full black-box deep scan with DeepSeek AI report + per-agent fix prompt",
  },
  pack_5: {
    amount: 7900,
    name: "Seclayer 5-Scan Pack",
    description: "5 Deep Scan credits — use any time, never expire (save $16 vs 5 singles)",
  },
  pack_20: {
    amount: 19900,
    name: "Seclayer 20-Scan Pack",
    description: "20 Deep Scan credits — for agencies and dev shops (save $181 vs singles)",
  },
};

export const CREDITS_MAP: Record<string, number> = {
  pack_5: 5,
  pack_20: 20,
};

export function getOrigin(req: { headers: Record<string, string | string[] | undefined> }): string {
  const proto = req.headers["x-forwarded-proto"] || "https";
  const host = req.headers["x-forwarded-host"] || req.headers["host"] || "localhost";
  return `${proto}://${host}`;
}

/**
 * Whether the deployment believes it is charging for scans.
 *
 * It is not, and cannot be yet. The receiving half of payments exists — the
 * Stripe webhook in routes/stripe.ts credits an account and queues the scan it
 * paid for — but nothing creates a Checkout Session, so there is no way for a
 * customer to reach that webhook. POST /api/scans returns
 * `checkoutUrl: null, creditUsed: false` unconditionally and queues the scan.
 *
 * DISABLE_PAYMENTS was documented as the switch that turns charging on, and
 * .env.production.example told operators to set it to "false" in production.
 * Nothing read it. That combination is worse than having no flag: it reads like
 * a gate that is closed while every scan is free.
 *
 * This does not invent a pricing decision — it makes the configuration honest,
 * loudly, at startup, until checkout is either built or the flag is retired.
 */
export function warnIfPaymentsMisconfigured(
  log: { warn: (obj: object, msg: string) => void },
): void {
  if (process.env["DISABLE_PAYMENTS"] === "false") {
    log.warn(
      {
        setting: "DISABLE_PAYMENTS=false",
        actual: "every scan is free",
        missing: "Checkout Session creation",
      },
      "DISABLE_PAYMENTS=false implies scans are charged for, but no checkout " +
      "flow exists — scans are queued free of charge. Set DISABLE_PAYMENTS=true " +
      "to match reality, or build checkout before relying on this.",
    );
  }
}
