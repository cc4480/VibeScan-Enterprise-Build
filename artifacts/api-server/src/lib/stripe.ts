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
    description: "Full black-box deep scan with DeepSeek AI report + per-agent fix prompt",
  },
  single: {
    amount: 1200,
    name: "SecScan Scan Credit",
    description: "1 Deep Scan credit — use any time, never expires",
  },
  pack_5: {
    amount: 5000,
    name: "SecScan 5-Scan Pack",
    description: "5 Deep Scan credits — use any time, never expire (17% off buying singles)",
  },
  pack_20: {
    amount: 16000,
    name: "SecScan 20-Scan Pack",
    description: "20 Deep Scan credits — for agencies and dev shops (33% off buying singles)",
  },
};

export const CREDITS_MAP: Record<string, number> = {
  single: 1,
  pack_5: 5,
  pack_20: 20,
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
