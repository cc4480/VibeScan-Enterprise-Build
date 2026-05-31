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
    name: "VibeScan Basic",
    description: "Black-box security scan — headers, SSL/TLS, tech fingerprint, and Supabase RLS check",
  },
  deep: {
    amount: 1900,
    name: "VibeScan Deep",
    description: "Full black-box penetration test with DeepSeek AI report + per-agent fix prompt",
  },
  pack_5: {
    amount: 7900,
    name: "VibeScan 5-Scan Pack",
    description: "5 Deep Scan credits — use any time, never expire (save $16 vs 5 singles)",
  },
  pack_20: {
    amount: 19900,
    name: "VibeScan 20-Scan Pack",
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
