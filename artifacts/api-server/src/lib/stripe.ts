import Stripe from "stripe";

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("STRIPE_SECRET_KEY is not set — Stripe features will be unavailable");
}

export const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: "2026-02-25.clover" })
  : null;

export const PRICE_MAP: Record<string, { amount: number; name: string; description: string }> = {
  basic: {
    amount: 2900,
    name: "VibeScan Basic",
    description: "Black-box security scan — headers, SSL/TLS, and tech fingerprint analysis",
  },
  deep: {
    amount: 7900,
    name: "VibeScan Deep",
    description: "Full black-box penetration test with DeepSeek AI plain-English report",
  },
  pack_5: {
    amount: 9900,
    name: "VibeScan 5-Scan Pack",
    description: "5 Deep Scan credits — use any time, never expire",
  },
  pack_20: {
    amount: 29900,
    name: "VibeScan 20-Scan Pack",
    description: "20 Deep Scan credits — for agencies and dev shops",
  },
};

export const CREDITS_MAP: Record<string, number> = {
  pack_5: 5,
  pack_20: 20,
};

export function getOrigin(_req?: unknown): string {
  // Use the configured APP_ORIGIN — never trust request headers for redirect URLs
  return process.env.APP_ORIGIN ?? "http://localhost:3000";
}
