import { customFetch } from "@workspace/api-client-react";

/**
 * Buying scans and the SecScan Starter and Pro subscriptions.
 *
 * Every price shown in the app is read from GET /api/checkout/packs — the same
 * table the server builds Checkout Sessions from — so the page can never
 * advertise a number the checkout will not charge.
 */

export interface CreditPack {
  tier: string;
  credits: number;
  amountCents: number;
  name: string;
  description: string;
}

export interface PlanOffer {
  key: string;
  name: string;
  amountCents: number;
  interval: "month";
  urlLimit: number;
  includedScans: number;
  description: string;
}

export interface BillingCatalog {
  packs: CreditPack[];
  /** The subscriptions on sale, cheapest first. */
  plans: PlanOffer[];
  /** False until Stripe is configured on this deployment. */
  enabled: boolean;
}

export interface BillingStatus {
  freeScansRemaining: number;
  freeScanLimit: number;
  /** When this month's free scans renew (ISO date, the 1st of next month, UTC). */
  freeScansResetAt?: string;
  credits: number;
  subscription: {
    plan: string;
    status: "active" | "past_due" | "paused" | "cancelled";
    includedScansRemaining: number;
    urlLimit: number;
    currentPeriodEnd: string | null;
    canManage: boolean;
  } | null;
  paymentsEnabled: boolean;
}

export const getBillingCatalog = () => customFetch<BillingCatalog>("/api/checkout/packs");
export const getBillingStatus = () => customFetch<BillingStatus>("/api/billing/status");

const post = <T,>(path: string, body: unknown = {}) =>
  customFetch<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

/** Start a credit-pack checkout and hand the browser to Stripe. */
export async function buyPack(tier: string): Promise<void> {
  const { checkoutUrl } = await post<{ checkoutUrl: string }>("/api/checkout/credits", { tier });
  window.location.assign(checkoutUrl);
}

/** Start a subscription checkout for one plan and hand the browser to Stripe. */
export async function subscribe(plan: string): Promise<void> {
  const { checkoutUrl } = await post<{ checkoutUrl: string }>("/api/checkout/subscription", { plan });
  window.location.assign(checkoutUrl);
}

/** Open Stripe's customer portal (cancel, change card, invoices). */
export async function openBillingPortal(): Promise<void> {
  const { url } = await post<{ url: string }>("/api/billing/portal");
  window.location.assign(url);
}

/** "$49" for whole dollars, "$12.50" otherwise. */
export function formatUsd(cents: number): string {
  return cents % 100 === 0 ? `$${cents / 100}` : `$${(cents / 100).toFixed(2)}`;
}

/** Per-scan price of a pack, for the "you save" line. */
export function perScanCents(pack: CreditPack): number {
  return Math.round(pack.amountCents / Math.max(1, pack.credits));
}
