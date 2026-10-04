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
  /** Scans are not counted, only rate-limited. `includedScans` is 0 then and means nothing. */
  unlimitedScans: boolean;
  description: string;
}

/** The per-account scan caps an unlimited plan is still subject to (the server's rate limits). */
export interface ScanLimits {
  perHour: number;
  perDay: number;
}

export interface BillingCatalog {
  packs: CreditPack[];
  /** The subscriptions on sale, cheapest first. */
  plans: PlanOffer[];
  /** Absent from a server older than this field. */
  scanLimits?: ScanLimits;
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
    /** The counter above means nothing on an unlimited plan. */
    unlimitedScans?: boolean;
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

const PLAN_NAMES: Record<string, string> = {
  unlimited: "SecScan Unlimited",
  starter: "SecScan Starter",
  pro: "SecScan Pro",
};

/** A plan's display name. A key this build does not know reads as plain "SecScan". */
export function planDisplayName(key: string): string {
  // hasOwn, not a bare lookup: "constructor" and the other inherited names would otherwise
  // resolve to a function and render as its source text.
  return Object.hasOwn(PLAN_NAMES, key) ? PLAN_NAMES[key]! : "SecScan";
}

/**
 * "fair use: up to 5 scans an hour and 20 a day", from the caps the server enforces. The cap is
 * material to an "unlimited" offer, so it is shown beside the word, not only in the Terms. With
 * no caps to hand (an older server, or the catalog not loaded yet) it says only "fair use".
 */
export function fairUseText(limits: ScanLimits | undefined): string {
  return limits ? `fair use: up to ${limits.perHour} scans an hour and ${limits.perDay} a day` : "fair use";
}

/** What a plan says about scans: "Unlimited full scans (fair use: ...)", or the monthly count. */
export function planScansLine(plan: Pick<PlanOffer, "unlimitedScans" | "includedScans">, limits?: ScanLimits): string {
  return plan.unlimitedScans ? `Unlimited full scans (${fairUseText(limits)})` : `${plan.includedScans} full scans every month`;
}

/** "$0.95 per scan", or null for an unlimited plan, where a per-scan price would be meaningless. */
export function planPerScanLabel(plan: Pick<PlanOffer, "unlimitedScans" | "includedScans" | "amountCents">): string | null {
  if (plan.unlimitedScans || plan.includedScans <= 0) return null;
  return `${formatUsd(Math.round(plan.amountCents / plan.includedScans))} per scan`;
}
