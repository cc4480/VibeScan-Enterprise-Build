import { customFetch, ApiError } from "@workspace/api-client-react";

/**
 * "Tell me when I can buy more scans."
 *
 * Temporary, and paired with the server's routes/purchaseIntent.ts — both go
 * when Checkout Session creation ships and the free-scan cap stops being a
 * wall. See lib/freeTrial.ts on the server for why the cap exists.
 */

export interface PurchaseIntentStatus {
  registered: boolean;
  scansUsed: number;
  scanLimit: number;
}

/** The server's machine-readable name for "you are out of free scans". */
export const TRIAL_EXHAUSTED = "trial_exhausted";

/**
 * Whether this failure is the free-scan cap rather than a real error.
 *
 * Keyed on the code the server sends, never on the message: that copy is
 * written for a person and will be reworded, and a UI matching the prose would
 * break silently at the exact moment somebody was ready to pay.
 */
export function isTrialExhausted(err: unknown): boolean {
  if (!(err instanceof ApiError)) return false;
  if (err.status !== 403) return false;
  const data = err.data as { code?: unknown } | null;
  return data?.code === TRIAL_EXHAUSTED;
}

export async function getPurchaseIntent(): Promise<PurchaseIntentStatus> {
  return customFetch<PurchaseIntentStatus>("/api/purchase-intent");
}

export async function registerPurchaseIntent(): Promise<void> {
  await customFetch<{ registered: boolean }>("/api/purchase-intent", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
}
