/**
 * Business logic: does a checkout bill whatever price the client sends?
 *
 * The flaw is the classic "trust the client's price": the server takes the unit price from the request instead of looking
 * it up. Detection is a differential, so no payment is attempted and nothing is guessed from a single response.
 *
 *  - Two requests are sent to the same candidate endpoint. They differ ONLY in the unit price (7 and 953), each with
 *    quantity 3, so the product is distinctive: 21 and 2859.
 *  - The finding needs a numeric field that is the product in BOTH responses, at the same path. A response that only echoes
 *    the price back never contains the product, so it is not a finding.
 *  - The requests carry line items only: no payment instrument and no confirm or commit step. At most a quote or a total can
 *    come back.
 *
 * Runs only on a verified domain (the caller passes `allowActiveProbes`) AND only when the scan has a signed-in test account,
 * because a checkout is normally reachable only after sign-in. The caller records the reason when either is missing.
 *
 * Detection only. A finding is a claim that the server computes the bill from client input; the fix is to look the price up
 * on the server.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";

export const QTY = 3;
export const PRICE_A = 7;   // product 21
export const PRICE_B = 953; // product 2859

/** Checkout and order endpoints worth one request each. A curated list, not a wordlist. */
export const CHECKOUT_PATHS = [
  "/api/checkout", "/api/cart", "/api/order", "/api/orders", "/api/purchase",
  "/api/payment", "/api/pay", "/checkout", "/api/billing/checkout", "/api/order/create",
];

export interface PostResult { status: number; body: string }
/** Sends a JSON POST. Returns null when the request fails or times out. Injected so the logic is tested without a network. */
export type JsonPoster = (url: string, body: string) => Promise<PostResult | null>;

const approxEq = (a: number, b: number) => Math.abs(a - b) < 0.005;

/** Every numeric leaf of a JSON value, keyed by its dotted path. */
export function numericLeaves(value: unknown, prefix = "", out: Record<string, number> = {}): Record<string, number> {
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (typeof v === "number" && Number.isFinite(v)) out[path] = v;
      else if (v && typeof v === "object") numericLeaves(v, path, out);
    }
  }
  return out;
}

const bodyFor = (price: number) => JSON.stringify({ items: [{ price, quantity: QTY }] });

/** The dotted path where both responses carry the computed product for their own price, or null. Exported for tests. */
export function computedTotalPath(bodyA: string, bodyB: string): string | null {
  let a: unknown;
  let b: unknown;
  try { a = JSON.parse(bodyA); b = JSON.parse(bodyB); } catch { return null; }
  const numsA = numericLeaves(a);
  const numsB = numericLeaves(b);
  const wantA = PRICE_A * QTY;
  const wantB = PRICE_B * QTY;
  for (const path of Object.keys(numsA)) {
    if (approxEq(numsA[path]!, wantA) && path in numsB && approxEq(numsB[path]!, wantB)) return path;
  }
  return null;
}

/** The default poster: a scoped request to the target, carrying the scan's signed-in session. */
export const scopedPoster: JsonPoster = async (url, body) => {
  const res = await scanFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
    timeoutMs: 5000,
  });
  return res ? { status: res.status, body: res.body } : null;
};

/** Findings for every candidate checkout endpoint that bills the client's price, one finding in all. */
export async function priceTamperingFindings(origin: string, post: JsonPoster = scopedPoster): Promise<ScanVulnerability[]> {
  const base = origin.replace(/\/+$/, "");
  for (const path of CHECKOUT_PATHS) {
    const url = `${base}${path}`;
    const a = await post(url, bodyFor(PRICE_A));
    if (!a || a.status < 200 || a.status >= 300) continue;
    const b = await post(url, bodyFor(PRICE_B));
    if (!b || b.status < 200 || b.status >= 300) continue;
    const path2 = computedTotalPath(a.body, b.body);
    if (path2 === null) continue;
    return [{
      id: randomUUID(),
      name: "Checkout Trusts the Client's Price",
      severity: "high",
      category: "Business Logic",
      description:
        `${path} computes the bill from the unit price the client sends. With the same quantity, a price of ${PRICE_A} produced a total of ` +
        `${PRICE_A * QTY} and a price of ${PRICE_B} produced ${PRICE_B * QTY}, at the same field (${path2}). The server does not look the price up, ` +
        `so a customer can change what they pay in the request.`,
      evidence:
        `POST ${url}\nBody: items[0].price=${PRICE_A}, quantity=${QTY} -> ${path2} = ${PRICE_A * QTY}\n` +
        `Body: items[0].price=${PRICE_B}, quantity=${QTY} -> ${path2} = ${PRICE_B * QTY}`,
      solution:
        "Never take a price from the request. Look up each item's price on the server from the product record, compute the total there, " +
        "and return or charge only that total.",
      cweId: "CWE-472",
      cvssScore: 8.1,
      wstgId: "WSTG-BUSL-01",
      confidence: 80,
    }];
  }
  return [];
}
