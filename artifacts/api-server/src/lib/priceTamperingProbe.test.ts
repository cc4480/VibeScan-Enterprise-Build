import { describe, it, expect } from "vitest";
import { priceTamperingFindings, computedTotalPath, PRICE_A, PRICE_B, QTY, type JsonPoster } from "./priceTamperingProbe";

const ORIGIN = "https://shop.example.com";

/** A checkout that multiplies the client's price by the client's quantity and returns the total. */
const trustsClient: JsonPoster = async (_url, body) => {
  const price = JSON.parse(body).items[0].price;
  return { status: 200, body: JSON.stringify({ total: price * QTY }) };
};

/** An endpoint that only echoes the price it was sent. */
const echoes: JsonPoster = async (_url, body) => ({ status: 200, body: JSON.stringify({ price: JSON.parse(body).items[0].price }) });

/** A checkout that ignores the client's price and bills from its own catalogue. */
const usesCatalogue: JsonPoster = async () => ({ status: 200, body: JSON.stringify({ total: 4999 * QTY }) });

describe("Checkout trusts the client's price", () => {
  it("is reported when the total follows the client's price at the same field", async () => {
    const f = await priceTamperingFindings(ORIGIN, trustsClient);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ name: "Checkout Trusts the Client's Price", severity: "high", cweId: "CWE-472" });
    expect(f[0]!.evidence).toContain(`${PRICE_A * QTY}`);
    expect(f[0]!.evidence).toContain(`${PRICE_B * QTY}`);
  });

  it("clean twin: an echo of the price is not a finding, because the product never appears", async () => {
    expect(await priceTamperingFindings(ORIGIN, echoes)).toEqual([]);
  });

  it("clean twin: a server that bills from its own catalogue is not a finding", async () => {
    expect(await priceTamperingFindings(ORIGIN, usesCatalogue)).toEqual([]);
  });

  it("an endpoint that does not exist, or fails, is not a finding", async () => {
    expect(await priceTamperingFindings(ORIGIN, async () => ({ status: 404, body: "not found" }))).toEqual([]);
    expect(await priceTamperingFindings(ORIGIN, async () => null)).toEqual([]);
  });
});

describe("computedTotalPath", () => {
  it("needs the product at the same path in both responses", () => {
    const a = JSON.stringify({ total: PRICE_A * QTY });
    expect(computedTotalPath(a, JSON.stringify({ total: PRICE_B * QTY }))).toBe("total");
    expect(computedTotalPath(a, JSON.stringify({ subtotal: PRICE_B * QTY }))).toBeNull();
    expect(computedTotalPath("not json", a)).toBeNull();
  });
});
