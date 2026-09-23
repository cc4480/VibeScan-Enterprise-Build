import { describe, it, expect } from "vitest";
import { generateToken, hashToken, authenticateApiToken, TOKEN_PREFIX } from "./apiTokens";

describe("generateToken", () => {
  it("is ssk_ + 256 random bits, and only the hash and a short prefix are kept", () => {
    const { token, hash, prefix } = generateToken();
    expect(token).toMatch(/^ssk_[A-Za-z0-9_-]{43}$/);
    expect(hash).toBe(hashToken(token));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(prefix).toBe(token.slice(0, 10));
    // The prefix must not be enough to reconstruct or brute-force the token.
    expect(token.length - prefix.length).toBeGreaterThanOrEqual(37);
  });

  it("never repeats", () => {
    const seen = new Set(Array.from({ length: 500 }, () => generateToken().token));
    expect(seen.size).toBe(500);
  });
});

describe("authenticateApiToken — refusals that never touch the database", () => {
  // The global test env points DATABASE_URL at a dead address: any of these
  // reaching a query would throw, so a null here also proves no lookup ran.
  it.each([
    [undefined],
    [""],
    ["ssk_abc"],                                          // no Bearer
    ["Basic dXNlcjpwYXNz"],
    ["Bearer 8f14e45f-ceea-467a-9575-2bf93a1b8c1e"],      // a legacy anonymous UUID
    [`Bearer ${TOKEN_PREFIX}short`],
    [`Bearer ${TOKEN_PREFIX}${"x".repeat(300)}`],
  ])("refuses %s", async (header) => {
    await expect(authenticateApiToken(header as string | undefined)).resolves.toBeNull();
  });
});
