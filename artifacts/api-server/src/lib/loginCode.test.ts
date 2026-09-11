import { describe, it, expect } from "vitest";
import {
  LOGIN_CODE_LENGTH,
  LOGIN_CODE_MAX_ATTEMPTS,
  LOGIN_CODE_TTL_MS,
  generateChallenge,
  generateLoginCode,
  hashValue,
  hashesEqual,
  normalizeLoginCode,
} from "./loginCode";

describe("generateLoginCode", () => {
  it("always produces exactly six digits, leading zeros kept", () => {
    for (let i = 0; i < 2000; i++) {
      expect(generateLoginCode()).toMatch(/^\d{6}$/);
    }
  });

  // Not a randomness test — it cannot be at this sample size. It catches the
  // one plausible failure: `randomBytes % 1000000`, whose bias crowds output
  // into the low end of the range and shows up as a starved bucket.
  it("spreads across the keyspace rather than crowding the low range", () => {
    const buckets = new Array(10).fill(0);
    for (let i = 0; i < 5000; i++) {
      buckets[Math.floor(Number(generateLoginCode()) / 100_000)]++;
    }
    expect(buckets.every((n) => n > 200)).toBe(true);
  });

  it("does not repeat within a short run", () => {
    const seen = new Set(Array.from({ length: 200 }, () => generateLoginCode()));
    expect(seen.size).toBeGreaterThan(190);
  });
});

describe("generateChallenge", () => {
  // The challenge is the real secret here — 32 bytes, unlike the code — which
  // is why a code can be matched safely inside it.
  it("is long, URL-safe, and unique per call", () => {
    const a = generateChallenge();
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.length).toBeGreaterThanOrEqual(42);
    const seen = new Set(Array.from({ length: 500 }, () => generateChallenge()));
    expect(seen.size).toBe(500);
  });
});

describe("normalizeLoginCode", () => {
  it("accepts the formats people actually paste", () => {
    expect(normalizeLoginCode("123456")).toBe("123456");
    expect(normalizeLoginCode("123 456")).toBe("123456"); // the email's own spacing
    expect(normalizeLoginCode("123-456")).toBe("123456");
    expect(normalizeLoginCode("  123456 ")).toBe("123456");
    expect(normalizeLoginCode("000000")).toBe("000000");
  });

  it("rejects anything that is not exactly six digits", () => {
    for (const bad of ["12345", "1234567", "12345a", "abcdef", "", "  ", "12.3456", "١٢٣٤٥٦"]) {
      expect(normalizeLoginCode(bad)).toBeNull();
    }
  });

  // A JSON body can carry anything; 123456 as a NUMBER must not slip through,
  // because the route's validation depends on the null.
  it("rejects non-strings rather than coercing them", () => {
    for (const bad of [123456, null, undefined, {}, [], true]) {
      expect(normalizeLoginCode(bad)).toBeNull();
    }
  });
});

describe("hashesEqual", () => {
  it("compares equal and unequal digests", () => {
    expect(hashesEqual(hashValue("a"), hashValue("a"))).toBe(true);
    expect(hashesEqual(hashValue("a"), hashValue("b"))).toBe(false);
  });

  // timingSafeEqual throws on a length mismatch, which would turn a malformed
  // stored value into a 500 rather than a refused sign-in.
  it("returns false on a length mismatch instead of throwing", () => {
    expect(() => hashesEqual("abc", "abcdef")).not.toThrow();
    expect(hashesEqual("abc", "abcdef")).toBe(false);
    expect(hashesEqual("", "x")).toBe(false);
  });
});

describe("the safety constants", () => {
  // These three numbers ARE the argument that a six-digit code is a credential.
  // Widening any of them silently is how it stops being one.
  it("stay within the range that makes a short code viable", () => {
    expect(LOGIN_CODE_MAX_ATTEMPTS).toBeLessThanOrEqual(10);
    expect(LOGIN_CODE_TTL_MS).toBeLessThanOrEqual(15 * 60 * 1000);
    expect(LOGIN_CODE_LENGTH).toBeGreaterThanOrEqual(6);
  });
});
