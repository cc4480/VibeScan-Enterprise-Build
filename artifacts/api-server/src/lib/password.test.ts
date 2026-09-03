import { describe, it, expect } from "vitest";
import { hashPassword, verifyPassword, needsRehash } from "./password.js";

describe("hashPassword", () => {
  it("produces the documented format", async () => {
    const hash = await hashPassword("correct horse battery staple");
    const parts = hash.split("$");
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe("scrypt");
    expect(Number(parts[1])).toBeGreaterThanOrEqual(65536);
  });

  it("salts, so the same password never yields the same hash twice", async () => {
    const [a, b] = await Promise.all([hashPassword("same"), hashPassword("same")]);
    expect(a).not.toBe(b);
  });

  it("never stores the password itself", async () => {
    const hash = await hashPassword("hunter2");
    expect(hash).not.toContain("hunter2");
  });
});

describe("verifyPassword", () => {
  it("accepts the right password", async () => {
    const hash = await hashPassword("s3cret-passphrase");
    expect(await verifyPassword("s3cret-passphrase", hash)).toBe(true);
  });

  it("rejects the wrong password", async () => {
    const hash = await hashPassword("s3cret-passphrase");
    expect(await verifyPassword("s3cret-passphras", hash)).toBe(false);
    expect(await verifyPassword("", hash)).toBe(false);
  });

  it("is case and whitespace sensitive", async () => {
    const hash = await hashPassword("CaseSensitive ");
    expect(await verifyPassword("casesensitive ", hash)).toBe(false);
    expect(await verifyPassword("CaseSensitive", hash)).toBe(false);
  });

  it("handles unicode and long passphrases", async () => {
    const pw = "🔐 correct—horse–battery staple ".repeat(8);
    const hash = await hashPassword(pw);
    expect(await verifyPassword(pw, hash)).toBe(true);
  });

  // A corrupt or hand-edited row must fail the login, not crash it.
  it.each([
    ["empty", ""],
    ["not our format", "just-a-string"],
    ["unknown algorithm", "bcrypt$65536$8$1$c2FsdA==$aGFzaA=="],
    ["too few fields", "scrypt$65536$8$1$c2FsdA=="],
    ["non-numeric parameters", "scrypt$N$r$p$c2FsdA==$aGFzaA=="],
    ["empty salt and hash", "scrypt$65536$8$1$$"],
    ["absurd cost parameters", "scrypt$999999999$999$999$c2FsdA==$aGFzaA=="],
  ])("returns false for a malformed hash (%s) instead of throwing", async (_label, stored) => {
    await expect(verifyPassword("anything", stored)).resolves.toBe(false);
  });
});

describe("needsRehash", () => {
  it("is false for a hash produced by the current settings", async () => {
    expect(needsRehash(await hashPassword("x"))).toBe(false);
  });

  it("is true for weaker parameters", () => {
    expect(needsRehash("scrypt$16384$8$1$c2FsdA==$aGFzaA==")).toBe(true);
  });

  it("is true for anything unrecognised, so it gets replaced", () => {
    expect(needsRehash("bcrypt$whatever")).toBe(true);
    expect(needsRehash("")).toBe(true);
  });
});
