import { describe, it, expect } from "vitest";
import { sha256Hex, signManifest, verifyManifestSignature } from "./evidenceSign";

const KEY_A = Buffer.alloc(32, 1).toString("base64");
const KEY_B = Buffer.alloc(32, 2).toString("base64");
const HASH = sha256Hex("a manifest");
const env = (over: Record<string, string | undefined>): NodeJS.ProcessEnv => ({ ...over });

describe("signManifest / verifyManifestSignature", () => {
  it("signs a manifest hash and verifies it", () => {
    const sig = signManifest(HASH, env({ ENCRYPTION_KEY: KEY_A }))!;
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyManifestSignature(HASH, sig, env({ ENCRYPTION_KEY: KEY_A }))).toBe(true);
  });

  it("is the same signature every time for the same manifest, and differs for another manifest", () => {
    const e = env({ ENCRYPTION_KEY: KEY_A });
    expect(signManifest(HASH, e)).toBe(signManifest(HASH, e));
    expect(signManifest(sha256Hex("another"), e)).not.toBe(signManifest(HASH, e));
  });

  it("refuses an edited manifest, a signature from another key, and a different signature", () => {
    const sig = signManifest(HASH, env({ ENCRYPTION_KEY: KEY_A }))!;
    const e = env({ ENCRYPTION_KEY: KEY_A });
    expect(verifyManifestSignature(sha256Hex("an edited manifest"), sig, e)).toBe(false);
    expect(verifyManifestSignature(HASH, sig, env({ ENCRYPTION_KEY: KEY_B }))).toBe(false);
    expect(verifyManifestSignature(HASH, "0".repeat(64), e)).toBe(false);
  });

  it("still verifies a pack signed before a key rotation", () => {
    const old = signManifest(HASH, env({ ENCRYPTION_KEY: KEY_A }))!;
    expect(verifyManifestSignature(HASH, old, env({ ENCRYPTION_KEY: KEY_B, ENCRYPTION_KEY_PREVIOUS: KEY_A }))).toBe(true);
    expect(verifyManifestSignature(HASH, old, env({ ENCRYPTION_KEY: KEY_B }))).toBe(false);
  });

  it("signs nothing, and verifies nothing, without a key", () => {
    expect(signManifest(HASH, env({}))).toBeNull();
    expect(verifyManifestSignature(HASH, "a".repeat(64), env({}))).toBe(false);
  });

  it.each([
    ["too short", "abc"],
    ["not hex", "z".repeat(64)],
    ["upper case", "A".repeat(64)],
    ["empty", ""],
    ["too long", "a".repeat(65)],
  ])("refuses a malformed signature (%s) without throwing", (_label, sig) => {
    expect(verifyManifestSignature(HASH, sig, env({ ENCRYPTION_KEY: KEY_A }))).toBe(false);
  });

  it("refuses a malformed manifest hash without throwing", () => {
    const sig = signManifest(HASH, env({ ENCRYPTION_KEY: KEY_A }))!;
    expect(verifyManifestSignature("not a hash", sig, env({ ENCRYPTION_KEY: KEY_A }))).toBe(false);
  });
});
