import { describe, it, expect, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { encryptSecret, decryptSecret } from "./crypto";

const k = () => randomBytes(32).toString("base64");
const saved = { key: process.env["ENCRYPTION_KEY"], prev: process.env["ENCRYPTION_KEY_PREVIOUS"] };
afterEach(() => {
  for (const [name, v] of [["ENCRYPTION_KEY", saved.key], ["ENCRYPTION_KEY_PREVIOUS", saved.prev]] as const) {
    if (v === undefined) delete process.env[name];
    else process.env[name] = v;
  }
});

describe("key rotation", () => {
  it("opens a secret written under the previous key, and writes new ones under the new key", () => {
    const oldKey = k();
    const newKey = k();
    process.env["ENCRYPTION_KEY"] = oldKey;
    delete process.env["ENCRYPTION_KEY_PREVIOUS"];
    const stored = encryptSecret("hunter2");

    process.env["ENCRYPTION_KEY"] = newKey;
    expect(() => decryptSecret(stored)).toThrow();
    process.env["ENCRYPTION_KEY_PREVIOUS"] = oldKey;
    expect(decryptSecret(stored)).toBe("hunter2");

    const fresh = encryptSecret("new");
    delete process.env["ENCRYPTION_KEY_PREVIOUS"];
    expect(decryptSecret(fresh)).toBe("new");
  });

  it("still refuses a secret no configured key wrote", () => {
    process.env["ENCRYPTION_KEY"] = k();
    const foreign = (() => { const a = process.env["ENCRYPTION_KEY"]; process.env["ENCRYPTION_KEY"] = k(); const e = encryptSecret("x"); process.env["ENCRYPTION_KEY"] = a; return e; })();
    process.env["ENCRYPTION_KEY_PREVIOUS"] = k();
    expect(() => decryptSecret(foreign)).toThrow();
  });
});

/**
 * Tamper checks on the stored format "<iv>.<authTag>.<ciphertext>". GCM authenticates the
 * ciphertext and the tag, so a single flipped bit in either must make decryption throw rather
 * than return altered plaintext.
 */
describe("tampered ciphertext", () => {
  const flipFirstByte = (b64: string): string => {
    const buf = Buffer.from(b64, "base64");
    buf[0] = buf[0]! ^ 0x01;
    return buf.toString("base64");
  };

  it("throws when one byte of the ciphertext is flipped", () => {
    process.env["ENCRYPTION_KEY"] = k();
    delete process.env["ENCRYPTION_KEY_PREVIOUS"];
    const [iv, tag, ciphertext] = encryptSecret("hunter2").split(".");
    const tampered = [iv, tag, flipFirstByte(ciphertext!)].join(".");
    expect(() => decryptSecret(tampered)).toThrow();
  });

  it("throws when one byte of the auth tag is flipped", () => {
    process.env["ENCRYPTION_KEY"] = k();
    delete process.env["ENCRYPTION_KEY_PREVIOUS"];
    const [iv, tag, ciphertext] = encryptSecret("hunter2").split(".");
    const tampered = [iv, flipFirstByte(tag!), ciphertext].join(".");
    expect(() => decryptSecret(tampered)).toThrow();
  });

  it("still opens the untouched value (the tamper cases above are not failing for another reason)", () => {
    process.env["ENCRYPTION_KEY"] = k();
    delete process.env["ENCRYPTION_KEY_PREVIOUS"];
    expect(decryptSecret(encryptSecret("hunter2"))).toBe("hunter2");
  });
});

/** Key length is checked when the key is used, with a message that says which variable is wrong. */
describe("key length", () => {
  const shortKey = () => randomBytes(16).toString("base64");

  it("rejects a current key that is not 32 bytes, naming ENCRYPTION_KEY", () => {
    process.env["ENCRYPTION_KEY"] = shortKey();
    delete process.env["ENCRYPTION_KEY_PREVIOUS"];
    expect(() => encryptSecret("x")).toThrow(/ENCRYPTION_KEY must decode to exactly 32 bytes/);
    expect(() => decryptSecret("aaaa.bbbb.cccc")).toThrow(/ENCRYPTION_KEY must decode to exactly 32 bytes/);
  });

  it("rejects a retired key that is not 32 bytes, naming ENCRYPTION_KEY_PREVIOUS", () => {
    const good = k();
    process.env["ENCRYPTION_KEY"] = good;
    const stored = encryptSecret("x");
    process.env["ENCRYPTION_KEY_PREVIOUS"] = shortKey();
    expect(() => decryptSecret(stored)).toThrow(/ENCRYPTION_KEY_PREVIOUS must decode to exactly 32 bytes/);
  });
});
