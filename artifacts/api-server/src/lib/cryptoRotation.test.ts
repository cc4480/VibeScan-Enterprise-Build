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
