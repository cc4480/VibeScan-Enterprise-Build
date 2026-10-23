/**
 * AES-256-GCM encryption for user-supplied secrets (e.g. BYO DeepSeek API keys)
 * stored at rest in the database. Key comes from ENCRYPTION_KEY (32-byte,
 * base64-encoded). Format: "<iv>.<authTag>.<ciphertext>", each base64.
 */

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export function isEncryptionConfigured(): boolean {
  return Boolean(process.env.ENCRYPTION_KEY);
}

function parseKey(raw: string, name: string): Buffer {
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error(
      `${name} must decode to exactly 32 bytes — generate one with: ` +
        `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`,
    );
  }
  return key;
}

function getKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) {
    throw new Error("ENCRYPTION_KEY is not set — cannot encrypt or decrypt secrets");
  }
  return parseKey(raw, "ENCRYPTION_KEY");
}

/**
 * Keys that may have encrypted what is stored: the current one, then any retired ones.
 *
 * Rotating: put the new key in ENCRYPTION_KEY and the old one in ENCRYPTION_KEY_PREVIOUS
 * (comma-separated for more than one). New secrets use the new key; stored ones still open with
 * the old. Drop the old key once nothing stored under it remains (stored credentials are discarded
 * when their scan finishes, so that is quick). Without this a rotation made every stored secret
 * unreadable at once.
 */
function getDecryptKeys(): Buffer[] {
  const previous = (process.env.ENCRYPTION_KEY_PREVIOUS ?? "")
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean)
    .map((k) => parseKey(k, "ENCRYPTION_KEY_PREVIOUS"));
  return [getKey(), ...previous];
}

export function encryptSecret(plaintext: string): string {
  const key = getKey();
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [iv, authTag, ciphertext].map((buf) => buf.toString("base64")).join(".");
}

export function decryptSecret(encrypted: string): string {
  const keys = getDecryptKeys();
  const [ivB64, tagB64, ciphertextB64] = encrypted.split(".");
  if (!ivB64 || !tagB64 || !ciphertextB64) {
    throw new Error("Malformed encrypted secret");
  }

  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(tagB64, "base64");
  const ciphertext = Buffer.from(ciphertextB64, "base64");

  let lastError: unknown;
  for (const key of keys) {
    try {
      const decipher = createDecipheriv(ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    } catch (err) {
      lastError = err; // wrong key: GCM's tag check fails; try the next one
    }
  }
  throw lastError;
}
