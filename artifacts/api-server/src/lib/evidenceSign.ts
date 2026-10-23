/**
 * SecScan's signature on an evidence pack.
 *
 * What it proves, and what it does not. The pack carries a manifest of every file's SHA-256, and SecScan signs the hash of
 * that manifest. Anyone can recompute the file hashes and the manifest hash offline (`sha256sum -c MANIFEST.sha256`), which
 * shows the files are the ones listed. Asking SecScan to verify the signature (POST /api/evidence/verify) shows the manifest
 * was issued by SecScan and not edited since. The signature is an HMAC with a key only SecScan holds, so only SecScan can
 * check it: this is an issuance receipt, not a public-key certificate, and it says nothing about whether the findings
 * themselves are complete. A scan is a point-in-time test, not a guarantee.
 *
 * The key is derived from ENCRYPTION_KEY (and, for packs issued before a rotation, ENCRYPTION_KEY_PREVIOUS), with its own
 * label so the same secret is never used for two purposes.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_VERSION = "secscan-evidence-v1";

const sha256Hex = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");
export { sha256Hex };

function signingKeys(env: NodeJS.ProcessEnv = process.env): Buffer[] {
  const secrets = [env["ENCRYPTION_KEY"], ...(env["ENCRYPTION_KEY_PREVIOUS"] ?? "").split(",")].map((s) => (s ?? "").trim()).filter(Boolean);
  return secrets.map((s) => createHash("sha256").update(`${SIGNATURE_VERSION}\n${s}`).digest());
}

/** The signature for a manifest hash, with the current key; null when the server has no key to sign with. */
export function signManifest(manifestSha256: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const [key] = signingKeys(env);
  return key ? createHmac("sha256", key).update(`${SIGNATURE_VERSION}\n${manifestSha256}`).digest("hex") : null;
}

/** Whether SecScan issued this manifest hash: true under the current key or any key it rotated away from. */
export function verifyManifestSignature(manifestSha256: string, signature: string, env: NodeJS.ProcessEnv = process.env): boolean {
  if (!/^[0-9a-f]{64}$/.test(manifestSha256) || !/^[0-9a-f]{64}$/.test(signature)) return false;
  const given = Buffer.from(signature, "hex");
  return signingKeys(env).some((key) => {
    const expected = createHmac("sha256", key).update(`${SIGNATURE_VERSION}\n${manifestSha256}`).digest();
    return expected.length === given.length && timingSafeEqual(expected, given);
  });
}
