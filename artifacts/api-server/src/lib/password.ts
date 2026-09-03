/**
 * Password hashing.
 *
 * Uses scrypt from node:crypto rather than bcrypt or argon2. Both of those are
 * listed in build.mjs's esbuild `external` array, so neither can be bundled —
 * adopting one would mean shipping a real node_modules package into the runtime
 * image and keeping its version in step, the same tax already paid for
 * playwright. scrypt is memory-hard, built in, and an accepted choice for
 * password storage, so it costs nothing at build time.
 *
 * Stored format:  scrypt$N$r$p$<salt-b64>$<hash-b64>
 *
 * Parameters are recorded in the string itself so they can be raised later
 * without invalidating existing hashes: an old hash still verifies against its
 * own parameters, and `needsRehash` reports when one should be upgraded on the
 * user's next successful login.
 */

import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

// Hand-rolled rather than promisify(scrypt): promisify resolves to scrypt's
// three-argument overload and drops the options parameter, so the cost settings
// below would be silently ignored.
function scryptAsync(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (err, derived) => {
      if (err) reject(err);
      else resolve(derived);
    });
  });
}

// N=2^16 with r=8 costs roughly 64 MB per hash. That is deliberately expensive
// for an attacker with a stolen table and unnoticeable on a login request, but
// it does mean concurrent logins are memory-bound — worth remembering if the
// API server is ever run somewhere small.
const N = 65536;
const R = 8;
const P = 1;
const KEY_LEN = 64;
const SALT_LEN = 16;

// scrypt needs maxmem above roughly 128 * N * r; Node's default is 32 MB, which
// these parameters exceed.
const MAX_MEM = 256 * N * R;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_LEN);
  const derived = await scryptAsync(password, salt, KEY_LEN, {
    N,
    r: R,
    p: P,
    maxmem: MAX_MEM,
  });

  return [
    "scrypt",
    N,
    R,
    P,
    salt.toString("base64"),
    derived.toString("base64"),
  ].join("$");
}

/**
 * Verify a password against a stored hash.
 *
 * Never throws — a malformed or unrecognised stored value returns false rather
 * than surfacing a parse error to the caller, so a corrupt row cannot turn into
 * a 500 on the login path.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;

  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;

  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(parts[4]!, "base64");
    expected = Buffer.from(parts[5]!, "base64");
  } catch {
    return false;
  }
  if (salt.length === 0 || expected.length === 0) return false;

  let derived: Buffer;
  try {
    derived = await scryptAsync(password, salt, expected.length, {
      N: n,
      r,
      p,
      maxmem: Math.max(MAX_MEM, 256 * n * r),
    });
  } catch {
    // Absurd stored parameters would otherwise throw out of the login handler.
    return false;
  }

  // Lengths already match by construction, but timingSafeEqual throws on a
  // mismatch, so guard it rather than let that become a 500.
  if (derived.length !== expected.length) return false;
  return timingSafeEqual(derived, expected);
}

/** True when a stored hash used weaker parameters than the current settings. */
export function needsRehash(stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return true;
  return Number(parts[1]) < N || Number(parts[2]) < R || Number(parts[3]) < P;
}
