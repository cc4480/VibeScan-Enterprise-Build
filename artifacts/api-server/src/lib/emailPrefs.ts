/**
 * Unsubscribe links for recurring mail.
 *
 * The token is a stateless HMAC of the user id rather than a row in
 * auth_tokens. An unsubscribe link has to keep working from an email someone
 * finds a year later, and the tokens in authTokens.ts are single-use and
 * expiring by design — correct for a password reset, wrong for this. Nothing
 * is stored, so nothing has to be cleaned up or can go stale.
 *
 * It is signed rather than just being the raw user id: an unauthenticated
 * endpoint that takes a bare id would let anyone unsubscribe anyone by
 * guessing, and ids are UUIDs that appear in other URLs.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Derived from ENCRYPTION_KEY rather than sharing it. The same key doing two
 * jobs means rotating it for one reason silently breaks the other; the label
 * keeps this signature independent of the at-rest encryption.
 */
function signingKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) throw new Error("ENCRYPTION_KEY is not set — cannot sign unsubscribe links");
  return createHmac("sha256", Buffer.from(raw, "base64")).update("unsubscribe-v1").digest();
}

function sign(userId: string): string {
  return createHmac("sha256", signingKey()).update(userId).digest("base64url");
}

export function unsubscribeToken(userId: string): string {
  return `${Buffer.from(userId).toString("base64url")}.${sign(userId)}`;
}

/** Returns the user id the token was issued for, or null if it does not verify. */
export function verifyUnsubscribeToken(token: string): string | null {
  const [encodedId, mac] = String(token ?? "").split(".");
  if (!encodedId || !mac) return null;

  let userId: string;
  try {
    userId = Buffer.from(encodedId, "base64url").toString();
  } catch {
    return null;
  }
  if (!userId) return null;

  const expected = Buffer.from(sign(userId));
  const actual = Buffer.from(mac);
  // timingSafeEqual throws on a length mismatch, which is itself a signal, so
  // the lengths are compared first and the result is the same either way.
  if (expected.length !== actual.length) return null;
  return timingSafeEqual(expected, actual) ? userId : null;
}

/**
 * RFC 8058 one-click unsubscribe headers.
 *
 * Both headers are required together: List-Unsubscribe alone lets a client
 * show the link, but Gmail and Yahoo only render their own native unsubscribe
 * control when List-Unsubscribe-Post is present, and their bulk-sender rules
 * expect it. The URL must accept POST and act without further interaction —
 * a page asking the user to confirm does not satisfy one-click.
 */
export function unsubscribeHeaders(appOrigin: string, userId: string): Record<string, string> {
  const url = `${appOrigin.replace(/\/$/, "")}/api/email/unsubscribe?token=${unsubscribeToken(userId)}`;
  return {
    "List-Unsubscribe": `<${url}>`,
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
  };
}
