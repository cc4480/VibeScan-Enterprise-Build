/**
 * The consent token: what the approve button carries.
 *
 * When someone opens an authorization link, the server checks it (known app,
 * exactly-registered redirect, S256 challenge) and hands the page a signed token that
 * freezes those values and the signed-in user. Approving must present that token. So:
 *   - what the person approved is exactly what was checked, whatever the page sends;
 *   - a token made for one user or one request cannot be replayed for another;
 *   - it expires in ten minutes.
 * Cross-site forgery is already stopped by the SameSite=lax session cookie; this adds
 * tamper-proofing between "looked at" and "approved".
 */
import { createHmac, timingSafeEqual } from "node:crypto";

const TTL_MS = 10 * 60_000;

export interface ConsentPayload {
  userId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string | null;
}

function key(): string {
  const k = process.env["ENCRYPTION_KEY"];
  if (k) return k;
  if (process.env["NODE_ENV"] === "production") throw new Error("ENCRYPTION_KEY is required to sign OAuth consent");
  return "dev-only-oauth-consent-key";
}

const sign = (body: string) => createHmac("sha256", key()).update(`oauth-consent:${body}`).digest("base64url");

export function signConsent(payload: ConsentPayload, now = Date.now()): string {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: now + TTL_MS })).toString("base64url");
  return `${body}.${sign(body)}`;
}

/** The payload, if the token is genuine, unexpired and was issued to THIS user. Otherwise null. */
export function verifyConsent(token: unknown, userId: string, now = Date.now()): ConsentPayload | null {
  if (typeof token !== "string" || token.length > 4096) return null;
  const dot = token.indexOf(".");
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const given = Buffer.from(token.slice(dot + 1));
  const expected = Buffer.from(sign(body));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as ConsentPayload & { exp: number };
    if (typeof parsed.exp !== "number" || parsed.exp < now) return null;
    if (parsed.userId !== userId) return null;
    const { exp: _exp, ...payload } = parsed;
    return payload;
  } catch {
    return null;
  }
}
