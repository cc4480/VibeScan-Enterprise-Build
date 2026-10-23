/**
 * PKCE (RFC 7636), S256 only.
 *
 * "plain" is refused: it sends the secret in the clear in the same request an
 * attacker would intercept, so it protects nothing. Every client of this server is a
 * public client (an editor on someone's machine holds no secret), so PKCE is the
 * only thing tying the token request to the browser sign-in that started it.
 */
import { createHash, timingSafeEqual } from "node:crypto";

/** A code_verifier is 43 to 128 characters of unreserved URL characters. */
const VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;
/** An S256 challenge is a base64url SHA-256: exactly 43 characters. */
const CHALLENGE = /^[A-Za-z0-9\-_]{43}$/;

export function isValidChallenge(challenge: unknown): challenge is string {
  return typeof challenge === "string" && CHALLENGE.test(challenge);
}

export function isValidVerifier(verifier: unknown): verifier is string {
  return typeof verifier === "string" && VERIFIER.test(verifier);
}

export function challengeFor(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/** Does this verifier belong to that challenge? Constant time, and false for anything malformed. */
export function verifyPkce(verifier: unknown, challenge: string): boolean {
  if (!isValidVerifier(verifier) || !isValidChallenge(challenge)) return false;
  const a = Buffer.from(challengeFor(verifier));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}
