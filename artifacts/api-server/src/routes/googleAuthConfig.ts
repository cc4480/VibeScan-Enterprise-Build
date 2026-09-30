/** Google sign-in configuration, the callback URL, the attempt limiter and the failure redirect. */
import { type Response } from "express";
import * as client from "openid-client";

export const GOOGLE_ISSUER = "https://accounts.google.com";

export const PKCE_COOKIE = "g_pkce";

export const PKCE_TTL_MS = 10 * 60_000;

export function googleConfigured(): boolean {
  return Boolean(
    process.env["GOOGLE_CLIENT_ID"] && process.env["GOOGLE_CLIENT_SECRET"],
  );
}

/**
 * Built from APP_ORIGIN rather than the request. A redirect URI derived from
 * Host or X-Forwarded-Host is attacker-influenceable, and it must in any case
 * match the value registered in Google Cloud Console exactly — so it should
 * come from configuration, not from whoever is calling.
 */
export function callbackUrl(): string {
  const origin = (process.env["APP_ORIGIN"] ?? "").replace(/\/$/, "");
  return `${origin}/api/auth/google/callback`;
}

export let cachedConfig: client.Configuration | null = null;

export async function getGoogleConfig(): Promise<client.Configuration> {
  if (!cachedConfig) {
    cachedConfig = await client.discovery(
      new URL(GOOGLE_ISSUER),
      process.env["GOOGLE_CLIENT_ID"]!,
      process.env["GOOGLE_CLIENT_SECRET"]!,
    );
  }
  return cachedConfig;
}

// Same shape as the limiter on /login and the account routes: in-memory,
// per-instance, enough to stop a loop rather than a determined attacker.
export const attempts = new Map<string, number[]>();

export const WINDOW_MS = 15 * 60_000;

export const MAX_ATTEMPTS = 20;

export function rateLimited(key: string): boolean {
  const now = Date.now();
  const recent = (attempts.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  attempts.set(key, recent);
  return recent.length > MAX_ATTEMPTS;
}

/**
 * Every failure here happens during a top-level browser navigation: the person
 * clicked a button and the browser left the site. Answering with a bare status
 * and a sentence strands them on an unstyled page with no navigation and no way
 * back other than the back button — which is what "it goes to a white screen"
 * means in practice.
 *
 * So failures go back to the sign-in page with a code, and the page says what
 * happened. The code is a fixed identifier rather than a message: it ends up in
 * a URL the user can see and edit, so it must not be something we render back
 * to them verbatim.
 */
export function failToSignIn(res: Response, code: string): void {
  res.redirect(`/sign-in?error=${encodeURIComponent(code)}`);
}
