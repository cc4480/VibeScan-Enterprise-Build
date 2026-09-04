/**
 * Credentials for authenticated scanning.
 *
 * Handling rules, enforced here rather than left to callers:
 *
 *  - Encrypted at rest with the existing AES-256-GCM helper, never plaintext.
 *  - Stored on the scan row, not in the pg-boss job payload — that table holds
 *    plaintext JSON and is not where a customer's password belongs.
 *  - Decrypted only inside the worker, for the life of one scan.
 *  - Discarded when the scan finishes.
 *  - Only ever attached to requests aimed at the target, which lib/http.ts
 *    enforces by scope rather than by convention.
 *
 * `toScanHttpCredentials` is the only way the plaintext reaches the scanner, and
 * it deliberately yields just a Cookie header and an Authorization header — the
 * password itself never leaves this module.
 */

import { encryptSecret, decryptSecret, isEncryptionConfigured } from "./crypto";
import type { ScanCredentials as HttpCredentials } from "./http";
import { logger } from "./logger";

export type CredentialMode = "session" | "form";

export interface ScanCredentialInput {
  mode: CredentialMode;
  authorized: boolean;
  cookie?: string | null;
  bearerToken?: string | null;
  loginUrl?: string | null;
  username?: string | null;
  password?: string | null;
}

export interface CredentialValidation {
  ok: boolean;
  error?: string;
}

/**
 * Reject anything that cannot produce a usable session before the scan is
 * queued, so the user finds out immediately rather than from an empty report.
 */
export function validateCredentials(input: ScanCredentialInput): CredentialValidation {
  if (!input.authorized) {
    return {
      ok: false,
      error:
        "Confirm you're authorised to sign in to this target before running a credentialed scan.",
    };
  }

  if (!isEncryptionConfigured()) {
    return {
      ok: false,
      error: "This server isn't configured to store credentials. Set ENCRYPTION_KEY and retry.",
    };
  }

  if (input.mode === "session") {
    if (!input.cookie?.trim() && !input.bearerToken?.trim()) {
      return { ok: false, error: "Provide a session cookie or a bearer token." };
    }
    return { ok: true };
  }

  if (!input.loginUrl?.trim()) return { ok: false, error: "Provide the URL of the sign-in page." };
  if (!input.username?.trim()) return { ok: false, error: "Provide the username to sign in with." };
  if (!input.password) return { ok: false, error: "Provide the password to sign in with." };

  try {
    const parsed = new URL(input.loginUrl);
    if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") {
      return {
        ok: false,
        error: "The sign-in page must be served over HTTPS — a password sent over plain HTTP is readable in transit.",
      };
    }
  } catch {
    return { ok: false, error: "That sign-in URL isn't valid." };
  }

  return { ok: true };
}

export function encryptCredentials(input: ScanCredentialInput): string {
  return encryptSecret(JSON.stringify(input));
}

export function decryptCredentials(blob: string): ScanCredentialInput | null {
  try {
    return JSON.parse(decryptSecret(blob)) as ScanCredentialInput;
  } catch {
    // A blob written under a different ENCRYPTION_KEY cannot be recovered.
    // Failing closed runs the scan unauthenticated rather than crashing it.
    return null;
  }
}

/**
 * Turn stored credentials into the headers the scanner will send.
 *
 * For `session` this is a direct translation. For `form` it drives a real
 * browser sign-in and harvests the resulting cookies, because a login that
 * depends on JavaScript, a CSRF token or a redirect chain cannot be reproduced
 * by posting a form body blindly.
 */
export async function toScanHttpCredentials(
  input: ScanCredentialInput,
  log: Pick<typeof logger, "info" | "warn"> = logger,
): Promise<HttpCredentials | null> {
  if (input.mode === "session") {
    const creds: HttpCredentials = {};
    if (input.cookie?.trim()) creds.cookie = input.cookie.trim();
    if (input.bearerToken?.trim()) {
      creds.headers = { Authorization: `Bearer ${input.bearerToken.trim()}` };
    }
    return Object.keys(creds).length > 0 ? creds : null;
  }

  return formLogin(input, log);
}

/**
 * Sign in through the login page with a headless browser and keep the cookies.
 *
 * Field detection is deliberately conservative: a visible password input, and
 * the text/email input nearest to it. Guessing more elaborately tends to fill
 * the wrong box on pages with a search bar or a newsletter signup.
 */
async function formLogin(
  input: ScanCredentialInput,
  log: Pick<typeof logger, "info" | "warn">,
): Promise<HttpCredentials | null> {
  if (!input.loginUrl || !input.username || !input.password) return null;

  let browser;
  try {
    // Imported here rather than at module scope so that requiring this file does
    // not pull Playwright in. seclayer (the web tier) imports validateCredentials
    // and encryptCredentials from this module; a static import would put Chromium
    // in the web bundle for the sake of a function only secscan ever calls.
    const { chromium } = await import("playwright");
    browser = await chromium.launch({ headless: true });
  } catch (err) {
    log.warn({ err }, "[auth] Headless browser unavailable — cannot perform form login");
    return null;
  }

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await page.goto(input.loginUrl, { waitUntil: "domcontentloaded", timeout: 20_000 });

    const passwordField = page.locator('input[type="password"]:visible').first();
    await passwordField.waitFor({ state: "visible", timeout: 10_000 });

    const userField = page
      .locator('input[type="email"]:visible, input[type="text"]:visible, input[name*="user" i]:visible')
      .first();

    await userField.fill(input.username);
    await passwordField.fill(input.password);

    // Submitting from the password field lets the page's own handler run,
    // which matters when the submit button is a div with a click listener.
    await Promise.all([
      page.waitForLoadState("networkidle", { timeout: 20_000 }).catch(() => undefined),
      passwordField.press("Enter"),
    ]);

    const cookies = await context.cookies();
    if (cookies.length === 0) {
      log.warn("[auth] Form login produced no cookies — treating the scan as unauthenticated");
      return null;
    }

    const cookie = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    log.info({ cookieCount: cookies.length }, "[auth] Form login succeeded");
    return { cookie };
  } catch (err) {
    // Never surface the error verbatim: a Playwright failure can echo the
    // filled value back in its message.
    log.warn(
      { errType: err instanceof Error ? err.name : typeof err },
      "[auth] Form login failed — scanning unauthenticated",
    );
    return null;
  } finally {
    await browser.close().catch(() => undefined);
  }
}

/** A URL that is itself a sign-in surface, rather than one bounced to it. */
const AUTH_SHAPED_URL = /\/(login|signin|sign-in|auth)(\b|\/|\?)/i;

/**
 * Heuristic check that a response still looks signed in.
 *
 * A session that expires mid-scan is worse than no session at all: the back
 * half of the scan runs logged out and reports a clean bill of health for pages
 * it never actually saw.
 */
export function looksSignedOut(
  body: string,
  finalUrl: string,
  requestedUrl?: string,
): boolean {
  // The scan deliberately probes /login, /auth and /signin during discovery.
  // Being served a sign-in page at a URL we asked a sign-in page for is the
  // expected answer, not evidence the session died — only being *bounced* to
  // one from somewhere else is. Without this the check fires on essentially
  // every authenticated scan of a real app (any target answering 200 on
  // /login rather than redirecting a signed-in visitor away) and stamps a
  // spurious "results are incomplete" notice on a complete report.
  if (requestedUrl && AUTH_SHAPED_URL.test(requestedUrl)) return false;
  if (AUTH_SHAPED_URL.test(finalUrl)) return true;
  const head = body.slice(0, 4_000);
  return (
    /<input[^>]+type=["']password["']/i.test(head) &&
    /sign in|log in|login/i.test(head)
  );
}
