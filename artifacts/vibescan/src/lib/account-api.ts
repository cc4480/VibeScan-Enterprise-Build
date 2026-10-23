/**
 * Account endpoints.
 *
 * Hand-written rather than generated, matching lib/monitor-api.ts — these
 * routes are not in the OpenAPI spec the client is generated from.
 *
 * customFetch attaches the anonymous bearer token automatically, which matters
 * on register: the server uses it to promote that anonymous identity into the
 * new account in place, so the user keeps the scans they ran before signing up.
 */

import { customFetch } from "@workspace/api-client-react";

export interface AccountUser {
  id: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  profileImageUrl: string | null;
}

/**
 * Pull the server's message out of a failed request.
 *
 * The API answers with { error } and writes those strings for people — "Use at
 * least 10 characters", "Email or password is incorrect" — so showing them beats
 * any generic message this layer could invent.
 */
export function accountErrorMessage(err: unknown, fallback: string): string {
  // Read the shape rather than importing ApiError: the client package does not
  // re-export the class, and widening its public surface for an error message
  // is not worth it.
  if (err && typeof err === "object" && "data" in err) {
    const data = (err as { data?: unknown }).data;
    if (data && typeof data === "object" && "error" in data) {
      const message = (data as { error?: unknown }).error;
      if (typeof message === "string" && message.trim()) return message;
    }
  }
  return fallback;
}

/**
 * Step one of creating an account. No account exists yet: the server emails a
 * six-digit code, and verifyRegistration creates the account only when that
 * code comes back — proving the address belongs to the person signing up.
 */
export interface RegistrationChallenge {
  codeRequired: true;
  challenge: string;
  /** Masked address the code went to. */
  sentTo: string;
}

export async function register(email: string, password: string): Promise<RegistrationChallenge> {
  return customFetch("/api/account/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    responseType: "json",
  });
}

/** Step two: exchange the challenge and the emailed code for the new account and a session. */
export async function verifyRegistration(challenge: string, code: string): Promise<{ user: AccountUser }> {
  return customFetch("/api/account/register/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge, code }),
    responseType: "json",
  });
}

/**
 * Step one of signing in: the password.
 *
 * A correct password does NOT produce a session. It returns a challenge, and
 * the server emails a six-digit code; verifySignIn exchanges the pair for a
 * session. That is what makes this two-factor — the password is something you
 * know, the code proves you can read the account's mailbox.
 */
export interface SignInChallenge {
  twoFactorRequired: true;
  /** Opaque handle to send back with the code. Not a credential on its own. */
  challenge: string;
  /** Masked address the code went to, e.g. "al***@example.com". */
  sentTo: string;
}

export async function signIn(email: string, password: string): Promise<SignInChallenge> {
  return customFetch("/api/account/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    responseType: "json",
  });
}

/** Step two: exchange the challenge and the emailed code for a session. */
export async function verifySignIn(challenge: string, code: string): Promise<{ user: AccountUser }> {
  return customFetch("/api/account/login/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge, code }),
    responseType: "json",
  });
}

export async function signOut(): Promise<void> {
  await customFetch("/api/account/logout", { method: "POST", responseType: "json" });
}

export async function requestPasswordReset(email: string): Promise<{ message: string }> {
  return customFetch("/api/account/password/forgot", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
    responseType: "json",
  });
}

export async function resetPassword(token: string, password: string): Promise<{ ok: boolean }> {
  return customFetch("/api/account/password/reset", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, password }),
    responseType: "json",
  });
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<{ ok: boolean }> {
  return customFetch("/api/account/password/change", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword, newPassword }),
    responseType: "json",
  });
}

export async function verifyEmail(token: string): Promise<{ ok: boolean }> {
  return customFetch("/api/account/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
    responseType: "json",
  });
}

export async function requestEmailVerification(): Promise<{ ok: boolean; alreadyVerified: boolean }> {
  return customFetch("/api/account/verify/request", { method: "POST", responseType: "json" });
}

/**
 * Permanently erase the account and everything belonging to it.
 *
 * There is no undo and no grace period, so the caller is responsible for
 * making the user confirm before this is reached. The code is the one emailed by
 * requestDeleteCode, so a session alone cannot erase an account.
 */
export async function deleteAccount(challenge: string, code: string): Promise<void> {
  await customFetch("/api/account", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge, code }),
    responseType: "json",
  });
}

/** Step one of deleting: email a 6-digit code to the address on the account. */
export async function requestDeleteCode(): Promise<{ challenge: string; sentTo: string }> {
  return customFetch("/api/account/delete/code", { method: "POST", responseType: "json" });
}

export interface EmailPreferences {
  /** Product updates and announcements. Marketing; off by choice.
   *  Account mail (resets, verification, receipts) is not covered by either
   *  flag and always sends. */
  productUpdates: boolean;
  /** Master switch for monitor alert EMAIL. Does not affect webhooks. */
  monitorAlerts: boolean;
  /** Per-kind control. Applies to email and webhooks alike. */
  alerts: {
    cve: boolean;
    regression: boolean;
    certExpiry: boolean;
    scanComplete: boolean;
    /** Site went down, or came back, per the hourly check. */
    availability: boolean;
    /** A security header disappeared, HSTS weakened, redirect target changed. */
    drift: boolean;
  };
  /** Only alerts at or above this severity are sent. "info" means everything. */
  minSeverity: AlertSeverity;
  /** A daily window when alerts below Critical are held back; null means none. */
  quietHours: QuietHours | null;
}

/** Whole hours 0-23 in the zone named; start inclusive, end exclusive; start after end wraps midnight. */
export interface QuietHours {
  start: number;
  end: number;
  timezone: string;
}

export type AlertSeverity = "info" | "low" | "medium" | "high" | "critical";

export async function getEmailPreferences(): Promise<EmailPreferences> {
  return customFetch("/api/account/email-preferences");
}

/**
 * Partial by design, including inside `alerts`: the settings screen sends one
 * toggle at a time, and the server changes only the fields it receives.
 */
export interface EmailPreferenceUpdate {
  productUpdates?: boolean;
  monitorAlerts?: boolean;
  alerts?: Partial<EmailPreferences["alerts"]>;
  minSeverity?: AlertSeverity;
  quietHours?: QuietHours | null;
}

export async function setEmailPreferences(
  changes: EmailPreferenceUpdate,
): Promise<EmailPreferences> {
  return customFetch("/api/account/email-preferences", {
    method: "PUT",
    body: JSON.stringify(changes),
    headers: { "Content-Type": "application/json" },
  });
}
