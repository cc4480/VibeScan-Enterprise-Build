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

export async function register(email: string, password: string): Promise<{ user: AccountUser }> {
  return customFetch("/api/account/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    responseType: "json",
  });
}

export async function signIn(email: string, password: string): Promise<{ user: AccountUser }> {
  return customFetch("/api/account/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
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
 * making the user confirm before this is reached.
 */
export async function deleteAccount(): Promise<void> {
  await customFetch("/api/account", { method: "DELETE", responseType: "json" });
}
