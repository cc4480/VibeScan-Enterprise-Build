import { type Request } from "express";

/** In-memory accounts, so a two-account credentialed scan has something to compare. */
// ── In-memory "accounts", so a two-account credentialed scan has something to
// compare. Session tokens are fixed strings rather than anything issued at
// request time, so a verify script can hold both without driving a login form.
export const SESSIONS: Record<string, { id: string; email: string }> = {
  "alice-session-token": { id: "1001", email: "alice@example.com" },
  "bob-session-token": { id: "1002", email: "bob@example.com" },
};

export function sessionFromCookie(req: Request): { id: string; email: string } | null {
  const cookie = req.headers.cookie ?? "";
  const match = /session=([^;]+)/.exec(cookie);
  return (match && SESSIONS[match[1]!]) || null;
}
