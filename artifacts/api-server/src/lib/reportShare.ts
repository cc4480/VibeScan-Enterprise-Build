/**
 * Minting report share links.
 *
 * Extracted from routes/shares.ts so the scan worker can create one without
 * going through HTTP (it has no session to authenticate with). Both callers use
 * this single implementation, because a share token is a bearer credential and
 * two places generating them differently is how one ends up weaker.
 *
 * ── Why the report-ready email needs one ──
 * The email used to link at /report/:id, which requires being signed in AS THE
 * OWNER. That fails on the most common way people open mail — on a phone,
 * logged out (401) or logged into a different account (404) — and both render as
 * a bare "Failed to load report". The person who received the report could not
 * read it. Observed live on 2026-09-12: report 107b3358 answered 200 on the
 * device that ran the scan and 404 on the owner's phone, which was signed into
 * their other Google account.
 *
 * A share link resolves through GET /api/share/:token, which takes no session,
 * so the emailed link works on any device in any signed-in state.
 *
 * ── The tradeoff, stated plainly ──
 * A share token IS a bearer credential: whoever holds the link can read that one
 * report. That is acceptable here precisely because the link is delivered to the
 * report owner's own mailbox and nowhere else, and it is scoped to a single
 * report — never to the account. Tokens are 32 bytes of CSPRNG output, so the
 * link cannot be guessed, and an operator can revoke it from the report's share
 * list like any other.
 */

import { db, reportSharesTable } from "@workspace/db";
import { randomBytes } from "node:crypto";

export type ShareExpiry = "7d" | "30d" | "never";

export function computeShareExpiry(expiresIn: ShareExpiry): Date | null {
  if (expiresIn === "never") return null;
  const days = expiresIn === "7d" ? 7 : 30;
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d;
}

export interface CreatedShare {
  id: string;
  token: string;
  expiresAt: Date | null;
  createdAt: Date;
}

/**
 * Create a share link for a report.
 *
 * Callers are responsible for authorising this — the HTTP route checks that the
 * requester owns the report; the worker passes the owner id it just wrote onto
 * the report itself. This function deliberately does NOT re-check ownership,
 * because the worker has no session to check against, and a silent
 * ownership-derivation here would be a worse place for that logic to live.
 */
export async function createReportShare(
  reportId: string,
  userId: string,
  expiresIn: ShareExpiry = "never",
): Promise<CreatedShare> {
  const token = randomBytes(32).toString("hex");
  const expiresAt = computeShareExpiry(expiresIn);

  const [share] = await db
    .insert(reportSharesTable)
    .values({ reportId, userId, token, expiresAt })
    .returning();

  return {
    id: share!.id,
    token: share!.token,
    expiresAt: share!.expiresAt,
    createdAt: share!.createdAt,
  };
}

/**
 * The public, session-independent URL a share token resolves at.
 *
 * /share/:token — matching App.tsx's route and the link the in-app share dialog
 * hands users. NOT /s/:token, which no route serves: shared-report.tsx declared
 * that as its canonical URL and it 404s.
 */
export function shareUrl(appOrigin: string, token: string): string {
  return `${appOrigin.replace(/\/+$/, "")}/share/${token}`;
}
