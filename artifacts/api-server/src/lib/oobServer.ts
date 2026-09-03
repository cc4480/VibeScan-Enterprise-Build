/**
 * Out-of-band interaction collector.
 *
 * The thing that makes blind vulnerabilities visible. A probe plants a URL
 * pointing back at this application, carrying a token unique to one injection
 * point. If the *target's* server fetches that URL — following an SSRF, running
 * an injected `<script>`, resolving a hostname — the request lands here, and
 * that arrival is the proof. Nothing in the target's own response is needed,
 * which is why this catches the whole class of bugs that produce no visible
 * output.
 *
 * The signal is almost perfectly clean: our token is random and appears nowhere
 * else, so a callback carrying it can only have come from something that
 * received the URL we injected. That is the appeal of out-of-band detection and
 * the reason it earns a high confidence.
 *
 * ── Requirements ─────────────────────────────────────────────────────────────
 *
 * The collector must be reachable from the internet, because the target's
 * server is what calls it. In production that is this app at APP_ORIGIN; the
 * callback path is unauthenticated by necessity. To stop an internet-facing
 * open endpoint becoming an unbounded write sink, a hit is only recorded when
 * its token was actually registered by a scan and has not expired.
 */

import { db, oobTokensTable, oobInteractionsTable } from "@workspace/db";
import { eq, and, gt, inArray, lt } from "drizzle-orm";
import { randomBytes } from "node:crypto";

/** How long a planted token stays live. SSRF callbacks can lag the request. */
const TOKEN_TTL_MS = 15 * 60 * 1000;

/**
 * Base URL a target should call back to. Prefers an explicit override so the
 * collector can live on a dedicated host, and falls back to the app's own
 * public origin. Empty when neither is configured, which disables OOB rather
 * than planting URLs nobody can reach.
 */
export function oobBaseUrl(): string {
  const explicit = process.env["OOB_BASE_URL"]?.trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const origin = process.env["APP_ORIGIN"]?.trim();
  // localhost is never reachable by a real target, so it does not count as
  // configured — a scan there simply runs without OOB.
  if (origin && !/^https?:\/\/(localhost|127\.|0\.0\.0\.0)/i.test(origin)) {
    return origin.replace(/\/+$/, "");
  }
  return "";
}

export function isOobConfigured(): boolean {
  return oobBaseUrl() !== "";
}

/**
 * Register a token for a scan and return the URL to plant.
 *
 * The token is 20 bytes of base32-ish text: long enough that it cannot be
 * guessed, and using only lowercase letters and digits so it survives being
 * placed in a hostname label, a path, or a query value unchanged.
 */
export async function registerOobToken(scanId: string | null, context: string): Promise<{
  token: string;
  url: string;
}> {
  const token =
    "oob" + randomBytes(16).toString("hex").replace(/[^a-z0-9]/g, "").slice(0, 24);

  await db.insert(oobTokensTable).values({
    token,
    scanId,
    context,
    expiresAt: new Date(Date.now() + TOKEN_TTL_MS),
  });

  return { token, url: `${oobBaseUrl()}/api/oob/${token}` };
}

/**
 * Record a callback, if the token is one we planted and still live.
 *
 * Returns whether it was recorded, so the route can answer a bare 200 either
 * way and never reveal to a prober which tokens are real.
 */
export async function recordOobInteraction(
  token: string,
  detail: { method?: string; path?: string; sourceIp?: string; userAgent?: string },
): Promise<boolean> {
  const [live] = await db
    .select({ token: oobTokensTable.token })
    .from(oobTokensTable)
    .where(and(eq(oobTokensTable.token, token), gt(oobTokensTable.expiresAt, new Date())));

  if (!live) return false;

  await db.insert(oobInteractionsTable).values({
    token,
    method: detail.method ?? null,
    path: detail.path ?? null,
    sourceIp: detail.sourceIp ?? null,
    userAgent: detail.userAgent ?? null,
  });
  return true;
}

/** Which of these tokens received at least one callback. */
export async function tokensWithInteractions(tokens: string[]): Promise<Set<string>> {
  if (tokens.length === 0) return new Set();
  const rows = await db
    .select({ token: oobInteractionsTable.token })
    .from(oobInteractionsTable)
    .where(inArray(oobInteractionsTable.token, tokens));
  return new Set(rows.map((r) => r.token));
}

/** Housekeeping: drop tokens past their expiry and the interactions that cite them. */
export async function purgeExpiredOobTokens(): Promise<void> {
  const cutoff = new Date();
  const expired = await db
    .select({ token: oobTokensTable.token })
    .from(oobTokensTable)
    .where(lt(oobTokensTable.expiresAt, cutoff));

  if (expired.length === 0) return;
  const tokens = expired.map((r) => r.token);
  await db.delete(oobInteractionsTable).where(inArray(oobInteractionsTable.token, tokens));
  await db.delete(oobTokensTable).where(inArray(oobTokensTable.token, tokens));
}
