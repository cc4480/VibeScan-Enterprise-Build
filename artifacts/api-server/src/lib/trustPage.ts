/**
 * Trust pages: the owner's side (choose a verified domain, name it, colour it, turn it on or off) and the public read.
 * What a page may show, and how the owner's text is cleaned, is in trustPageView.ts.
 *
 * A page exists only for a domain the account has verified, one account per domain. The public read re-checks that on every
 * request: it needs the page switched on, the owner's verification still current, and a scan of that domain whose active tests
 * ran. Any one missing and the answer is the same "not available", so a visitor cannot tell a page that is off from one that
 * never existed, or a lapsed verification from either.
 */
import { and, desc, eq, gt } from "drizzle-orm";
import { db, domainVerificationsTable, reportsTable, trustPagesTable } from "@workspace/db";
import { extractDomain, verificationCutoff } from "./domainVerify";
import { domainVerifiedBy } from "./reportBadge";
import { cleanAccent, cleanDisplayName, trustView, type TrustView } from "./trustPageView";

export type Failure = { ok: false; status: 400 | 403 | 409; code: string; message: string };
const fail = (status: Failure["status"], code: string, message: string): Failure => ({ ok: false, status, code, message });

/** The normalised hostname of what the owner typed (a bare host or a URL), or null. */
export function domainOf(input: string): string | null {
  try {
    const d = extractDomain(input);
    return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d) && d.length <= 253 ? d : null;
  } catch {
    return null;
  }
}

export interface MyTrustPages {
  pages: Array<{ domain: string; enabled: boolean; displayName: string | null; accent: string | null }>;
  /** Verified domains with no page yet, so the owner can pick one. */
  available: string[];
}

export async function myTrustPages(userId: string): Promise<MyTrustPages> {
  const pages = await db.select({
    domain: trustPagesTable.domain, enabled: trustPagesTable.enabled, displayName: trustPagesTable.displayName, accent: trustPagesTable.accent,
  }).from(trustPagesTable).where(eq(trustPagesTable.userId, userId)).orderBy(trustPagesTable.domain);
  const verified = await db.select({ domain: domainVerificationsTable.domain }).from(domainVerificationsTable)
    .where(and(eq(domainVerificationsTable.userId, userId), gt(domainVerificationsTable.verifiedAt, verificationCutoff())));
  const have = new Set(pages.map((p) => p.domain));
  return { pages, available: verified.map((v) => v.domain).filter((d) => !have.has(d)).sort() };
}

export async function saveTrustPage(userId: string, domainInput: string, body: { displayName?: unknown; accent?: unknown; enabled?: unknown }): Promise<{ ok: true; domain: string } | Failure> {
  const domain = domainOf(domainInput);
  if (!domain) return fail(400, "bad_domain", "Enter a domain such as shop.example.com.");
  const accent = cleanAccent(body.accent);
  if (!accent.ok) return fail(400, "bad_accent", "The colour must look like #1a73e8.");
  // Only a domain this account has verified, and only while that verification is current.
  if (!(await domainVerifiedBy(userId, `https://${domain}/`))) {
    return fail(403, "not_verified", "Verify this domain first (Domains). A trust page can only speak for a domain you have proved you control.");
  }
  const [existing] = await db.select({ userId: trustPagesTable.userId }).from(trustPagesTable).where(eq(trustPagesTable.domain, domain));
  if (existing && existing.userId !== userId) return fail(409, "domain_taken", "Another account already has a trust page for this domain.");

  const values = { displayName: cleanDisplayName(body.displayName), accent: accent.value, enabled: body.enabled === false ? false : true, updatedAt: new Date() };
  await db.insert(trustPagesTable).values({ userId, domain, ...values })
    .onConflictDoUpdate({ target: trustPagesTable.domain, set: values, setWhere: eq(trustPagesTable.userId, userId) });
  return { ok: true, domain };
}

export async function deleteTrustPage(userId: string, domainInput: string): Promise<void> {
  const domain = domainOf(domainInput);
  if (domain) await db.delete(trustPagesTable).where(and(eq(trustPagesTable.userId, userId), eq(trustPagesTable.domain, domain)));
}

/** The public view for a domain, or null for every reason there is nothing to show. */
export async function publicTrustView(domainInput: string, now: Date = new Date()): Promise<TrustView | null> {
  const domain = domainOf(domainInput);
  if (!domain) return null;
  const [page] = await db.select().from(trustPagesTable).where(eq(trustPagesTable.domain, domain));
  if (!page || !page.enabled) return null;
  if (!(await domainVerifiedBy(page.userId, `https://${domain}/`))) return null;

  // The newest scans of this owner; the first one of this domain whose active tests ran speaks for it.
  const recent = await db.select({ targetUrl: reportsTable.targetUrl, scannedAt: reportsTable.scannedAt, data: reportsTable.data })
    .from(reportsTable).where(eq(reportsTable.userId, page.userId)).orderBy(desc(reportsTable.scannedAt)).limit(100);
  for (const r of recent) {
    if (domainOf(r.targetUrl) !== domain) continue;
    const view = trustView({ domain, displayName: page.displayName, accent: page.accent, data: r.data, scannedAt: r.scannedAt, now });
    if (view) return view;
  }
  return null;
}
