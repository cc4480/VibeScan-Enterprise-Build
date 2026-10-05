/**
 * The public grade badge: a small SVG a site owner can put in a README or a footer.
 *
 * What it shows is deliberately thin: the grade and the date of the scan. Never the
 * address that was scanned, never a finding, never a count. A badge is public by the
 * nature of where it is pasted, so it can only carry what its owner would be happy to
 * have anyone read.
 *
 * Its token is its own (see reportBadgesTable), not the report's share token: a share
 * token opens the whole report, so it must never appear in a public README.
 *
 * Three things keep a badge honest:
 *   - It is only for a scan of a domain its owner has verified (scanRanVerified and
 *     domainVerifiedBy). Without that, anyone could scan a well-run site they do not own and
 *     paste its A on their own app, and a passive-only scan's grade would read as the whole
 *     test. A badge minted before this rule shows "not verified" instead of the grade.
 *   - It shows the date. A grade with no date is a claim that never expires.
 *   - After STALE_AFTER_DAYS it goes grey and says "old scan", so a site that scanned
 *     once as an A and has changed since does not go on advertising it.
 */
import { randomBytes } from "node:crypto";
import { and, eq, isNull } from "drizzle-orm";
import { db, domainVerificationsTable, reportBadgesTable } from "@workspace/db";
import { extractDomain } from "./domainVerify";
import { verificationIsCurrent } from "./activeProbeGate";

/** A badge older than this goes grey and says so. */
export const STALE_AFTER_DAYS = 30;

export interface BadgeState {
  /** Left half. */
  label: string;
  /** Right half. */
  value: string;
  /** Right-half background. Every colour here holds white text at WCAG AA. */
  color: string;
  stale: boolean;
}

const LABEL = "SecScan";

// White text on each of these is at least 4.5:1.
const GRADE_COLOR: Record<string, string> = {
  A: "#1F7A4D",
  B: "#4A7C1F",
  C: "#8F6200",
  D: "#B34A00",
  F: "#B23A2F",
};
const NEUTRAL = "#5E6870";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "Oct 3, 2026", in UTC so the same scan reads the same everywhere. */
export function badgeDate(d: Date): string {
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()}`;
}

/**
 * What the badge says. Pure, so the rules are testable without a database.
 *
 * `grade` comes out of stored report JSON, so it is treated as untrusted: only a
 * single letter A to F is shown as a grade. Anything else, including the
 * incomplete-coverage sentinel, reads "not graded" and never echoes the stored text.
 */
export function badgeState(grade: unknown, scannedAt: Date, now: Date = new Date()): BadgeState {
  const date = badgeDate(scannedAt);
  const ageDays = (now.getTime() - scannedAt.getTime()) / 86_400_000;
  const stale = ageDays > STALE_AFTER_DAYS;

  const letter = typeof grade === "string" && /^[A-F]$/.test(grade) ? grade : null;
  if (letter === null) {
    // The incomplete-coverage sentinel ("N/A") lands here, and so would anything else
    // that is not a single letter.
    return { label: LABEL, value: `not graded · ${date}`, color: NEUTRAL, stale };
  }
  if (stale) {
    return { label: LABEL, value: `grade ${letter} · ${date} (old scan)`, color: NEUTRAL, stale: true };
  }
  return { label: LABEL, value: `grade ${letter} · ${date}`, color: GRADE_COLOR[letter]!, stale: false };
}

/**
 * The start of the ledger's reason for a test skipped because the domain is not verified
 * (NOT_VERIFIED in testLedger.ts; a test pins that it still starts with this). Matched on the
 * prefix, not the whole text, so a later rewording of the tail does not make old unverified
 * reports look verified.
 */
export const NOT_VERIFIED_PREFIX = "domain not verified";

/**
 * Did this stored report's scan run with the domain verified, so its grade covers the active
 * tests too? Read from the report's test ledger: a scan of an unverified domain records each
 * active test as skipped for that reason. A report with no ledger cannot show it either way,
 * so it does not count.
 */
export function scanRanVerified(data: unknown): boolean {
  const tests = data && typeof data === "object" ? (data as { tests?: unknown }).tests : undefined;
  if (!Array.isArray(tests) || tests.length === 0) return false;
  return !tests.some((t) => {
    if (!t || typeof t !== "object") return false;
    const { status, reason } = t as { status?: unknown; reason?: unknown };
    return status === "skipped" && typeof reason === "string" && reason.startsWith(NOT_VERIFIED_PREFIX);
  });
}

/**
 * What the badge says for a stored report: its grade (see badgeState), or "not verified" when
 * the scan skipped the active tests for want of a verified domain. That second case is a badge
 * minted before badges needed a verified scan; it keeps loading, but no longer shows a grade.
 */
export function badgeStateForReport(data: unknown, scannedAt: Date, now: Date = new Date()): BadgeState {
  if (!scanRanVerified(data)) {
    const stale = (now.getTime() - scannedAt.getTime()) / 86_400_000 > STALE_AFTER_DAYS;
    return { label: LABEL, value: `not verified · ${badgeDate(scannedAt)}`, color: NEUTRAL, stale };
  }
  const grade = (data as { summary?: { grade?: unknown } }).summary?.grade;
  return badgeState(grade, scannedAt, now);
}

/** Has this account verified the domain of `targetUrl`? The same match, expiry included, the active-test gate makes. */
export async function domainVerifiedBy(userId: string, targetUrl: string): Promise<boolean> {
  let domain: string;
  try {
    domain = extractDomain(targetUrl);
  } catch {
    return false;
  }
  const [row] = await db
    .select({ id: domainVerificationsTable.id })
    .from(domainVerificationsTable)
    .where(
      and(
        eq(domainVerificationsTable.userId, userId),
        eq(domainVerificationsTable.domain, domain),
        verificationIsCurrent(),
      ),
    )
    .limit(1);
  return Boolean(row);
}

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Width of `text` at 11px Verdana-ish, close enough to size a badge without a font. */
function textWidth(text: string): number {
  return Math.ceil(text.length * 6.4);
}

/** The badge as SVG text. Every string that goes in is escaped. */
export function renderBadgeSvg(state: BadgeState): string {
  const pad = 8;
  const leftW = textWidth(state.label) + pad * 2;
  const rightW = textWidth(state.value) + pad * 2;
  const w = leftW + rightW;
  const label = xmlEscape(state.label);
  const value = xmlEscape(state.value);
  const aria = `${state.label}: ${state.value}`;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${xmlEscape(aria)}">` +
    `<title>${xmlEscape(aria)}</title>` +
    `<rect width="${leftW}" height="20" fill="#1B2733"/>` +
    `<rect x="${leftW}" width="${rightW}" height="20" fill="${state.color}"/>` +
    `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">` +
    `<text x="${leftW / 2}" y="14">${label}</text>` +
    `<text x="${leftW + rightW / 2}" y="14">${value}</text>` +
    `</g></svg>`
  );
}

/** The grey badge shown for a token that does not resolve, so a broken embed is visible. */
export function renderMissingBadgeSvg(): string {
  return renderBadgeSvg({ label: LABEL, value: "badge not found", color: NEUTRAL, stale: false });
}

/** A fresh badge token: 24 bytes of CSPRNG output, URL-safe. */
export function mintBadgeToken(): string {
  return randomBytes(24).toString("base64url");
}

/** Tokens are base64url, so anything else is not one and never reaches the database. */
export function isBadgeToken(s: string): boolean {
  return /^[A-Za-z0-9_-]{20,64}$/.test(s);
}

/**
 * The report's live badge, minted if it has none. Idempotent on purpose: pressing
 * "get badge" twice must hand back the same image, not leave two live tokens that
 * both have to be revoked.
 */
export async function ensureReportBadge(reportId: string, userId: string): Promise<{ token: string }> {
  const [existing] = await db
    .select({ token: reportBadgesTable.token })
    .from(reportBadgesTable)
    .where(and(eq(reportBadgesTable.reportId, reportId), isNull(reportBadgesTable.revokedAt)))
    .limit(1);
  if (existing) return existing;

  const token = mintBadgeToken();
  await db.insert(reportBadgesTable).values({ reportId, userId, token });
  return { token };
}

/** The copy-paste snippets for a badge. `origin` has no trailing slash. */
export function badgeSnippets(origin: string, token: string): { imageUrl: string; markdown: string; html: string } {
  const imageUrl = `${origin}/api/badge/${token}.svg`;
  const link = `${origin}/?ref=badge`;
  return {
    imageUrl,
    markdown: `[![SecScan grade](${imageUrl})](${link})`,
    html: `<a href="${link}"><img src="${imageUrl}" alt="SecScan grade"></a>`,
  };
}
