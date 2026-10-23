/**
 * What a trust page shows, and how what an owner types is cleaned. Pure: no database, no network.
 *
 * A trust page makes a public claim in the owner's name, so it says only what a scan established and nothing it did not:
 * a grade only for a scan whose active tests ran (a verified domain), counts of findings by severity and never their
 * names, and how many tests ran out of how many. A scan older than 30 days is shown as out of date, not as current.
 */
import { summariseReport } from "./apiV1Report";
import { scanRanVerified } from "./reportBadge";

export const TRUST_STALE_AFTER_DAYS = 30;
export const DISPLAY_NAME_MAX = 80;

/** The organisation name: one line of plain text, bounded, or null when there is nothing left. */
export function cleanDisplayName(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  // Control, format (zero-width, bidirectional override) and line/paragraph separator characters become spaces.
  const text = raw.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ").replace(/\s+/g, " ").trim().slice(0, DISPLAY_NAME_MAX).trim();
  return text || null;
}

/** A #rrggbb colour, lower-cased. Empty means "none"; anything else that is not a colour is refused rather than guessed at. */
export function cleanAccent(raw: unknown): { ok: true; value: string | null } | { ok: false } {
  if (raw === undefined || raw === null || raw === "") return { ok: true, value: null };
  if (typeof raw === "string" && /^#[0-9a-fA-F]{6}$/.test(raw.trim())) return { ok: true, value: raw.trim().toLowerCase() };
  return { ok: false };
}

/** Read from storage: a stored value that is somehow not a colour is not used. */
export function safeAccent(stored: string | null | undefined): string | null {
  return stored && /^#[0-9a-f]{6}$/.test(stored) ? stored : null;
}

export interface TrustView {
  domain: string;
  displayName: string | null;
  accent: string | null;
  grade: string | null;
  scannedAt: string;
  /** True when the scan is older than TRUST_STALE_AFTER_DAYS. */
  stale: boolean;
  findings: { critical: number; high: number; medium: number; low: number; info: number; total: number } | null;
  coverage: { ran: number; total: number } | null;
}

/** The public view of one stored report, or null when it cannot support a claim (the active tests did not run). */
export function trustView(input: {
  domain: string; displayName: string | null; accent: string | null; data: unknown; scannedAt: Date; now?: Date;
}): TrustView | null {
  if (!scanRanVerified(input.data)) return null;
  const s = summariseReport(input.data);
  const ageDays = ((input.now ?? new Date()).getTime() - input.scannedAt.getTime()) / 86_400_000;
  return {
    domain: input.domain,
    displayName: input.displayName,
    accent: safeAccent(input.accent),
    grade: s.grade ?? null,
    scannedAt: input.scannedAt.toISOString(),
    stale: ageDays > TRUST_STALE_AFTER_DAYS,
    findings: s.findings ?? null,
    coverage: s.coverage ? { ran: s.coverage.ran, total: s.coverage.total } : null,
  };
}
