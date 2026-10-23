/**
 * The words on a trust page. The server decides what may be shown (api-server lib/trustPageView.ts); this only words it, and
 * never says more than the server returned: a scan the server marks out of date is said to be out of date, and a missing
 * grade is left out rather than guessed.
 */

export interface TrustView {
  domain: string;
  displayName: string | null;
  accent: string | null;
  grade: string | null;
  scannedAt: string;
  stale: boolean;
  findings: { critical: number; high: number; medium: number; low: number; info: number; total: number } | null;
  coverage: { ran: number; total: number } | null;
}

/** An accent is used in a style attribute, so it is checked here too, whatever the server sent. */
export function accentOrNull(value: string | null | undefined): string | null {
  return value && /^#[0-9a-f]{6}$/.test(value) ? value : null;
}

const MS_DAY = 86_400_000;

/** "Scanned today", "Scanned 3 days ago", or an out-of-date warning with the age. */
export function freshness(scannedAt: string, stale: boolean, now: Date = new Date()): { text: string; warn: boolean } {
  const days = Math.max(0, Math.floor((now.getTime() - new Date(scannedAt).getTime()) / MS_DAY));
  const when = days === 0 ? "today" : days === 1 ? "yesterday" : `${days} days ago`;
  return stale
    ? { text: `Last scanned ${when}. This scan is out of date and may no longer describe the site.`, warn: true }
    : { text: `Scanned ${when}.`, warn: false };
}

/** "No findings", or "1 critical, 2 high, 3 low" (only the kinds there are), most serious first. */
export function findingsLine(f: TrustView["findings"]): string | null {
  if (!f) return null;
  if (f.total === 0) return "No findings.";
  const parts = (["critical", "high", "medium", "low", "info"] as const).filter((k) => f[k] > 0).map((k) => `${f[k]} ${k}`);
  return `${f.total} finding${f.total === 1 ? "" : "s"}: ${parts.join(", ")}.`;
}

export function coverageLine(c: TrustView["coverage"]): string | null {
  return c ? `${c.ran} of ${c.total} tests ran.` : null;
}

/** What the page is called: the owner's name, or the domain. */
export function heading(v: Pick<TrustView, "displayName" | "domain">): string {
  return v.displayName ?? v.domain;
}
