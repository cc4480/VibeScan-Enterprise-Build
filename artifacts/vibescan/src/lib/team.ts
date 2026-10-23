/**
 * Teams as shared viewing: the wording and the small checks. The server decides everything that matters (who is on a team,
 * what a teammate may read: api-server lib/team.ts); this only words it.
 */

export interface TeamMember { id: string; email: string; status: "pending" | "active"; createdAt: string; acceptedAt: string | null }
export interface SharedTeam { id: string; ownerEmail: string | null; since: string | null }
export interface SharedReport { id: string; targetUrl: string; scannedAt: string; tier: string; grade: string | null }

/** What the invite form checks before it sends anything; the server checks again. */
export function inviteFormError(email: string): string | null {
  const e = email.trim();
  return e.length <= 254 && /^[^\s@<>()",;:\\]+@[^\s@<>()",;:\\]+\.[^\s@<>()",;:\\]{2,}$/.test(e) ? null : "Enter the teammate's email address.";
}

/** The server's own words for a refusal, with a fallback. */
export function teamRefusal(err: unknown): string {
  const data = (err as { data?: { error?: unknown } } | null)?.data;
  return typeof data?.error === "string" ? data.error : "That did not work. Please try again.";
}

/** Whether a report was opened by a teammate rather than its owner (the server says which, in `access`). */
export function isViewOnly(report: unknown): boolean {
  return typeof report === "object" && report !== null && (report as { access?: unknown }).access === "team";
}

/** Where to send someone who is not signed in, so they come back to the invitation. Only the token travels, as a query value. */
export function signInForInvite(token: string): string {
  return `/sign-in?returnTo=${encodeURIComponent(`/team/accept?token=${token}`)}`;
}

export function memberLabel(m: Pick<TeamMember, "status">): string {
  return m.status === "pending" ? "Invited, not accepted yet" : "On your team";
}

/** "Joined 3 Oct 2026". */
export function joinedOn(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return `Joined ${d.getUTCDate()} ${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/** One monitored site of a team, as the server sends it to a teammate (api-server lib/teamMonitors.ts). Read-only. */
export interface SharedMonitor {
  targetUrl: string;
  paused: boolean;
  grade: string | null;
  lastScanAt: string | null;
  nextScanAt: string | null;
  reachable: boolean | null;
  lastCheckedAt: string | null;
  uptime24h: number | null;
  medianResponseMs: number | null;
  certDaysRemaining: number | null;
  regressionCount: number;
  cveAlertCount: number;
}

export type MonitorTone = "good" | "warn" | "bad" | "idle";

/** The one word for a site's state, in the order that matters: paused, down, needs attention, healthy, not checked yet. */
export function monitorState(m: SharedMonitor): { label: string; tone: MonitorTone } {
  if (m.paused) return { label: "Paused", tone: "idle" };
  if (m.reachable === false) return { label: "Down", tone: "bad" };
  if (m.regressionCount > 0 || m.cveAlertCount > 0 || (m.certDaysRemaining !== null && m.certDaysRemaining <= 14)) return { label: "Needs attention", tone: "warn" };
  if (m.reachable === true) return { label: "Healthy", tone: "good" };
  return { label: "Not checked yet", tone: "idle" };
}

/** The facts under the site name, only those that are known: "99.9% up · 180 ms · certificate 63 days · 2 regressions". */
export function monitorFacts(m: SharedMonitor): string[] {
  const facts: string[] = [];
  if (m.uptime24h !== null) facts.push(`${m.uptime24h}% up in 24 h`);
  if (m.medianResponseMs !== null) facts.push(`${m.medianResponseMs} ms`);
  if (m.certDaysRemaining !== null) facts.push(`certificate ${m.certDaysRemaining} day${m.certDaysRemaining === 1 ? "" : "s"}`);
  if (m.regressionCount > 0) facts.push(`${m.regressionCount} regression${m.regressionCount === 1 ? "" : "s"}`);
  if (m.cveAlertCount > 0) facts.push(`${m.cveAlertCount} CVE alert${m.cveAlertCount === 1 ? "" : "s"}`);
  return facts;
}
