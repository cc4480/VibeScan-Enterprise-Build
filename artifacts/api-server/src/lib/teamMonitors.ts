/**
 * The monitored sites of a team, for a teammate: what the owner's own Monitor page shows at a glance, read-only.
 *
 * Built field by field from an allowlist. A subscription row also holds the owner's account id, their email, a webhook URL
 * (which can carry a secret token in its path) and a billing reference; none of that is read into the answer, so none of it
 * can reach a teammate however the row grows. Like everything a teammate sees, it is checked against the membership on every
 * request.
 */
import { and, count, desc, eq, gte, inArray } from "drizzle-orm";
import {
  db, monitorSubscriptionsTable, monitorPulseChecksTable, monitorRegressionsTable, monitorScoreHistoryTable,
  cveAlertsTable, reportsTable, teamMembersTable,
} from "@workspace/db";
import { summariseUptime } from "./monitorPulse";

export interface SharedMonitorRow {
  /** Only for an editor, who needs it to pause or resume the site; a viewer is never given it. */
  id?: string;
  targetUrl: string;
  paused: boolean;
  grade: string | null;
  lastScanAt: string | null;
  nextScanAt: string | null;
  /** The newest hourly check: null before the first one. */
  reachable: boolean | null;
  lastCheckedAt: string | null;
  uptime24h: number | null;
  medianResponseMs: number | null;
  certDaysRemaining: number | null;
  regressionCount: number;
  cveAlertCount: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** The active monitored sites of the team with this membership id, for the teammate; null when the caller is not on that team. */
export async function sharedMonitors(viewerId: string, membershipId: string): Promise<SharedMonitorRow[] | null> {
  const [m] = await db.select({ ownerId: teamMembersTable.userId, role: teamMembersTable.role }).from(teamMembersTable)
    .where(and(eq(teamMembersTable.id, membershipId), eq(teamMembersTable.memberId, viewerId), eq(teamMembersTable.status, "active"))).limit(1);
  if (!m) return null;

  const subs = await db.select({
    id: monitorSubscriptionsTable.id,
    targetUrl: monitorSubscriptionsTable.targetUrl,
    pausedAt: monitorSubscriptionsTable.pausedAt,
    lastScanAt: monitorSubscriptionsTable.lastScanAt,
    nextScanAt: monitorSubscriptionsTable.nextScanAt,
    lastReportId: monitorSubscriptionsTable.lastReportId,
  }).from(monitorSubscriptionsTable)
    .where(and(eq(monitorSubscriptionsTable.userId, m.ownerId), eq(monitorSubscriptionsTable.status, "active")))
    .orderBy(desc(monitorSubscriptionsTable.createdAt)).limit(100);
  if (subs.length === 0) return [];

  const ids = subs.map((s) => s.id);
  const reportIds = subs.map((s) => s.lastReportId).filter((x): x is string => Boolean(x));

  const [reports, pulses, cves] = await Promise.all([
    reportIds.length ? db.select({ id: reportsTable.id, data: reportsTable.data }).from(reportsTable).where(inArray(reportsTable.id, reportIds)) : Promise.resolve([]),
    db.select({
      subscriptionId: monitorPulseChecksTable.subscriptionId, reachable: monitorPulseChecksTable.reachable,
      responseTimeMs: monitorPulseChecksTable.responseTimeMs, checkedAt: monitorPulseChecksTable.checkedAt,
      certDaysRemaining: monitorPulseChecksTable.certDaysRemaining,
    }).from(monitorPulseChecksTable)
      .where(and(inArray(monitorPulseChecksTable.subscriptionId, ids), gte(monitorPulseChecksTable.checkedAt, new Date(Date.now() - DAY_MS))))
      .orderBy(desc(monitorPulseChecksTable.checkedAt)),
    db.select({ subscriptionId: cveAlertsTable.subscriptionId, n: count() }).from(cveAlertsTable).where(inArray(cveAlertsTable.subscriptionId, ids)).groupBy(cveAlertsTable.subscriptionId),
  ]);
  const gradeOf = new Map(reports.map((r) => [r.id, (r.data as { summary?: { grade?: unknown } } | null)?.summary?.grade]));

  return Promise.all(subs.map(async (s) => {
    const mine = pulses.filter((p) => p.subscriptionId === s.id); // newest first
    const newest = mine[0] ?? null;
    const up = summariseUptime(mine);

    // Regressions of the most recent scan only, as on the owner's own page.
    const [latest] = await db.select({ scanId: monitorScoreHistoryTable.scanId }).from(monitorScoreHistoryTable)
      .where(eq(monitorScoreHistoryTable.subscriptionId, s.id)).orderBy(desc(monitorScoreHistoryTable.scannedAt)).limit(1);
    let regressionCount = 0;
    if (latest?.scanId) {
      const [{ value }] = await db.select({ value: count() }).from(monitorRegressionsTable)
        .where(and(eq(monitorRegressionsTable.subscriptionId, s.id), eq(monitorRegressionsTable.scanId, latest.scanId)));
      regressionCount = Number(value);
    }

    const grade = s.lastReportId ? gradeOf.get(s.lastReportId) : null;
    return {
      ...(m.role === "editor" ? { id: s.id } : {}),
      targetUrl: s.targetUrl,
      paused: s.pausedAt !== null,
      grade: typeof grade === "string" ? grade : null,
      lastScanAt: s.lastScanAt?.toISOString() ?? null,
      nextScanAt: s.pausedAt ? null : s.nextScanAt?.toISOString() ?? null,
      reachable: newest?.reachable ?? null,
      lastCheckedAt: newest?.checkedAt.toISOString() ?? null,
      uptime24h: up.uptimePct,
      medianResponseMs: up.medianResponseMs,
      certDaysRemaining: newest?.certDaysRemaining ?? null,
      regressionCount,
      cveAlertCount: Number(cves.find((c) => c.subscriptionId === s.id)?.n ?? 0),
    };
  }));
}
