import { customFetch } from "@workspace/api-client-react";

export interface MonitorSubscription {
  id: string;
  userId: string;
  userEmail: string;
  targetUrl: string;
  status: "active" | "cancelled" | "expired";
  subscribedAt: string;
  expiresAt: string;
  lastScanAt: string | null;
  lastReportId: string | null;
  nextScanAt: string | null;
  webhookUrl: string | null;
  /** When the owner paused this monitor; null while it is running. */
  pausedAt: string | null;
  /** Days between full rescans, when the owner picked one; null means the default (set by the grade). */
  scanIntervalDays: number | null;
  createdAt: string;
  lastReport: { id: string; grade: string | null; riskScore: number | null } | null;
  alertCount: number;
  regressionCount: number;
  certExpiryDays: number | null;
  /** False once monitoring runs on a paid plan: then the plan ends it, not expiresAt. */
  expiryApplies?: boolean;
  /** A scan for this target is queued or running right now. */
  scanInProgress: boolean;
  /** Which stage it is at, when one is running: queued | scanning | analyzing. */
  scanStatus: string | null;

  // ── The hourly pulse check ──
  // A full rescan happens every 3–14 days depending on grade, so everything
  // above can legitimately be a fortnight old. These are never more than an
  // hour old, and they are what tells a user the product is still watching.
  /** When the site was last checked. Null until the first hourly pulse runs. */
  lastPulseAt: string | null;
  /** Whether it answered. Null if no pulse has run yet. */
  pulseReachable: boolean | null;
  pulseStatus: number | null;
  pulseFailureReason: string | null;
  responseTimeMs: number | null;
  /** Percentage of the last 24 hours' checks that reached the site. */
  uptime24h: number | null;
  medianResponseMs: number | null;
  pulseChecks24h: number;
  /** The last 24 hours of checks, oldest first, for the uptime strip. */
  pulseTimeline: Array<{ checkedAt: string; reachable: boolean; responseTimeMs: number | null }>;
}

export interface PulseCheck {
  id: string;
  checkedAt: string;
  reachable: boolean;
  httpStatus: number | null;
  responseTimeMs: number | null;
  certDaysRemaining: number | null;
  failureReason: string | null;
  presentHeaders: string[] | null;
}

export interface PulseWindow {
  pulses: PulseCheck[];
  summary: { uptimePct: number | null; medianResponseMs: number | null; checks: number };
  windowHours: number;
}

export interface CveAlert {
  id: string;
  subscriptionId: string;
  cveId: string;
  cveSummary: string;
  affectedTech: string;
  severity: string;
  epssScore: number | null;
  epssPercentile: number | null;
  triggerScanId: string | null;
  detectedAt: string;
}

export interface ScoreHistoryPoint {
  id: string;
  subscriptionId: string;
  scanId: string | null;
  grade: string;
  riskScore: number;
  criticalCount: number;
  highCount: number;
  scannedAt: string;
  reportId: string | null;
}

export interface MonitorRegression {
  id: string;
  subscriptionId: string;
  scanId: string | null;
  checkId: string;
  checkTitle: string;
  severity: string;
  detectedAt: string;
}

export async function listMonitorSubscriptions(): Promise<MonitorSubscription[]> {
  return customFetch<MonitorSubscription[]>("/api/monitor/subscriptions");
}

export async function createMonitorSubscription(
  targetUrl: string,
  webhookUrl?: string,
): Promise<{
  subscription: MonitorSubscription;
  initialScanId: string | null;
  /** An earlier scan of this site that was found and is shown on the card while the baseline scan runs. */
  seededFrom?: { reportId: string; scannedAt: string; grade: string | null } | null;
}> {
  return customFetch("/api/monitor/subscriptions", {
    method: "POST",
    body: JSON.stringify({ targetUrl, webhookUrl: webhookUrl || undefined }),
    headers: { "Content-Type": "application/json" },
  });
}

export async function cancelMonitorSubscription(id: string): Promise<void> {
  await customFetch(`/api/monitor/subscriptions/${id}`, { method: "DELETE" });
}

export const SCAN_INTERVAL_CHOICES = [3, 7, 14, 30] as const;

/** `null` goes back to the default, where the site's grade sets how often it is rescanned. */
export async function setMonitorInterval(id: string, days: number | null): Promise<void> {
  await customFetch(`/api/monitor/subscriptions/${id}/interval`, {
    method: "PATCH",
    body: JSON.stringify({ days }),
    headers: { "Content-Type": "application/json" },
  });
}

export async function setMonitorPaused(id: string, paused: boolean): Promise<void> {
  await customFetch(`/api/monitor/subscriptions/${id}/pause`, {
    method: "PATCH",
    body: JSON.stringify({ paused }),
    headers: { "Content-Type": "application/json" },
  });
}

export async function listCveAlerts(subscriptionId: string): Promise<CveAlert[]> {
  return customFetch<CveAlert[]>(`/api/monitor/subscriptions/${subscriptionId}/alerts`);
}

export interface ScanHistoryEntry {
  id: string;
  scanId: string | null;
  scannedAt: string;
  tier: string;
  grade: string | null;
  riskScore: number | null;
  vulnCount: number | null;
}

export async function listSubscriptionHistory(subscriptionId: string): Promise<ScanHistoryEntry[]> {
  return customFetch<ScanHistoryEntry[]>(`/api/monitor/subscriptions/${subscriptionId}/history`);
}

export async function getScoreHistory(subscriptionId: string): Promise<ScoreHistoryPoint[]> {
  return customFetch<ScoreHistoryPoint[]>(`/api/monitor/subscriptions/${subscriptionId}/score-history`);
}

export async function getRecentRegressions(subscriptionId: string): Promise<MonitorRegression[]> {
  return customFetch<MonitorRegression[]>(`/api/monitor/subscriptions/${subscriptionId}/regressions`);
}

export async function getPulseHistory(subscriptionId: string, hours = 48): Promise<PulseWindow> {
  return customFetch<PulseWindow>(
    `/api/monitor/subscriptions/${subscriptionId}/pulses?hours=${hours}`,
  );
}

export async function triggerManualScan(subscriptionId: string): Promise<{ scanId: string }> {
  return customFetch(`/api/monitor/subscriptions/${subscriptionId}/scan`, { method: "POST" });
}
