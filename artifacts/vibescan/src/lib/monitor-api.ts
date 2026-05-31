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
  createdAt: string;
  lastReport: { id: string; grade: string | null; riskScore: number | null } | null;
  alertCount: number;
  regressionCount: number;
  certExpiryDays: number | null;
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
): Promise<{ subscription: MonitorSubscription; initialScanId: string | null }> {
  return customFetch("/api/monitor/subscriptions", {
    method: "POST",
    body: JSON.stringify({ targetUrl, webhookUrl: webhookUrl || undefined }),
    headers: { "Content-Type": "application/json" },
  });
}

export async function cancelMonitorSubscription(id: string): Promise<void> {
  await customFetch(`/api/monitor/subscriptions/${id}`, { method: "DELETE" });
}

export async function listCveAlerts(subscriptionId: string): Promise<CveAlert[]> {
  return customFetch<CveAlert[]>(`/api/monitor/subscriptions/${subscriptionId}/alerts`);
}

export async function getScoreHistory(subscriptionId: string): Promise<ScoreHistoryPoint[]> {
  return customFetch<ScoreHistoryPoint[]>(`/api/monitor/subscriptions/${subscriptionId}/history`);
}

export async function getRecentRegressions(subscriptionId: string): Promise<MonitorRegression[]> {
  return customFetch<MonitorRegression[]>(`/api/monitor/subscriptions/${subscriptionId}/regressions`);
}

export async function triggerManualScan(subscriptionId: string): Promise<{ scanId: string }> {
  return customFetch(`/api/monitor/subscriptions/${subscriptionId}/scan`, { method: "POST" });
}
