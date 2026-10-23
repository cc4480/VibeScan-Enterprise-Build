import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { cancelMonitorSubscription, triggerManualScan, listCveAlerts, getScoreHistory, getRecentRegressions, getPulseHistory, type MonitorSubscription, type ScoreHistoryPoint } from "@/lib/monitor-api";
import { useToast } from "@/hooks/use-toast";
import { ApiError } from "@workspace/api-client-react";
import { accountErrorMessage } from "@/lib/account-api";
import { cadenceDays, daysRemaining, GRADE_NUMERIC } from "./monitor-format";

export type DrawerTab = "cve" | "regressions" | "history" | "uptime" | null;

/** All the state, queries and handlers behind one subscription card. */
export function useSubscriptionCard(sub: MonitorSubscription, onCancel: (id: string) => void) {
  const [drawer, setDrawer] = useState<DrawerTab>(null);
  const [cancelling, setCancelling] = useState(false);
  const [scanning, setScanning] = useState(false);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const alertsQuery = useQuery({
    queryKey: ["monitor-alerts", sub.id],
    queryFn: () => listCveAlerts(sub.id),
    // Loaded as soon as the site has any, so the card can list the worst of them without a click.
    enabled: drawer === "cve" || sub.alertCount > 0,
  });

  const historyQuery = useQuery({
    queryKey: ["monitor-history", sub.id],
    queryFn: () => getScoreHistory(sub.id),
    staleTime: 60_000,
  });

  const regressionQuery = useQuery({
    queryKey: ["monitor-regressions", sub.id],
    queryFn: () => getRecentRegressions(sub.id),
    enabled: drawer === "regressions" || sub.regressionCount > 0,
  });

  const pulseQuery = useQuery({
    queryKey: ["monitor-pulses", sub.id],
    queryFn: () => getPulseHistory(sub.id, 48),
    enabled: drawer === "uptime",
  });

  const days = daysRemaining(sub.expiresAt);
  const isActive = sub.status === "active";
  const historyPoints: ScoreHistoryPoint[] = historyQuery.data ?? [];
  const grade = sub.lastReport?.grade ?? null;
  const cadence = cadenceDays(grade);

  const isDown = sub.pulseReachable === false;
  const trendDirection = (() => {
    const pts = historyPoints.slice(-2);
    if (pts.length < 2) return null;
    const a = GRADE_NUMERIC[pts[0].grade] ?? 50;
    const b = GRADE_NUMERIC[pts[1].grade] ?? 50;
    if (a === b) return "flat" as const;
    return b > a ? ("up" as const) : ("down" as const);
  })();

  async function handleScanNow() {
    setScanning(true);
    try {
      await triggerManualScan(sub.id);
      toast({ title: "Scan queued", description: "A fresh full scan has started — most finish in under a minute." });
      queryClient.invalidateQueries({ queryKey: ["monitor-subscriptions"] });
    } catch (err) {
      // Show the server's reason. Most refusals are not transient: "no scans
      // left this month" or a rate limit, and "try again in a moment" sent
      // people pressing the button until the rate limit refused them too.
      const status = err instanceof ApiError ? err.status : 0;
      toast({
        title: status === 403 ? "No scans left" : status === 429 ? "Too many scans for now" : "Couldn't start the scan",
        description: accountErrorMessage(err, "Please try again in a moment."),
        variant: "destructive",
      });
    } finally {
      setScanning(false);
    }
  }

  async function handleCancel() {
    if (!confirm(`Stop monitoring ${sub.targetUrl}? This cannot be undone.`)) return;
    setCancelling(true);
    try {
      await cancelMonitorSubscription(sub.id);
      onCancel(sub.id);
    } finally {
      setCancelling(false);
    }
  }

  function toggleDrawer(tab: DrawerTab) {
    setDrawer((prev) => (prev === tab ? null : tab));
  }

  return {
    drawer, cancelling, scanning, alertsQuery, historyQuery, regressionQuery, pulseQuery, days, isActive, historyPoints,
    grade, cadence, isDown, trendDirection, handleScanNow, handleCancel, toggleDrawer,
  };
}

export type SubscriptionCardState = ReturnType<typeof useSubscriptionCard>;
