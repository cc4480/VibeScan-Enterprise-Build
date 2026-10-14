import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { useListScans } from "@workspace/api-client-react";
import { Shield, RefreshCw, Loader2, ArrowRight, Bell, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { listMonitorSubscriptions } from "@/lib/monitor-api";
import { PurchaseResultBanner } from "@/components/billing-summary";
import { ScanRow } from "./dashboard-rows";

export default function DashboardPage() {
  useSeo({ title: "Dashboard — SecScan.us", noindex: true });
  const params = new URLSearchParams(
    typeof window !== "undefined" ? window.location.search : "",
  );
  const highlightScanId = params.get("scan");

  const { data: scans, isLoading: loadingScans, isError: scansFailed, refetch } = useListScans();
  const { data: monitors } = useQuery({
    queryKey: ["monitor-subscriptions"],
    queryFn: listMonitorSubscriptions,
  });

  if (loadingScans) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  // A failed request used to fall through to the counters and the empty state,
  // so someone with a page full of scans was told they had none — with nothing
  // to retry. "You have no scans" and "we could not load your scans" cannot
  // share a rendering.
  if (scansFailed) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[60vh] px-4">
        <div className="text-center max-w-sm">
          <AlertTriangle className="w-8 h-8 text-yellow-400 mx-auto mb-4" />
          <h2 className="text-lg font-semibold mb-2">Could not load your scans</h2>
          <p className="text-sm text-muted-foreground mb-6">
            This is a problem reaching the server, not a problem with your account —
            your scans are safe.
          </p>
          <button
            type="button"
            onClick={() => void refetch()}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium"
          >
            <RefreshCw className="w-4 h-4" /> Try again
          </button>
        </div>
      </div>
    );
  }

  const completedCount = scans?.filter((s) => s.status === 'complete').length ?? 0;
  const activeMonitors = monitors?.filter((m) => m.status === 'active') ?? [];
  const pendingCveAlerts = activeMonitors.reduce((sum, m) => sum + m.alertCount, 0);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      {/* No page-level "New Scan" CTA here -- the global header nav (Layout)
          already has one fixed on every page, and having both stacked
          right on top of each other read as a duplicated button. */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground mt-1">Manage your security scans and reports.</p>
      </div>

      {/* Stripe returns people here with ?purchase=…; say what happened. */}
      <PurchaseResultBanner />

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2">
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Total Scans
          </div>
          <div className="text-4xl font-bold">{scans?.length ?? 0}</div>
        </div>

        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2">
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2">
            <Shield className="w-4 h-4 text-green-400" /> Completed
          </div>
          <div className="text-4xl font-bold">{completedCount}</div>
        </div>

        <Link
          href="/monitor"
          className={cn(
            "glass-card p-6 rounded-2xl flex flex-col gap-2 relative overflow-hidden group transition-colors hover:border-indigo-500/30",
            pendingCveAlerts > 0 && "border-red-400/30",
          )}
        >
          <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2 relative z-10">
            <Bell className="w-4 h-4 text-indigo-400" /> Active Monitors
          </div>
          <div className="flex items-end justify-between relative z-10">
            <div className={cn("text-4xl font-bold", activeMonitors.length > 0 ? "text-indigo-400" : "")}>
              {activeMonitors.length}
            </div>
            {pendingCveAlerts > 0 ? (
              <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-red-400/10 border border-red-400/20 pb-1">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                <span className="text-xs font-bold text-red-400">{pendingCveAlerts} CVE{pendingCveAlerts > 1 ? "s" : ""}</span>
              </div>
            ) : activeMonitors.length === 0 ? (
              <span className="text-xs font-medium text-indigo-400 hover:underline underline-offset-4 pb-1">
                Set up &rarr;
              </span>
            ) : (
              <span className="text-xs font-medium text-indigo-400 pb-1">
                Watching &rarr;
              </span>
            )}
          </div>
        </Link>
      </div>

      {/* Scan table */}
      <div className="glass-panel rounded-2xl overflow-hidden">
        {scans && scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 bg-secondary/50">
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Target</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden sm:table-cell">Type</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden md:table-cell">Security</th>
                  <th className="p-4 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <ScanRow
                    key={scan.id}
                    initialScan={scan}
                    highlight={scan.id === highlightScanId}
                  />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-24 px-6 text-center flex flex-col items-center">
            <div className="w-16 h-16 bg-secondary rounded-2xl flex items-center justify-center mb-4 border border-white/5">
              <Shield className="w-8 h-8 text-muted-foreground opacity-50" />
            </div>
            <h3 className="text-xl font-bold mb-2">No scans yet</h3>
            <p className="text-muted-foreground max-w-sm mb-6">
              You haven&apos;t run any security scans yet. Launch your first scan to see how secure your app is.
            </p>
            <Link
              href="/scan"
              className="px-6 py-3 bg-secondary hover:bg-white/10 text-foreground font-semibold rounded-xl transition-colors border border-white/5 flex items-center gap-2"
            >
              Start your first scan <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}