import type { SubscriptionCardState } from "./monitor-card-state";
import { AlertTriangle, Trash2, ExternalLink, Loader2, RefreshCw, TrendingDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { MonitorPauseButton } from "@/components/monitor-pause-button";
import { type MonitorSubscription } from "@/lib/monitor-api";
import { relativeTime, formatMs } from "./monitor-format";

/** The card's top row: site, status, badges and the scan / pause / cancel actions. */
export function SubscriptionHeader({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { cancelling, scanning, days, isActive, isDown, handleScanNow, handleCancel, toggleDrawer } = card;
  return (
    <div className="flex items-start justify-between gap-4 mb-4">
      <div className="flex items-center gap-3 min-w-0">
        <div className={cn(
          "w-2 h-2 rounded-full shrink-0 mt-1",
          !isActive ? "bg-zinc-500" : isDown ? "bg-red-400" : "bg-green-400",
        )} />
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <a
              href={sub.targetUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="font-semibold text-foreground hover:text-primary transition-colors flex items-center gap-1 truncate max-w-xs"
            >
              {sub.targetUrl}
              <ExternalLink className="w-3 h-3 shrink-0" />
            </a>
            <span className={cn(
              "px-2 py-0.5 rounded-full text-xs font-semibold border",
              isActive
                ? "bg-green-400/10 border-green-400/20 text-green-400"
                : "bg-zinc-400/10 border-zinc-400/20 text-zinc-400",
            )}>
              {sub.status === "active" ? "Active" : sub.status === "cancelled" ? "Cancelled" : "Expired"}
            </span>
            {isActive && sub.pausedAt && (
              <span className="px-2 py-0.5 rounded-full text-xs font-semibold border bg-amber-400/10 border-amber-400/20 text-amber-400" title="No scans, uptime checks or alerts until you resume">
                Paused
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Checked {relativeTime(sub.lastPulseAt)}
            {sub.responseTimeMs != null && !isDown && ` · ${formatMs(sub.responseTimeMs)}`}
            {isActive && sub.expiryApplies !== false && ` · ${days} day${days !== 1 ? "s" : ""} left on subscription`}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
        {sub.regressionCount > 0 && (
          <button
            onClick={() => toggleDrawer("regressions")}
            className="flex items-center gap-1 px-2 py-1 rounded-lg bg-orange-400/10 border border-orange-400/20 hover:bg-orange-400/20 transition-colors"
          >
            <TrendingDown className="w-3.5 h-3.5 text-orange-400" />
            <span className="text-xs font-bold text-orange-400">{sub.regressionCount} regression{sub.regressionCount > 1 ? "s" : ""}</span>
          </button>
        )}
        {sub.alertCount > 0 && (
          <button
            onClick={() => toggleDrawer("cve")}
            className="flex items-center gap-1 px-2 py-1 rounded-lg bg-red-400/10 border border-red-400/20 hover:bg-red-400/20 transition-colors"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            <span className="text-xs font-bold text-red-400">{sub.alertCount} CVE{sub.alertCount > 1 ? "s" : ""}</span>
          </button>
        )}
        {isActive && (
          <button
            onClick={handleScanNow}
            disabled={scanning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary/10 border border-primary/20 hover:bg-primary/20 text-primary text-xs font-semibold transition-colors disabled:opacity-50"
            title="Run a full deep scan right now"
          >
            {scanning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            {scanning ? "Scanning…" : "Scan Now"}
          </button>
        )}
        {isActive && <MonitorPauseButton sub={sub} />}
        {isActive && (
          <button
            onClick={handleCancel}
            disabled={cancelling}
            className="p-2 rounded-lg hover:bg-red-400/10 text-muted-foreground hover:text-red-400 transition-colors"
            title="Stop monitoring this URL"
          >
            {cancelling ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
          </button>
        )}
      </div>
    </div>
  );
}
