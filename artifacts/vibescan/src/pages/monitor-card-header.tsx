import type { SubscriptionCardState } from "./monitor-card-state";
import { AlertTriangle, Trash2, ExternalLink, Loader2, RefreshCw, TrendingDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { MonitorPauseButton } from "@/components/monitor-pause-button";
import { MonitorIntervalSelect } from "@/components/monitor-interval-select";
import { type MonitorSubscription } from "@/lib/monitor-api";
import { relativeTime, formatMs } from "./monitor-format";
import { siteStatus, STATUS_TONE } from "./monitor-card-sections";
import { safeHref } from "@/lib/safe-href";

/** The card's top row: site, status, badges and the scan / pause / cancel actions. */
export function SubscriptionHeader({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { cancelling, scanning, days, isActive, isDown, handleScanNow, handleCancel, toggleDrawer } = card;
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4 mb-4">
      <div className="flex items-center gap-3 min-w-0">
        <div className={cn(
          "w-2 h-2 rounded-full shrink-0 mt-1",
          !isActive ? "bg-zinc-500" : isDown ? "bg-red-400" : "bg-green-400",
        )} />
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {safeHref(sub.targetUrl) ? (
              <a
                href={safeHref(sub.targetUrl)}
                target="_blank"
                rel="noopener noreferrer"
                className="font-semibold text-foreground hover:text-primary transition-colors flex items-center gap-1 truncate max-w-[16rem] sm:max-w-xs"
              >
                {sub.targetUrl}
                <ExternalLink className="w-3 h-3 shrink-0" />
              </a>
            ) : (
              <span className="font-semibold text-foreground flex items-center gap-1 truncate max-w-[16rem] sm:max-w-xs">
                {sub.targetUrl}
              </span>
            )}
            {/* One pill for the site's state: Healthy, Needs attention, Down, Scanning, Paused, Getting started. */}
            <span className={cn("px-2 py-0.5 rounded-full text-xs font-semibold border", STATUS_TONE[siteStatus(sub).tone])}>
              {siteStatus(sub).label}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Checked {relativeTime(sub.lastPulseAt)}
            {sub.responseTimeMs != null && !isDown && ` · ${formatMs(sub.responseTimeMs)}`}
            {isActive && sub.expiryApplies !== false && ` · ${days} day${days !== 1 ? "s" : ""} left on subscription`}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 flex-wrap sm:justify-end">
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
        {isActive && <MonitorIntervalSelect sub={sub} />}
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
