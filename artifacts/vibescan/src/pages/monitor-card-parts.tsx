import type { SubscriptionCardState } from "./monitor-card-state";
import { Link } from "wouter";
import { Shield, XCircle, ChevronDown, ChevronUp, Loader2, TrendingDown, TrendingUp, Webhook, Lock, Gauge, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import { type MonitorSubscription } from "@/lib/monitor-api";
import { gradeColor, formatDate, relativeTime, untilLabel, formatMs } from "./monitor-format";
import { ScoreTrend, UptimeStrip } from "./monitor-charts";

/** Banners above everything else on the card: the site is not answering, or its certificate is about to lapse. */
export function SubscriptionBanners({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { isDown } = card;
  return (
    <>
      {/* Site is not answering. Above everything else on the card, because it
          makes every number below it historical. */}
      {isDown && (
        <div className="flex items-center gap-2 px-5 py-2.5 text-xs font-semibold border-b bg-red-400/10 border-red-400/20 text-red-400">
          <XCircle className="w-3.5 h-3.5 shrink-0" />
          Not responding as of {relativeTime(sub.lastPulseAt)}
          {sub.pulseFailureReason ? ` — ${sub.pulseFailureReason}` : ""}
        </div>
      )}

      {/* Cert expiry warning */}
      {sub.certExpiryDays != null && sub.certExpiryDays <= 30 && (
        <div className={cn(
          "flex items-center gap-2 px-5 py-2.5 text-xs font-semibold border-b",
          sub.certExpiryDays <= 7
            ? "bg-red-400/10 border-red-400/20 text-red-400"
            : sub.certExpiryDays <= 14
            ? "bg-orange-400/10 border-orange-400/20 text-orange-400"
            : "bg-yellow-400/10 border-yellow-400/20 text-yellow-400",
        )}>
          <Lock className="w-3.5 h-3.5 shrink-0" />
          TLS certificate expires in {sub.certExpiryDays} day{sub.certExpiryDays !== 1 ? "s" : ""} — renew before it lapses
        </div>
      )}
    </>
  );
}

/** A scan is running right now. */
export function ScanInProgressNotice({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { scanning } = card;
  return (
    <>
      {/* A scan is running right now. Shown because the alternative — the
          card sitting on stale values with no sign of life — is what made a
          working baseline scan look like nothing had happened at all. */}
      {sub.scanInProgress && (
        <div className="flex items-center gap-2 mb-4 px-3 py-2 rounded-xl bg-primary/10 border border-primary/20">
          <Loader2 className="w-3.5 h-3.5 animate-spin text-primary shrink-0" />
          <span className="text-xs text-primary font-medium">
            {sub.scanStatus === "analyzing"
              ? "Analysing results…"
              : sub.scanStatus === "scanning"
              ? "Scanning now — this usually takes 1–2 minutes"
              : "Scan queued…"}
          </span>
        </div>
      )}
    </>
  );
}

/** Grade, uptime, median response and certificate days. */
export function HeadlineNumbers({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { grade } = card;
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
      <div className="bg-background/40 rounded-xl p-3 text-center">
        <div className={cn("text-2xl font-black", gradeColor(grade))}>{grade ?? "—"}</div>
        <div className="text-[11px] text-muted-foreground mt-0.5">
          {sub.lastReport?.riskScore != null ? `Risk ${sub.lastReport.riskScore}` : "Last grade"}
        </div>
      </div>
      <div className="bg-background/40 rounded-xl p-3 text-center">
        <div className={cn(
          "text-2xl font-black tabular-nums",
          sub.uptime24h == null ? "text-muted-foreground"
            : sub.uptime24h >= 99.9 ? "text-green-400"
            : sub.uptime24h >= 95 ? "text-yellow-400"
            : "text-red-400",
        )}>
          {sub.uptime24h == null ? "—" : `${sub.uptime24h}%`}
        </div>
        <div className="text-[11px] text-muted-foreground mt-0.5">
          Uptime · {sub.pulseChecks24h} check{sub.pulseChecks24h !== 1 ? "s" : ""}/24h
        </div>
      </div>
      <div className="bg-background/40 rounded-xl p-3 text-center">
        <div className="text-2xl font-black tabular-nums">{formatMs(sub.medianResponseMs)}</div>
        <div className="text-[11px] text-muted-foreground mt-0.5">Median response</div>
      </div>
      <div className="bg-background/40 rounded-xl p-3 text-center">
        <div className={cn(
          "text-2xl font-black tabular-nums",
          sub.certExpiryDays == null ? "text-muted-foreground"
            : sub.certExpiryDays <= 7 ? "text-red-400"
            : sub.certExpiryDays <= 30 ? "text-yellow-400"
            : "text-green-400",
        )}>
          {sub.certExpiryDays == null ? "—" : `${sub.certExpiryDays}d`}
        </div>
        <div className="text-[11px] text-muted-foreground mt-0.5">TLS cert left</div>
      </div>
    </div>
  );
}

/** The last day of hourly checks. */
export function HourlyChecks({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { drawer, toggleDrawer } = card;
  return (
    <div className="bg-background/40 rounded-xl p-4 mb-4">
      <div className="flex items-center justify-between mb-2.5 gap-2 flex-wrap">
        <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
          <Gauge className="w-3.5 h-3.5" /> Hourly checks · last 24h
        </span>
        <button
          onClick={() => toggleDrawer("uptime")}
          className="text-xs text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
        >
          {drawer === "uptime" ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          48-hour detail
        </button>
      </div>
      <UptimeStrip timeline={sub.pulseTimeline} />
    </div>
  );
}

/** Grade over time. */
export function GradeTrend({ card }: { card: SubscriptionCardState }) {
  const { historyPoints, trendDirection } = card;
  return (
    <div className="bg-background/40 rounded-xl p-4 mb-4">
      <div className="flex items-center justify-between mb-1 gap-2 flex-wrap">
        <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5" /> Grade over time
        </span>
        {trendDirection && (
          <span className={cn(
            "text-xs font-semibold flex items-center gap-1",
            trendDirection === "up" ? "text-green-400" : trendDirection === "down" ? "text-red-400" : "text-muted-foreground",
          )}>
            {trendDirection === "up" ? <TrendingUp className="w-3.5 h-3.5" />
              : trendDirection === "down" ? <TrendingDown className="w-3.5 h-3.5" />
              : null}
            {trendDirection === "up" ? "Improved" : trendDirection === "down" ? "Worse than last scan" : "Unchanged"}
          </span>
        )}
      </div>
      <ScoreTrend points={historyPoints} />
    </div>
  );
}

/** When the next scan is, and why. */
export function ScanCadence({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { days, isActive, grade, cadence } = card;
  return (
    <div className="flex items-start gap-2 text-xs text-muted-foreground mb-4">
      <Clock className="w-3.5 h-3.5 shrink-0 mt-0.5" />
      <span className="leading-relaxed">
        {!isActive
          ? "Monitoring is stopped for this URL."
          : sub.nextScanAt
          ? <>Next full scan {untilLabel(sub.nextScanAt)} ({formatDate(sub.nextScanAt)}){cadence ? ` — grade ${grade} is rescanned every ${cadence} days` : ""}. Availability and configuration are checked every hour in between.</>
          : "First full scan is queued. Availability and configuration are checked every hour."}
      </span>
    </div>
  );
}

/** Latest report, webhook and drawer toggles. */
export function SubscriptionLinks({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { drawer, historyPoints, toggleDrawer } = card;
  return (
    <div className="flex items-center justify-between flex-wrap gap-2">
      <div className="flex items-center gap-3 flex-wrap">
        {sub.lastReportId && (
          <Link
            href={`/report/${sub.lastReportId}`}
            className="text-xs font-medium text-primary hover:underline flex items-center gap-1"
          >
            <Shield className="w-3.5 h-3.5" /> View latest report
          </Link>
        )}
        {sub.webhookUrl && (
          <span className="flex items-center gap-1 text-xs text-muted-foreground" title="Alerts are also posted to your webhook">
            <Webhook className="w-3 h-3" /> Webhook active
          </span>
        )}
      </div>
      <div className="flex items-center gap-3">
        {sub.pulseTimeline.length > 0 && (
          <button
            onClick={() => toggleDrawer("uptime")}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {drawer === "uptime" ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            48-hour detail
          </button>
        )}
        {historyPoints.length > 0 && (
          <button
            onClick={() => toggleDrawer("history")}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {drawer === "history" ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            Every scan
          </button>
        )}
        {sub.alertCount > 0 && (
          <button
            onClick={() => toggleDrawer("cve")}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {drawer === "cve" ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            CVEs
          </button>
        )}
      </div>
    </div>
  );
}

