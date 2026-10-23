/** The sections of a monitor card: the overview row, what needs attention, and the checklist a brand-new site shows. */
import { Link } from "wouter";
import { AlertTriangle, CheckCircle2, Circle, Loader2, TrendingDown, ShieldCheck, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import { type MonitorSubscription } from "@/lib/monitor-api";
import type { SubscriptionCardState } from "./monitor-card-state";
import { SEVERITY_CONFIG, formatDate, relativeTime, untilLabel } from "./monitor-format";
import { GradeRing, SecurityTrend, ResponsePanel, CertBar } from "./monitor-viz";

/** The site's state in one word, for the pill beside its name. */
export function siteStatus(sub: MonitorSubscription): { label: string; tone: "good" | "warn" | "bad" | "info" | "muted" } {
  if (sub.status !== "active") return { label: sub.status === "cancelled" ? "Cancelled" : "Expired", tone: "muted" };
  if (sub.pausedAt) return { label: "Paused", tone: "warn" };
  if (sub.pulseReachable === false) return { label: "Down", tone: "bad" };
  if (sub.scanInProgress) return { label: "Scanning", tone: "info" };
  if (!sub.lastReport && !sub.lastPulseAt) return { label: "Getting started", tone: "info" };
  const cert = sub.certExpiryDays;
  if (sub.alertCount > 0 || sub.regressionCount > 0 || (cert != null && cert <= 14)) return { label: "Needs attention", tone: "warn" };
  return { label: "Healthy", tone: "good" };
}

export const STATUS_TONE = {
  good: "bg-emerald-400/10 border-emerald-400/25 text-emerald-300",
  warn: "bg-amber-400/10 border-amber-400/25 text-amber-300",
  bad: "bg-red-400/10 border-red-400/25 text-red-300",
  info: "bg-sky-400/10 border-sky-400/25 text-sky-300",
  muted: "bg-zinc-400/10 border-zinc-400/20 text-zinc-400",
} as const;

/** True until the site has anything to chart: no finished scan and no hourly check yet. */
export const isBrandNew = (sub: MonitorSubscription): boolean => !sub.lastReport && sub.pulseTimeline.length === 0;

/** Grade ring beside the three numbers that say how the site is doing, and the certificate bar. */
export function OverviewRow({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const { grade } = card;
  return (
    <div className="mb-5 flex flex-col gap-5 sm:flex-row sm:items-center">
      <div className="flex items-center gap-5">
        <GradeRing grade={grade} riskScore={sub.lastReport?.riskScore ?? null} />
        <div className="space-y-2.5 sm:hidden">
          <CertBar days={sub.certExpiryDays} />
        </div>
      </div>
      <div className="grid flex-1 grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
        <Fact label="Last full scan" value={sub.lastScanAt ? relativeTime(sub.lastScanAt) : "not yet"} hint={sub.lastScanAt ? formatDate(sub.lastScanAt) : undefined} />
        <Fact label="Next full scan" value={sub.nextScanAt ? untilLabel(sub.nextScanAt) : "—"} hint={sub.nextScanAt ? formatDate(sub.nextScanAt) : undefined} />
        <Fact
          label="Open issues"
          value={String(sub.alertCount + sub.regressionCount)}
          hint={`${sub.alertCount} CVE${sub.alertCount === 1 ? "" : "s"} · ${sub.regressionCount} regression${sub.regressionCount === 1 ? "" : "s"}`}
          tone={sub.alertCount + sub.regressionCount > 0 ? "text-amber-300" : "text-emerald-300"}
        />
        <div className="col-span-2 hidden sm:col-span-3 sm:block"><CertBar days={sub.certExpiryDays} /></div>
      </div>
    </div>
  );
}

function Fact({ label, value, hint, tone = "text-foreground" }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={cn("truncate text-lg font-black leading-tight", tone)}>{value}</div>
      {hint && <div className="truncate text-[11px] text-muted-foreground">{hint}</div>}
    </div>
  );
}

/** The two charts, each in its own panel. */
export function ChartPanels({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const hasTrend = card.historyPoints.length >= 2;
  const hasPulse = sub.pulseTimeline.length > 0;
  if (!hasTrend && !hasPulse) return null;
  return (
    <div className={cn("mb-5 grid gap-4", hasTrend && hasPulse ? "lg:grid-cols-2" : "")}>
      {hasTrend && <div className="rounded-xl bg-background/40 p-4"><SecurityTrend points={card.historyPoints} /></div>}
      {hasPulse && <div className="rounded-xl bg-background/40 p-4"><ResponsePanel sub={sub} /></div>}
    </div>
  );
}

/** The worst CVEs and the regressions, listed on the card. The drawers below still hold the full lists. */
export function AttentionList({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const alerts = [...(card.alertsQuery.data ?? [])]
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (b.epssScore ?? 0) - (a.epssScore ?? 0))
    .slice(0, 3);
  const regressions = (card.regressionQuery.data ?? []).slice(0, 3);
  const hasAny = alerts.length > 0 || regressions.length > 0;

  if (!hasAny) {
    // Only claim it is clean once it has actually been scanned.
    if (!sub.lastReport || card.alertsQuery.isLoading || card.regressionQuery.isLoading) return null;
    return (
      <div className="mb-5 flex items-center gap-2.5 rounded-xl border border-emerald-400/20 bg-emerald-400/5 px-4 py-3 text-sm text-emerald-200">
        <ShieldCheck className="h-4 w-4 shrink-0" /> No open CVEs or regressions. Each scan is compared with the last, and any new match is flagged here.
      </div>
    );
  }

  return (
    <div className="mb-5 rounded-xl border border-white/8 bg-background/40">
      <div className="flex items-center justify-between border-b border-white/8 px-4 py-2.5">
        <span className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <AlertTriangle className="h-3.5 w-3.5 text-amber-400" /> Needs attention
        </span>
        <span className="text-[11px] text-muted-foreground">worst first</span>
      </div>
      <ul className="divide-y divide-white/6">
        {alerts.map((a) => {
          const sev = SEVERITY_CONFIG[a.severity.toUpperCase()] ?? SEVERITY_CONFIG.UNKNOWN!;
          return (
            <li key={a.id} className="flex items-start gap-3 px-4 py-3">
              <span className={cn("mt-0.5 shrink-0 rounded-md border px-1.5 py-0.5 text-[10px] font-bold uppercase", sev.bg, sev.color)}>{sev.label}</span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-2 text-sm">
                  <span className="font-semibold">{a.cveId}</span>
                  <span className="text-xs text-muted-foreground">{a.affectedTech}</span>
                  {a.epssScore != null && (
                    <span className="rounded bg-white/6 px-1.5 text-[10px] font-semibold text-muted-foreground" title="EPSS: the modelled chance this CVE is exploited in the next 30 days">
                      {Math.round(a.epssScore * 100)}% exploit chance
                    </span>
                  )}
                </div>
                <p className="truncate text-xs text-muted-foreground" title={a.cveSummary}>{a.cveSummary}</p>
              </div>
              <span className="shrink-0 text-[11px] text-muted-foreground">{relativeTime(a.detectedAt)}</span>
            </li>
          );
        })}
        {regressions.map((g) => {
          const sev = SEVERITY_CONFIG[g.severity.toUpperCase()] ?? SEVERITY_CONFIG.UNKNOWN!;
          return (
            <li key={g.id} className="flex items-start gap-3 px-4 py-3">
              <span className={cn("mt-0.5 shrink-0 rounded-md border px-1.5 py-0.5 text-[10px] font-bold uppercase", sev.bg, sev.color)}>{sev.label}</span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5 text-sm font-semibold"><TrendingDown className="h-3.5 w-3.5 text-orange-400" /> {g.checkTitle}</div>
                <p className="text-xs text-muted-foreground">A regression: this was fine on the previous scan.</p>
              </div>
              <span className="shrink-0 text-[11px] text-muted-foreground">{relativeTime(g.detectedAt)}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

const sevRank = (s: string) => ({ critical: 4, high: 3, medium: 2, low: 1 } as Record<string, number>)[s.toLowerCase()] ?? 0;

/** What a site that was just added shows instead of rows of dashes: where it is and what comes next. */
export function GettingStarted({ sub, card }: { sub: MonitorSubscription; card: SubscriptionCardState }) {
  const scanDone = Boolean(sub.lastReport) && !sub.scanInProgress;
  const scanning = sub.scanInProgress;
  const pulseDone = Boolean(sub.lastPulseAt);
  const trendDone = card.historyPoints.length >= 2;
  const steps: Array<{ title: string; detail: string; state: "done" | "running" | "waiting" }> = [
    {
      title: "Baseline security scan",
      detail: scanDone ? `Done ${relativeTime(sub.lastScanAt)}${sub.lastReport?.grade ? `: grade ${sub.lastReport.grade}` : ""}.` : scanning ? "Running now. Most scans finish in one to two minutes." : "Queued; it starts as soon as a worker is free.",
      state: scanDone ? "done" : scanning ? "running" : "waiting",
    },
    {
      title: "First hourly check",
      detail: pulseDone ? `Last checked ${relativeTime(sub.lastPulseAt)}.` : "Within the hour: whether the site answers, how fast, and its certificate.",
      state: pulseDone ? "done" : "waiting",
    },
    {
      title: "Security trend",
      detail: trendDone ? "Two scans are in, so the trend chart is drawn above." : `Drawn once a second scan is in${sub.nextScanAt ? `, due ${untilLabel(sub.nextScanAt)}` : ""}. Until then the grade ring is your starting point.`,
      state: trendDone ? "done" : "waiting",
    },
    {
      title: "CVE watch",
      detail: "Starts once the first scan has identified the site's software; new matches are listed here and sent to you.",
      state: scanDone ? "done" : "waiting",
    },
  ];
  return (
    <div className="mb-5 rounded-xl border border-white/8 bg-background/40 p-4">
      <div className="mb-3 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
        <Clock className="h-3.5 w-3.5" /> Getting started
      </div>
      <ol className="space-y-3">
        {steps.map((s) => (
          <li key={s.title} className="flex gap-3">
            <span className="mt-0.5 shrink-0">
              {s.state === "done" ? <CheckCircle2 className="h-4.5 w-4.5 text-emerald-400" />
                : s.state === "running" ? <Loader2 className="h-4.5 w-4.5 animate-spin text-sky-300" />
                : <Circle className="h-4.5 w-4.5 text-zinc-600" />}
            </span>
            <div>
              <div className={cn("text-sm font-semibold", s.state === "waiting" && "text-muted-foreground")}>{s.title}</div>
              <div className="text-xs leading-relaxed text-muted-foreground">{s.detail}</div>
            </div>
          </li>
        ))}
      </ol>
      {sub.lastReportId && (
        <Link href={`/report/${sub.lastReportId}`} className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline">
          <ShieldCheck className="h-3.5 w-3.5" /> View the scan this started from
        </Link>
      )}
    </div>
  );
}
