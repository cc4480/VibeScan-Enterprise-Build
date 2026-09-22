import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { useSeo } from "@/lib/seo";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bell, Shield, CheckCircle2, XCircle, AlertTriangle,
  Plus, Trash2, ChevronDown, ChevronUp, ExternalLink, Loader2,
  RefreshCw, ShieldAlert, ArrowLeft, TrendingDown, TrendingUp,
  Webhook, Lock, Activity, Gauge, Clock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  listMonitorSubscriptions,
  createMonitorSubscription,
  cancelMonitorSubscription,
  triggerManualScan,
  listCveAlerts,
  getScoreHistory,
  getRecentRegressions,
  getPulseHistory,
  type MonitorSubscription,
  type CveAlert,
  type ScoreHistoryPoint,
  type MonitorRegression,
} from "@/lib/monitor-api";
import { useToast } from "@/hooks/use-toast";
import { ApiError } from "@workspace/api-client-react";
import { BuyOptions } from "@/components/billing-options";

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string }> = {
  CRITICAL: { label: "Critical", color: "text-red-400",    bg: "bg-red-400/10 border-red-400/20" },
  HIGH:     { label: "High",     color: "text-orange-400", bg: "bg-orange-400/10 border-orange-400/20" },
  MEDIUM:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-400/10 border-yellow-400/20" },
  LOW:      { label: "Low",      color: "text-green-400",  bg: "bg-green-400/10 border-green-400/20" },
  UNKNOWN:  { label: "Unknown",  color: "text-zinc-400",   bg: "bg-zinc-400/10 border-zinc-400/20" },
};

function gradeColor(grade: string | null) {
  if (!grade) return "text-muted-foreground";
  if (grade === "A" || grade === "B") return "text-green-400";
  if (grade === "C") return "text-yellow-400";
  if (grade === "D") return "text-orange-400";
  return "text-red-400";
}

/** Published cadence, so the card can explain the date it is showing. */
function cadenceDays(grade: string | null): number | null {
  if (!grade) return null;
  if (grade === "A") return 14;
  if (grade === "B" || grade === "C") return 7;
  if (grade === "D" || grade === "F") return 3;
  return null;
}

function daysRemaining(expiresAt: string): number {
  return Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86_400_000));
}

function formatDate(iso: string | null): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

/**
 * "12 min ago" rather than a timestamp.
 *
 * The whole point of the hourly check is that somebody can see at a glance that
 * the product looked recently. A formatted date makes that a subtraction the
 * reader has to do.
 */
function relativeTime(iso: string | null): string {
  if (!iso) return "not yet";
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 90) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours !== 1 ? "s" : ""} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days !== 1 ? "s" : ""} ago`;
}

/** Time until a future moment, or "due now" once it has passed. */
function untilLabel(iso: string | null): string {
  if (!iso) return "—";
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) return "due now";
  const hours = Math.round(ms / 3_600_000);
  if (hours < 24) return `in ${hours} hour${hours !== 1 ? "s" : ""}`;
  const days = Math.round(hours / 24);
  return `in ${days} day${days !== 1 ? "s" : ""}`;
}

function formatMs(ms: number | null): string {
  if (ms == null) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

// ── Score trend chart ─────────────────────────────────────────────────────────

// Letter grade to a 0–100 scale for charting. Higher is better.
const GRADE_NUMERIC: Record<string, number> = { A: 100, B: 80, C: 60, D: 40, F: 20 };

/**
 * Risk score over time, drawn to the scale the axis labels name.
 *
 * Replaces a 72px sparkline with no axis and no labels, which could show that
 * something had changed but never what or when.
 */
function ScoreTrend({ points }: { points: ScoreHistoryPoint[] }) {
  const recent = points.slice(-12);
  if (recent.length < 2) {
    return (
      <div className="flex items-center justify-center h-[120px] text-xs text-muted-foreground">
        Two scans are needed before a trend can be drawn.
      </div>
    );
  }

  const W = 520;
  const H = 120;
  const PAD_L = 28;
  const PAD_R = 8;
  const PAD_T = 12;
  const PAD_B = 22;

  const scores = recent.map((p) => GRADE_NUMERIC[p.grade] ?? 50);
  const step = (W - PAD_L - PAD_R) / (recent.length - 1);
  const yFor = (score: number) => PAD_T + (1 - score / 100) * (H - PAD_T - PAD_B);

  const coords = scores.map((s, i) => ({ x: PAD_L + i * step, y: yFor(s) }));
  const pathD = coords.map((c, i) => `${i === 0 ? "M" : "L"}${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(" ");
  const areaD = `${pathD} L${coords[coords.length - 1].x.toFixed(1)},${H - PAD_B} L${coords[0].x.toFixed(1)},${H - PAD_B} Z`;

  const first = scores[0];
  const last = scores[scores.length - 1];
  const improving = last >= first;
  const stroke = improving ? "#4ade80" : "#f87171";

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} className="min-w-[320px]" role="img"
        aria-label={`Grade trend over the last ${recent.length} scans`}>
        {/* Grade gridlines, labelled with the grades they mark */}
        {(["A", "C", "F"] as const).map((g) => (
          <g key={g}>
            <line
              x1={PAD_L} x2={W - PAD_R}
              y1={yFor(GRADE_NUMERIC[g])} y2={yFor(GRADE_NUMERIC[g])}
              stroke="currentColor" strokeWidth="1" className="text-white/8"
              strokeDasharray="3 4"
            />
            <text
              x={PAD_L - 8} y={yFor(GRADE_NUMERIC[g]) + 3}
              textAnchor="end" fontSize="9" fill="currentColor"
              className="text-muted-foreground"
            >
              {g}
            </text>
          </g>
        ))}

        <path d={areaD} fill={stroke} fillOpacity="0.08" />
        <path d={pathD} fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />

        {coords.map((c, i) => (
          <circle key={i} cx={c.x} cy={c.y} r={i === coords.length - 1 ? 3.5 : 2} fill={stroke} />
        ))}

        {/* Only the ends are labelled — twelve dates would not fit and nobody
            reads the middle of an axis on a card. */}
        <text x={PAD_L} y={H - 6} fontSize="9" fill="currentColor" className="text-muted-foreground">
          {new Date(recent[0].scannedAt).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
        </text>
        <text x={W - PAD_R} y={H - 6} textAnchor="end" fontSize="9" fill="currentColor" className="text-muted-foreground">
          {new Date(recent[recent.length - 1].scannedAt).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
        </text>
      </svg>
    </div>
  );
}

// ── Uptime strip ──────────────────────────────────────────────────────────────

/**
 * One cell per hourly check over the last day.
 *
 * Deliberately not a percentage alone: "99%" and "one hour down at 04:00" are
 * the same number and very different facts.
 */
function UptimeStrip({ timeline }: { timeline: MonitorSubscription["pulseTimeline"] }) {
  if (timeline.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        The first hourly check runs within the hour.
      </p>
    );
  }

  return (
    <div className="flex items-end gap-[3px] h-6" role="img" aria-label="Hourly checks over the last 24 hours">
      {timeline.map((pulse, i) => (
        <div
          key={i}
          title={`${new Date(pulse.checkedAt).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })} — ${
            pulse.reachable ? `up, ${formatMs(pulse.responseTimeMs)}` : "no response"
          }`}
          className={cn(
            "flex-1 min-w-[4px] rounded-sm transition-colors",
            pulse.reachable ? "bg-green-400/70 h-full" : "bg-red-400 h-full",
          )}
        />
      ))}
    </div>
  );
}

// ── Response time chart ───────────────────────────────────────────────────────

function ResponseTimeChart({ pulses }: { pulses: Array<{ checkedAt: string; responseTimeMs: number | null; reachable: boolean }> }) {
  const usable = [...pulses].reverse().filter((p) => p.reachable && p.responseTimeMs != null);
  if (usable.length < 2) {
    return <p className="text-xs text-muted-foreground py-2">Not enough successful checks yet to chart response time.</p>;
  }

  const W = 520;
  const H = 100;
  const PAD_L = 36;
  const PAD_R = 8;
  const PAD_T = 10;
  const PAD_B = 20;

  const values = usable.map((p) => p.responseTimeMs as number);
  const max = Math.max(...values);
  const min = Math.min(...values);
  // A flat line at the bottom of an empty box reads as "no data", so the scale
  // always starts at zero and leaves headroom above the peak.
  const top = Math.max(max * 1.15, 100);

  const step = (W - PAD_L - PAD_R) / (usable.length - 1);
  const yFor = (v: number) => PAD_T + (1 - v / top) * (H - PAD_T - PAD_B);
  const coords = values.map((v, i) => ({ x: PAD_L + i * step, y: yFor(v) }));
  const pathD = coords.map((c, i) => `${i === 0 ? "M" : "L"}${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(" ");

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} className="min-w-[320px]" role="img"
        aria-label="Response time per hourly check">
        {[0, top / 2, top].map((v, i) => (
          <g key={i}>
            <line x1={PAD_L} x2={W - PAD_R} y1={yFor(v)} y2={yFor(v)} stroke="currentColor" strokeWidth="1"
              className="text-white/8" strokeDasharray="3 4" />
            <text x={PAD_L - 6} y={yFor(v) + 3} textAnchor="end" fontSize="9" fill="currentColor"
              className="text-muted-foreground">
              {Math.round(v)}
            </text>
          </g>
        ))}
        <path d={pathD} fill="none" stroke="#818cf8" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx={coords[coords.length - 1].x} cy={coords[coords.length - 1].y} r="3" fill="#818cf8" />
        <text x={PAD_L} y={H - 5} fontSize="9" fill="currentColor" className="text-muted-foreground">
          ms · fastest {formatMs(min)} · slowest {formatMs(max)}
        </text>
      </svg>
    </div>
  );
}

// ── EPSS pill ─────────────────────────────────────────────────────────────────

function EpssPill({ percentile }: { percentile: number | null }) {
  if (percentile == null) return null;
  const pct = Math.round(percentile * 100);
  const color = pct >= 90 ? "text-red-400 bg-red-400/10 border-red-400/30"
    : pct >= 50 ? "text-orange-400 bg-orange-400/10 border-orange-400/30"
    : "text-zinc-400 bg-zinc-400/10 border-zinc-400/20";
  return (
    <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold border", color)}
      title="EPSS estimates the probability a vulnerability is exploited in the wild in the next 30 days">
      EPSS {pct}th%
    </span>
  );
}

function CveAlertRow({ alert }: { alert: CveAlert }) {
  const sev = SEVERITY_CONFIG[alert.severity] ?? SEVERITY_CONFIG.UNKNOWN;
  return (
    <div className="flex items-start gap-3 py-3 border-b border-white/5 last:border-0">
      <div className={cn("mt-0.5 px-2 py-0.5 rounded text-xs font-bold border shrink-0", sev.bg, sev.color)}>
        {sev.label}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
          <span className="font-mono text-xs text-indigo-400">{alert.cveId}</span>
          <span className="text-xs text-muted-foreground">· {alert.affectedTech}</span>
          <EpssPill percentile={alert.epssPercentile} />
        </div>
        <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2">{alert.cveSummary}</p>
      </div>
      <span className="text-xs text-muted-foreground shrink-0">{formatDate(alert.detectedAt)}</span>
    </div>
  );
}

function RegressionRow({ reg }: { reg: MonitorRegression }) {
  const sev = SEVERITY_CONFIG[reg.severity.toUpperCase()] ?? SEVERITY_CONFIG.UNKNOWN;
  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-white/5 last:border-0">
      <div className={cn("px-2 py-0.5 rounded text-xs font-bold border shrink-0", sev.bg, sev.color)}>
        {reg.severity}
      </div>
      <span className="text-sm flex-1 min-w-0 truncate">{reg.checkTitle}</span>
      <span className="text-xs text-muted-foreground shrink-0">{formatDate(reg.detectedAt)}</span>
    </div>
  );
}

// ── Portfolio summary ─────────────────────────────────────────────────────────

const GRADE_ORDER = ["F", "D", "C", "B", "A"];

/**
 * The state of everything being monitored, above the per-site cards.
 *
 * Someone watching eight sites should not have to read eight cards to find out
 * whether anything needs them today.
 */
function PortfolioSummary({ subs }: { subs: MonitorSubscription[] }) {
  const active = subs.filter((s) => s.status === "active");
  if (active.length === 0) return null;

  const grades = active.map((s) => s.lastReport?.grade).filter((g): g is string => Boolean(g));
  const worstGrade = grades.length
    ? grades.reduce((worst, g) => (GRADE_ORDER.indexOf(g) < GRADE_ORDER.indexOf(worst) ? g : worst), grades[0])
    : null;

  const down = active.filter((s) => s.pulseReachable === false);
  const openCves = active.reduce((sum, s) => sum + s.alertCount, 0);
  const regressions = active.reduce((sum, s) => sum + s.regressionCount, 0);

  const certs = active
    .map((s) => s.certExpiryDays)
    .filter((d): d is number => d != null && d >= 0);
  const soonestCert = certs.length ? Math.min(...certs) : null;

  const lastChecked = active
    .map((s) => s.lastPulseAt)
    .filter((t): t is string => Boolean(t))
    .sort()
    .pop() ?? null;

  const nextScan = active
    .map((s) => s.nextScanAt)
    .filter((t): t is string => Boolean(t))
    .sort()
    .shift() ?? null;

  const needsAttention = down.length > 0 || openCves > 0 || regressions > 0 || (soonestCert != null && soonestCert <= 14);

  const tiles: Array<{ label: string; value: string; tone: "good" | "warn" | "bad" | "plain"; hint?: string }> = [
    {
      label: "Sites up",
      value: `${active.length - down.length}/${active.length}`,
      tone: down.length > 0 ? "bad" : "good",
      hint: down.length > 0 ? `${down.map((s) => hostOf(s.targetUrl)).join(", ")} not responding` : undefined,
    },
    {
      label: "Worst grade",
      value: worstGrade ?? "—",
      tone: !worstGrade ? "plain" : worstGrade === "A" || worstGrade === "B" ? "good" : worstGrade === "C" ? "warn" : "bad",
    },
    {
      label: "Open CVEs",
      value: String(openCves),
      tone: openCves > 0 ? "bad" : "good",
    },
    {
      label: "Regressions",
      value: String(regressions),
      tone: regressions > 0 ? "warn" : "good",
    },
    {
      label: "Cert expires",
      value: soonestCert == null ? "—" : `${soonestCert}d`,
      tone: soonestCert == null ? "plain" : soonestCert <= 7 ? "bad" : soonestCert <= 30 ? "warn" : "good",
    },
    {
      label: "Next scan",
      value: untilLabel(nextScan).replace(/^in /, ""),
      tone: "plain",
    },
  ];

  const toneClass = {
    good: "text-green-400",
    warn: "text-yellow-400",
    bad: "text-red-400",
    plain: "text-foreground",
  } as const;

  return (
    <div className="glass-card rounded-2xl p-5">
      <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
        <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
          <Activity className="w-4 h-4 text-primary" /> Everything you are watching
        </h2>
        <span className="text-xs text-muted-foreground flex items-center gap-1.5">
          <span className={cn("w-1.5 h-1.5 rounded-full", lastChecked ? "bg-green-400" : "bg-zinc-500")} />
          Last checked {relativeTime(lastChecked)}
        </span>
      </div>

      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
        {tiles.map((tile) => (
          <div key={tile.label} className="bg-background/40 rounded-xl p-3 text-center" title={tile.hint}>
            <div className={cn("text-xl font-black tabular-nums", toneClass[tile.tone])}>{tile.value}</div>
            <div className="text-[11px] text-muted-foreground mt-0.5 leading-tight">{tile.label}</div>
          </div>
        ))}
      </div>

      <p className="text-xs text-muted-foreground mt-4 leading-relaxed">
        {needsAttention
          ? "Something on this list needs you — the affected sites are marked below."
          : "Nothing needs your attention. Every site is answering, and no new CVEs match your stacks."}
      </p>
    </div>
  );
}

function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}

// ── Subscription card ─────────────────────────────────────────────────────────

type DrawerTab = "cve" | "regressions" | "history" | "uptime" | null;

function SubscriptionCard({ sub, onCancel }: { sub: MonitorSubscription; onCancel: (id: string) => void }) {
  const [drawer, setDrawer] = useState<DrawerTab>(null);
  const [cancelling, setCancelling] = useState(false);
  const [scanning, setScanning] = useState(false);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const alertsQuery = useQuery({
    queryKey: ["monitor-alerts", sub.id],
    queryFn: () => listCveAlerts(sub.id),
    enabled: drawer === "cve",
  });

  const historyQuery = useQuery({
    queryKey: ["monitor-history", sub.id],
    queryFn: () => getScoreHistory(sub.id),
    staleTime: 60_000,
  });

  const regressionQuery = useQuery({
    queryKey: ["monitor-regressions", sub.id],
    queryFn: () => getRecentRegressions(sub.id),
    enabled: drawer === "regressions",
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
      toast({ title: "Scan queued", description: "A fresh deep scan has started — this usually takes 1–2 minutes." });
      queryClient.invalidateQueries({ queryKey: ["monitor-subscriptions"] });
    } catch {
      toast({ title: "Failed to start scan", description: "Please try again in a moment.", variant: "destructive" });
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

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className="glass-card rounded-2xl overflow-hidden"
    >
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

      <div className="p-6">
        {/* Top row */}
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
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Checked {relativeTime(sub.lastPulseAt)}
                {sub.responseTimeMs != null && !isDown && ` · ${formatMs(sub.responseTimeMs)}`}
                {isActive && ` · ${days} day${days !== 1 ? "s" : ""} left on subscription`}
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

        {/* Headline numbers */}
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

        {/* Hourly checks over the last day */}
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

        {/* Grade trend */}
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

        {/* Scan cadence — the card explains the date rather than just showing it */}
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

        {/* Links */}
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
      </div>

      {/* Drawers */}
      <AnimatePresence>
        {drawer === "uptime" && (
          <motion.div
            key="uptime"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-white/5 overflow-hidden"
          >
            <div className="p-6 pt-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                <Gauge className="w-3.5 h-3.5" /> Response time · last 48 hours
              </h4>
              {pulseQuery.isLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading checks…
                </div>
              ) : pulseQuery.data ? (
                <>
                  <ResponseTimeChart pulses={pulseQuery.data.pulses} />
                  <div className="grid grid-cols-3 gap-2 mt-4">
                    <div className="bg-background/40 rounded-xl p-3 text-center">
                      <div className="text-lg font-black tabular-nums">{pulseQuery.data.summary.checks}</div>
                      <div className="text-[11px] text-muted-foreground">Checks</div>
                    </div>
                    <div className="bg-background/40 rounded-xl p-3 text-center">
                      <div className="text-lg font-black tabular-nums">
                        {pulseQuery.data.summary.uptimePct == null ? "—" : `${pulseQuery.data.summary.uptimePct}%`}
                      </div>
                      <div className="text-[11px] text-muted-foreground">Reachable</div>
                    </div>
                    <div className="bg-background/40 rounded-xl p-3 text-center">
                      <div className="text-lg font-black tabular-nums">{formatMs(pulseQuery.data.summary.medianResponseMs)}</div>
                      <div className="text-[11px] text-muted-foreground">Median</div>
                    </div>
                  </div>
                  {pulseQuery.data.pulses.some((p) => !p.reachable) && (
                    <div className="mt-4">
                      <h5 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground mb-2">Failed checks</h5>
                      {pulseQuery.data.pulses.filter((p) => !p.reachable).slice(0, 10).map((p) => (
                        <div key={p.id} className="flex items-center gap-3 text-xs py-2 border-b border-white/5 last:border-0">
                          <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          <span className="flex-1 min-w-0 truncate text-muted-foreground">
                            {p.failureReason ?? "No response"}
                          </span>
                          <span className="text-muted-foreground shrink-0">
                            {new Date(p.checkedAt).toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-muted-foreground py-2">No checks recorded yet.</p>
              )}
            </div>
          </motion.div>
        )}

        {drawer === "history" && (
          <motion.div
            key="history"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-white/5 overflow-hidden"
          >
            <div className="p-6 pt-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5" /> Every scan
              </h4>
              {historyQuery.isLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading…
                </div>
              ) : (
                <div className="space-y-0">
                  {[...historyPoints].reverse().map((pt) => (
                    <div key={pt.id} className="flex items-center gap-3 text-xs py-2.5 border-b border-white/5 last:border-0">
                      <span className={cn("font-black text-base w-6 text-center shrink-0", gradeColor(pt.grade))}>{pt.grade}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-foreground font-medium">Risk {pt.riskScore}</div>
                        <div className="text-muted-foreground mt-0.5">
                          {pt.criticalCount > 0 && <span className="text-red-400 mr-1">{pt.criticalCount} critical</span>}
                          {pt.highCount > 0 && <span className="text-orange-400">{pt.highCount} high</span>}
                          {pt.criticalCount === 0 && pt.highCount === 0 && <span>No critical/high</span>}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-1 shrink-0">
                        <span className="text-muted-foreground">{formatDate(pt.scannedAt)}</span>
                        {pt.reportId && (
                          <a
                            href={`/report/${pt.reportId}`}
                            className="text-primary hover:underline font-medium flex items-center gap-0.5"
                          >
                            View report <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                  {historyPoints.length === 0 && (
                    <p className="text-sm text-muted-foreground py-2">No scans recorded yet.</p>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {drawer === "regressions" && (
          <motion.div
            key="regressions"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-white/5 overflow-hidden"
          >
            <div className="p-6 pt-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <TrendingDown className="w-3.5 h-3.5 text-orange-400" /> Checks that started failing
              </h4>
              {regressionQuery.isLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading…
                </div>
              ) : (
                <>
                  {regressionQuery.data?.map((reg) => <RegressionRow key={reg.id} reg={reg} />)}
                  {regressionQuery.data?.length === 0 && (
                    <p className="text-sm text-muted-foreground py-2">Nothing has regressed.</p>
                  )}
                </>
              )}
            </div>
          </motion.div>
        )}

        {drawer === "cve" && (
          <motion.div
            key="cve"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-white/5 overflow-hidden"
          >
            <div className="p-6 pt-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Bell className="w-3.5 h-3.5" /> CVEs matching this site's stack
              </h4>
              {alertsQuery.isLoading && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading alerts…
                </div>
              )}
              {alertsQuery.data?.map((alert) => (
                <CveAlertRow key={alert.id} alert={alert} />
              ))}
              {alertsQuery.data?.length === 0 && (
                <p className="text-sm text-muted-foreground py-2">No CVE matches so far.</p>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Add subscription form ─────────────────────────────────────────────────────

function AddSubscriptionForm({ onSuccess }: { onSuccess: () => void }) {
  const [url, setUrl] = useState("https://");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [showWebhook, setShowWebhook] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Set when the server says monitoring needs SecScan Pro (only once
  // MONITORING_REQUIRES_PLAN is on). The moment someone asks to monitor is the
  // moment to offer the plan — a bare error there loses the sale.
  const [refusal, setRefusal] = useState<"plan" | "limit" | null>(null);
  const { toast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setRefusal(null);
    setLoading(true);
    try {
      const result = await createMonitorSubscription(
        url.trim(),
        webhookUrl.trim() || undefined,
      );
      if (result.initialScanId) {
        toast({ title: "Monitoring activated", description: `Baseline scan queued for ${url.trim()} — results will appear shortly.` });
      } else {
        toast({ title: "Monitoring activated", description: "Using your most recent scan results. The next full scan is scheduled from your security grade." });
      }
      onSuccess();
    } catch (err: unknown) {
      // Keyed on the server's code, never on the prose, which will be reworded.
      const code = err instanceof ApiError ? (err.data as { code?: unknown } | null)?.code : undefined;
      if (code === "monitor_plan_required") setRefusal("plan");
      else if (code === "monitor_url_limit") setRefusal("limit");
      const msg = err instanceof Error ? err.message : "Failed to create subscription";
      setError(msg.replace(/^HTTP \d+ [^:]+: /, ""));
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-6">
      <h3 className="font-bold mb-4 flex items-center gap-2">
        <Plus className="w-4 h-4 text-primary" /> Monitor a new URL
      </h3>
      <div className="flex flex-col sm:flex-row gap-3 mb-3">
        <input
          id="monitor-url"
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://yourapp.com"
          required
          className="flex-1 bg-background/60 border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-primary/50 transition-colors"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-5 py-2.5 bg-primary text-primary-foreground font-semibold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] transition-all disabled:opacity-60 flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Bell className="w-4 h-4" />}
          {loading ? "Starting…" : "Start Monitoring"}
        </button>
      </div>

      <button
        type="button"
        onClick={() => setShowWebhook((x) => !x)}
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors mb-2"
      >
        <Webhook className="w-3.5 h-3.5" />
        {showWebhook ? "Hide" : "Add"} webhook (optional — Slack / Discord / Teams)
        {showWebhook ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
      </button>

      <AnimatePresence>
        {showWebhook && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <input
              id="monitor-webhook"
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full bg-background/60 border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-primary/50 transition-colors mb-2"
            />
            <p className="text-xs text-muted-foreground mb-3">
              Receives Slack-compatible JSON for CVE matches, regressions, certificate expiry, outages, configuration changes and completed scans.
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
      {refusal === "plan" && (
        <div className="mt-5">
          <BuyOptions compact />
        </div>
      )}
      {refusal === "limit" && (
        <p className="mt-2 text-sm text-muted-foreground">
          SecScan Pro covers 3 sites. Stop monitoring one below to add another, or{" "}
          <Link href="/settings#billing" className="text-primary underline underline-offset-2">see your plan</Link>.
        </p>
      )}
    </form>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function MonitorPage() {
  useSeo({ title: "Monitor — SecScan", noindex: true });
  const queryClient = useQueryClient();

  const { data: subscriptions, isLoading, error } = useQuery({
    queryKey: ["monitor-subscriptions"],
    queryFn: listMonitorSubscriptions,
    // Poll only while something is actually running.
    //
    // Without this the page fetched once and never again, so a subscription
    // created seconds earlier sat showing "Last scan: Never" while its
    // baseline scan finished half a minute later and the card never moved.
    // The data was being written correctly the whole time — it just never
    // arrived on screen, which is indistinguishable from broken.
    //
    // Conditional rather than a blanket interval because this endpoint runs
    // several queries per subscription; polling it forever would be a steady
    // cost for a page that is usually static. The hourly pulse does not need
    // polling — nobody sits watching for an event that arrives once an hour.
    refetchInterval: (query) => {
      const subs = query.state.data;
      if (!subs?.length) return false;
      const busy = subs.some((s) => s.status === "active" && (s.scanInProgress || !s.lastScanAt));
      return busy ? 5_000 : false;
    },
  });

  function handleCancelled(_id: string) {
    queryClient.invalidateQueries({ queryKey: ["monitor-subscriptions"] });
  }

  function handleAdded() {
    queryClient.invalidateQueries({ queryKey: ["monitor-subscriptions"] });
  }

  const active = subscriptions?.filter((s) => s.status === "active") ?? [];
  const inactive = subscriptions?.filter((s) => s.status !== "active") ?? [];

  return (
    <div className="max-w-3xl mx-auto px-4 py-10 space-y-8">
      {/* Header */}
      <div>
        <Link href="/dashboard" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground mb-6 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
        <h1 className="text-3xl font-black mb-2 flex items-center gap-3">
          <Bell className="w-7 h-7 text-primary" /> Continuous Monitoring
        </h1>
        <p className="text-muted-foreground max-w-lg">
          Hourly availability and configuration checks, risk-adaptive deep scans, and alerts when a new CVE matches your stack.
        </p>
      </div>

      {/* Portfolio summary — above the cards, so eight sites do not mean
          reading eight cards to find the one that needs attention. */}
      {!isLoading && subscriptions && <PortfolioSummary subs={subscriptions} />}

      {/* How it works */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {[
          {
            icon: Gauge,
            title: "Hourly Checks",
            desc: "Every monitored URL is checked once an hour: is it up, how fast did it answer, is the certificate still valid, and did any security header disappear.",
            color: "text-primary",
            bg: "bg-primary/10",
          },
          {
            icon: RefreshCw,
            title: "Adaptive Deep Scans",
            desc: "Full scans follow your risk grade: A every 14 days, B and C every 7, D and F every 3. A deep scan is heavy, so it is scheduled — not run hourly.",
            color: "text-green-400",
            bg: "bg-green-400/10",
          },
          {
            icon: ShieldAlert,
            title: "CVE Alerts + EPSS",
            desc: "The NVD feed is checked hourly against your detected stack and enriched with EPSS exploit probability. A new match triggers an immediate rescan.",
            color: "text-indigo-400",
            bg: "bg-indigo-400/10",
          },
          {
            icon: TrendingDown,
            title: "Regressions & Drift",
            desc: "Each scan is compared with the last, and each hourly check with the one before. Anything that weakens your posture is emailed and posted to your webhook.",
            color: "text-orange-400",
            bg: "bg-orange-400/10",
          },
        ].map((item) => (
          <div key={item.title} className="glass-card p-5 rounded-2xl flex gap-4">
            <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center shrink-0", item.bg, item.color)}>
              <item.icon className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm mb-1">{item.title}</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">{item.desc}</p>
            </div>
          </div>
        ))}
      </div>

      <AddSubscriptionForm onSuccess={handleAdded} />

      {isLoading && (
        <div className="flex items-center gap-3 text-muted-foreground py-8 justify-center">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Loading subscriptions…</span>
        </div>
      )}

      {error && (
        <div className="glass-card rounded-2xl p-6 text-center text-sm text-red-400">
          Could not load your monitors. Refresh to try again.
        </div>
      )}

      {!isLoading && active.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-400" /> Active ({active.length})
          </h2>
          <AnimatePresence>
            {active.map((sub) => (
              <SubscriptionCard key={sub.id} sub={sub} onCancel={handleCancelled} />
            ))}
          </AnimatePresence>
        </div>
      )}

      {!isLoading && inactive.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <XCircle className="w-4 h-4 text-zinc-500" /> Inactive ({inactive.length})
          </h2>
          <AnimatePresence>
            {inactive.map((sub) => (
              <SubscriptionCard key={sub.id} sub={sub} onCancel={handleCancelled} />
            ))}
          </AnimatePresence>
        </div>
      )}

      {!isLoading && !error && subscriptions?.length === 0 && (
        <div className="text-center py-16 text-muted-foreground">
          <Bell className="w-12 h-12 mx-auto mb-4 opacity-20" />
          <p className="text-lg font-semibold mb-2">No monitors yet</p>
          <p className="text-sm">Add a URL above to start continuous monitoring.</p>
        </div>
      )}
    </div>
  );
}
