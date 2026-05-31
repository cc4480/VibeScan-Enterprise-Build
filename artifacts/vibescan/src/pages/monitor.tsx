import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { useSeo } from "@/lib/seo";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bell, Shield, Globe, CheckCircle2, XCircle, Clock, AlertTriangle,
  Plus, Trash2, ChevronDown, ChevronUp, ExternalLink, Loader2,
  RefreshCw, CalendarClock, ShieldAlert, ArrowLeft, TrendingDown,
  Webhook, Lock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  listMonitorSubscriptions,
  createMonitorSubscription,
  cancelMonitorSubscription,
  listCveAlerts,
  getScoreHistory,
  getRecentRegressions,
  type MonitorSubscription,
  type CveAlert,
  type ScoreHistoryPoint,
  type MonitorRegression,
} from "@/lib/monitor-api";
import { useToast } from "@/hooks/use-toast";

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string }> = {
  CRITICAL: { label: "Critical", color: "text-red-400",    bg: "bg-red-400/10 border-red-400/20" },
  HIGH:     { label: "High",     color: "text-orange-400", bg: "bg-orange-400/10 border-orange-400/20" },
  MEDIUM:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-400/10 border-yellow-400/20" },
  LOW:      { label: "Low",      color: "text-green-400",  bg: "bg-green-400/10 border-green-400/20" },
  UNKNOWN:  { label: "Unknown",  color: "text-slate-400",  bg: "bg-slate-400/10 border-slate-400/20" },
};

function gradeColor(grade: string | null) {
  if (!grade) return "text-muted-foreground";
  if (grade === "A") return "text-emerald-400";
  if (grade === "B") return "text-green-400";
  if (grade === "C") return "text-yellow-400";
  if (grade === "D") return "text-orange-400";
  return "text-red-400";
}

function daysRemaining(expiresAt: string): number {
  return Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86_400_000));
}

function formatDate(iso: string | null): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function nextScanLabel(sub: MonitorSubscription): string {
  if (!sub.nextScanAt) {
    if (!sub.lastScanAt) return "Pending initial scan";
    const next = new Date(sub.lastScanAt);
    next.setDate(next.getDate() + 7);
    return `~${formatDate(next.toISOString())}`;
  }
  const d = new Date(sub.nextScanAt);
  if (d <= new Date()) return "Soon";
  return `~${formatDate(sub.nextScanAt)}`;
}

// ── SVG Sparkline ─────────────────────────────────────────────────────────────

function Sparkline({ points, width = 120, height = 36 }: { points: ScoreHistoryPoint[]; width?: number; height?: number }) {
  if (points.length < 2) {
    return <span className="text-xs text-muted-foreground italic">—</span>;
  }

  const scores = points.map((p) => p.riskScore);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const range = max - min || 1;

  const step = width / (scores.length - 1);
  const coords = scores.map((s, i) => ({
    x: i * step,
    y: height - ((s - min) / range) * (height - 4) - 2,
  }));

  const pathD = coords
    .map((c, i) => `${i === 0 ? "M" : "L"}${c.x.toFixed(1)},${c.y.toFixed(1)}`)
    .join(" ");

  const last = coords[coords.length - 1];
  const prev = coords[coords.length - 2];
  const trendUp = last && prev ? last.y < prev.y : false; // lower y = higher risk score

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible">
      <path
        d={pathD}
        fill="none"
        stroke={trendUp ? "#f87171" : "#34d399"}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {last && (
        <circle cx={last.x} cy={last.y} r="2.5" fill={trendUp ? "#f87171" : "#34d399"} />
      )}
    </svg>
  );
}

// ── EPSS pill ─────────────────────────────────────────────────────────────────

function EpssPill({ percentile }: { percentile: number | null }) {
  if (percentile == null) return null;
  const pct = Math.round(percentile * 100);
  const color = pct >= 90 ? "text-red-400 bg-red-400/10 border-red-400/30"
    : pct >= 50 ? "text-orange-400 bg-orange-400/10 border-orange-400/30"
    : "text-slate-400 bg-slate-400/10 border-slate-400/20";
  return (
    <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold border", color)}>
      EPSS {pct}th%
    </span>
  );
}

// ── CVE Alert row ─────────────────────────────────────────────────────────────

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

// ── Regression row ────────────────────────────────────────────────────────────

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

// ── Subscription card ─────────────────────────────────────────────────────────

type DrawerTab = "cve" | "regressions" | "history" | null;

function SubscriptionCard({ sub, onCancel }: { sub: MonitorSubscription; onCancel: (id: string) => void }) {
  const [drawer, setDrawer] = useState<DrawerTab>(null);
  const [cancelling, setCancelling] = useState(false);

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

  const days = daysRemaining(sub.expiresAt);
  const isActive = sub.status === "active";
  const historyPoints: ScoreHistoryPoint[] = historyQuery.data ?? [];

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
      {/* Cert expiry warning banner */}
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
          TLS certificate expires in {sub.certExpiryDays} day{sub.certExpiryDays !== 1 ? "s" : ""} — renew immediately
        </div>
      )}

      <div className="p-6">
        {/* Top row */}
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className={cn("w-2 h-2 rounded-full shrink-0 mt-1", isActive ? "bg-emerald-400" : "bg-slate-500")} />
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
                    ? "bg-emerald-400/10 border-emerald-400/20 text-emerald-400"
                    : "bg-slate-400/10 border-slate-400/20 text-slate-400",
                )}>
                  {sub.status === "active" ? "Active" : sub.status === "cancelled" ? "Cancelled" : "Expired"}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Subscribed {formatDate(sub.subscribedAt)}
                {isActive && ` · ${days} day${days !== 1 ? "s" : ""} remaining`}
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
                onClick={handleCancel}
                disabled={cancelling}
                className="p-2 rounded-lg hover:bg-red-400/10 text-muted-foreground hover:text-red-400 transition-colors"
                title="Cancel subscription"
              >
                {cancelling ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
              </button>
            )}
          </div>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-4 gap-2 mb-4">
          <div className="bg-background/40 rounded-xl p-3 text-center">
            <div className={cn("text-2xl font-black", gradeColor(sub.lastReport?.grade ?? null))}>
              {sub.lastReport?.grade ?? "—"}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">Last Grade</div>
          </div>
          <div className="bg-background/40 rounded-xl p-3 text-center">
            <div className="text-sm font-semibold truncate">{formatDate(sub.lastScanAt)}</div>
            <div className="text-xs text-muted-foreground mt-0.5">Last Scan</div>
          </div>
          <div className="bg-background/40 rounded-xl p-3 text-center">
            <div className="text-sm font-semibold truncate">{isActive ? nextScanLabel(sub) : "—"}</div>
            <div className="text-xs text-muted-foreground mt-0.5">Next Scan</div>
          </div>
          <div className="bg-background/40 rounded-xl p-3 flex flex-col items-center justify-center gap-0.5">
            {historyPoints.length >= 2 ? (
              <>
                <Sparkline points={historyPoints} width={72} height={26} />
                <div className="text-xs text-muted-foreground">Trend</div>
              </>
            ) : (
              <>
                <div className="text-sm font-semibold text-muted-foreground">—</div>
                <div className="text-xs text-muted-foreground">Trend</div>
              </>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-3">
            {sub.lastReportId && (
              <Link
                href={`/report/${sub.lastReportId}`}
                className="text-xs font-medium text-primary hover:underline flex items-center gap-1"
              >
                <Shield className="w-3.5 h-3.5" /> View latest report
              </Link>
            )}
            {sub.webhookUrl && (
              <span className="flex items-center gap-1 text-xs text-muted-foreground" title={sub.webhookUrl}>
                <Webhook className="w-3 h-3" /> Webhook active
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {historyPoints.length > 0 && (
              <button
                onClick={() => toggleDrawer("history")}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                {drawer === "history" ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                {drawer === "history" ? "Hide" : "Show"} history
              </button>
            )}
            {sub.alertCount > 0 && (
              <button
                onClick={() => toggleDrawer("cve")}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                {drawer === "cve" ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                {drawer === "cve" ? "Hide" : "Show"} CVEs
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Drawers */}
      <AnimatePresence>
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
                <RefreshCw className="w-3.5 h-3.5" /> Score History
              </h4>
              {historyQuery.isLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading…
                </div>
              ) : (
                <div className="space-y-0">
                  {historyPoints.map((pt) => (
                    <div key={pt.id} className="flex items-center gap-3 text-xs py-2 border-b border-white/5 last:border-0">
                      <span className={cn("font-black text-base w-6 text-center shrink-0", gradeColor(pt.grade))}>{pt.grade}</span>
                      <div className="flex-1">
                        <span className="text-foreground font-medium">Risk {pt.riskScore}</span>
                        <span className="text-muted-foreground ml-2">
                          {pt.criticalCount > 0 && <span className="text-red-400">{pt.criticalCount}C </span>}
                          {pt.highCount > 0 && <span className="text-orange-400">{pt.highCount}H</span>}
                        </span>
                      </div>
                      <span className="text-muted-foreground shrink-0">{formatDate(pt.scannedAt)}</span>
                    </div>
                  ))}
                  {historyPoints.length === 0 && (
                    <p className="text-sm text-muted-foreground py-2">No history yet.</p>
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
                <TrendingDown className="w-3.5 h-3.5 text-orange-400" /> Regressions (last 30 days)
              </h4>
              {regressionQuery.isLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                  <Loader2 className="w-4 h-4 animate-spin" /> Loading…
                </div>
              ) : (
                <>
                  {regressionQuery.data?.map((reg) => <RegressionRow key={reg.id} reg={reg} />)}
                  {regressionQuery.data?.length === 0 && (
                    <p className="text-sm text-muted-foreground py-2">No regressions found.</p>
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
                <Bell className="w-3.5 h-3.5" /> CVE Alerts
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
                <p className="text-sm text-muted-foreground py-2">No CVE alerts yet.</p>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Add subscription dialog ───────────────────────────────────────────────────

function AddSubscriptionForm({ onSuccess }: { onSuccess: () => void }) {
  const [url, setUrl] = useState("https://");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [showWebhook, setShowWebhook] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await createMonitorSubscription(
        url.trim(),
        webhookUrl.trim() || undefined,
      );
      if (result.initialScanId) {
        toast({ title: "Monitoring activated", description: `Baseline scan queued for ${url.trim()} — results will appear shortly.` });
      } else {
        toast({ title: "Monitoring activated", description: `Using your most recent scan results. Next automated rescan scheduled based on your security grade.` });
      }
      onSuccess();
    } catch (err: unknown) {
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
      <div className="flex gap-3 mb-3">
        <input
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
          className="px-5 py-2.5 bg-primary text-primary-foreground font-semibold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] transition-all disabled:opacity-60 flex items-center gap-2"
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
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full bg-background/60 border border-white/10 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-primary/50 transition-colors mb-2"
            />
            <p className="text-xs text-muted-foreground mb-3">
              Receives Slack-compatible JSON payloads for CVE alerts, regressions, cert expiry, and scan completions.
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
    </form>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function MonitorPage() {
  useSeo({ title: "Monitor — Seclayer", noindex: true });
  const queryClient = useQueryClient();

  const { data: subscriptions, isLoading, error } = useQuery({
    queryKey: ["monitor-subscriptions"],
    queryFn: listMonitorSubscriptions,
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
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-black mb-2 flex items-center gap-3">
              <Bell className="w-7 h-7 text-primary" /> Continuous Monitoring
            </h1>
            <p className="text-muted-foreground max-w-lg">
              Risk-adaptive rescans + instant alerts when new CVEs match your tech stack. $129/yr per URL.
            </p>
          </div>
        </div>
      </div>

      {/* How it works */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {[
          {
            icon: RefreshCw,
            title: "Adaptive Rescans",
            desc: "Scan cadence adapts to your risk grade: A grades rescan every 14 days, B/C every 7, D/F every 3.",
            color: "text-emerald-400",
            bg: "bg-emerald-400/10",
          },
          {
            icon: ShieldAlert,
            title: "CVE Alerts + EPSS",
            desc: "Daily NVD feed checks enriched with EPSS exploit probability scores. Matches trigger an immediate rescan.",
            color: "text-indigo-400",
            bg: "bg-indigo-400/10",
          },
          {
            icon: TrendingDown,
            title: "Regression Detection",
            desc: "Each rescan is compared to the previous. Any newly failing check triggers an email and optional webhook.",
            color: "text-orange-400",
            bg: "bg-orange-400/10",
          },
          {
            icon: Lock,
            title: "Cert Expiry Alerts",
            desc: "TLS certificate expiry is checked daily. Alerts fire at 30, 14, and 7 days before expiry.",
            color: "text-sky-400",
            bg: "bg-sky-400/10",
          },
        ].map((item, i) => (
          <div key={i} className="glass-card p-5 rounded-2xl flex gap-4">
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

      {/* Add new subscription */}
      <AddSubscriptionForm onSuccess={handleAdded} />

      {/* Active subscriptions */}
      {isLoading && (
        <div className="flex items-center gap-3 text-muted-foreground py-8 justify-center">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Loading subscriptions…</span>
        </div>
      )}

      {error && (
        <div className="glass-card rounded-2xl p-6 text-center text-sm text-red-400">
          Failed to load subscriptions. Please refresh.
        </div>
      )}

      {!isLoading && active.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Active ({active.length})
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
            <XCircle className="w-4 h-4 text-slate-500" /> Inactive ({inactive.length})
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
