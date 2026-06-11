import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bell, AlertTriangle, Trash2, ChevronDown, ChevronUp,
  ExternalLink, Loader2, Shield, Plus,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  listCveAlerts,
  cancelMonitorSubscription,
  createMonitorSubscription,
  type MonitorSubscription,
  type CveAlert,
} from "@/lib/monitor-api";
import { useToast } from "@/hooks/use-toast";

export const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string }> = {
  CRITICAL: { label: "Critical", color: "text-red-400",    bg: "bg-red-400/10 border-red-400/20" },
  HIGH:     { label: "High",     color: "text-orange-400", bg: "bg-orange-400/10 border-orange-400/20" },
  MEDIUM:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-400/10 border-yellow-400/20" },
  LOW:      { label: "Low",      color: "text-green-400",  bg: "bg-green-400/10 border-green-400/20" },
  UNKNOWN:  { label: "Unknown",  color: "text-slate-400",  bg: "bg-slate-400/10 border-slate-400/20" },
};

export function gradeColor(grade: string | null) {
  if (!grade) return "text-muted-foreground";
  if (grade === "A") return "text-emerald-400";
  if (grade === "B") return "text-green-400";
  if (grade === "C") return "text-yellow-400";
  if (grade === "D") return "text-orange-400";
  return "text-red-400";
}

export function daysRemaining(expiresAt: string): number {
  return Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86_400_000));
}

export function formatDate(iso: string | null): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export function nextScanDate(sub: MonitorSubscription): string {
  if (!sub.lastScanAt) return "Pending initial scan";
  const next = new Date(sub.lastScanAt);
  next.setDate(next.getDate() + 7);
  return `~${formatDate(next.toISOString())}`;
}

export function CveAlertRow({ alert }: { alert: CveAlert }) {
  const sev = SEVERITY_CONFIG[alert.severity] ?? SEVERITY_CONFIG.UNKNOWN;
  return (
    <div className="flex items-start gap-3 py-3 border-b border-white/5 last:border-0">
      <div className={cn("mt-0.5 px-2 py-0.5 rounded text-xs font-bold border", sev.bg, sev.color)}>
        {sev.label}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="font-mono text-xs text-indigo-400">{alert.cveId}</span>
          <span className="text-xs text-muted-foreground">· {alert.affectedTech}</span>
        </div>
        <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2">{alert.cveSummary}</p>
      </div>
      <span className="text-xs text-muted-foreground shrink-0">{formatDate(alert.detectedAt)}</span>
    </div>
  );
}

export function SubscriptionCard({ sub, onCancel }: { sub: MonitorSubscription; onCancel: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  const alertsQuery = useQuery({
    queryKey: ["monitor-alerts", sub.id],
    queryFn: () => listCveAlerts(sub.id),
    enabled: expanded,
  });

  const days = daysRemaining(sub.expiresAt);
  const isActive = sub.status === "active";

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

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className="glass-card rounded-2xl overflow-hidden"
    >
      <div className="p-6">
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

          <div className="flex items-center gap-2 shrink-0">
            {sub.alertCount > 0 && (
              <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-red-400/10 border border-red-400/20">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                <span className="text-xs font-bold text-red-400">{sub.alertCount} CVE{sub.alertCount > 1 ? "s" : ""}</span>
              </div>
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

        <div className="grid grid-cols-3 gap-3 mb-4">
          <div className="bg-background/40 rounded-xl p-3 text-center">
            <div className={cn("text-2xl font-black", gradeColor(sub.lastReport?.grade ?? null))}>
              {sub.lastReport?.grade ?? "—"}
            </div>
            <div className="text-xs text-muted-foreground mt-0.5">Last Grade</div>
          </div>
          <div className="bg-background/40 rounded-xl p-3 text-center">
            <div className="text-sm font-semibold">{formatDate(sub.lastScanAt)}</div>
            <div className="text-xs text-muted-foreground mt-0.5">Last Scan</div>
          </div>
          <div className="bg-background/40 rounded-xl p-3 text-center">
            <div className="text-sm font-semibold">{isActive ? nextScanDate(sub) : "—"}</div>
            <div className="text-xs text-muted-foreground mt-0.5">Next Scan</div>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {sub.lastReportId && (
              <Link
                href={`/report/${sub.lastReportId}`}
                className="text-xs font-medium text-primary hover:underline flex items-center gap-1"
              >
                <Shield className="w-3.5 h-3.5" /> View latest report
              </Link>
            )}
          </div>
          {sub.alertCount > 0 && (
            <button
              onClick={() => setExpanded((x) => !x)}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              {expanded ? "Hide" : "Show"} CVE alerts
            </button>
          )}
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
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

export function AddSubscriptionForm({ onSuccess }: { onSuccess: () => void }) {
  const [url, setUrl] = useState("https://");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await createMonitorSubscription(url.trim());
      if (result.initialScanId) {
        toast({ title: "Monitoring activated", description: `Baseline scan queued for ${url.trim()} — results will appear shortly.` });
      } else {
        toast({ title: "Monitoring activated", description: `Using your most recent scan results. Next automated rescan in ~7 days.` });
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
      <div className="flex gap-3">
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
      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
    </form>
  );
}
