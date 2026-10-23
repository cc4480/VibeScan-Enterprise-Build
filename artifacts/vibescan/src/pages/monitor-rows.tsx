/** Rows for CVE alerts and regressions. */
import { cn } from "@/lib/utils";
import { type CveAlert, type MonitorRegression } from "@/lib/monitor-api";
import { SEVERITY_CONFIG, formatDate } from "./monitor-format";

// ── EPSS pill ─────────────────────────────────────────────────────────────────

export function EpssPill({ percentile }: { percentile: number | null }) {
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

export function CveAlertRow({ alert }: { alert: CveAlert }) {
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

export function RegressionRow({ reg }: { reg: MonitorRegression }) {
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
