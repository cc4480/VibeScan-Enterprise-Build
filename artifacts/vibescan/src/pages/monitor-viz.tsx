/** The monitor page's visuals: grade ring, security-score trend, response-time chart, certificate bar. Hand-drawn SVG, like monitor-charts.tsx. */
import { useId } from "react";
import { cn } from "@/lib/utils";
import { type MonitorSubscription, type ScoreHistoryPoint } from "@/lib/monitor-api";
import { formatMs } from "./monitor-format";

/** One colour per grade, used by the ring, the trend dots and the portfolio bars. */
export function gradeHex(grade: string | null | undefined): string {
  if (!grade) return "#64748b";
  if (grade === "A") return "#34d399";
  if (grade === "B") return "#4ade80";
  if (grade === "C") return "#fbbf24";
  if (grade === "D") return "#fb923c";
  return "#f87171";
}

/** The security score the charts draw: higher is better, 100 is no weighted findings. */
export const scoreOf = (riskScore: number | null | undefined): number | null =>
  riskScore == null ? null : Math.max(0, Math.min(100, Math.round(100 - riskScore)));

/** A ring that fills with the security score, the grade letter in the middle. */
export function GradeRing({ grade, riskScore, size = 108 }: { grade: string | null; riskScore: number | null; size?: number }) {
  const stroke = 9;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const score = scoreOf(riskScore);
  const color = gradeHex(grade);
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={grade ? `Grade ${grade}, security score ${score ?? "unknown"} of 100` : "Not graded yet"}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={stroke} className="text-white/8" />
        {score != null && (
          <circle
            cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
            strokeDasharray={`${(circ * score) / 100} ${circ}`}
            style={{ filter: `drop-shadow(0 0 6px ${color}66)` }}
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-black leading-none" style={{ color }}>{grade ?? "—"}</span>
        <span className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          {score != null ? `${score}/100` : "no grade"}
        </span>
      </div>
    </div>
  );
}

/** Security score over the recent scans, with a dot per scan coloured by its grade; a ring marks scans that had critical findings. */
export function SecurityTrend({ points }: { points: ScoreHistoryPoint[] }) {
  const gid = useId().replace(/:/g, "");
  const recent = points.slice(-14);
  if (recent.length < 2) return null;

  const W = 560, H = 176, L = 34, R = 14, T = 16, B = 28;
  const xs = (i: number) => L + (i * (W - L - R)) / (recent.length - 1);
  const ys = (score: number) => T + (1 - score / 100) * (H - T - B);
  const scores = recent.map((p) => scoreOf(p.riskScore) ?? 0);
  const line = scores.map((s, i) => `${i === 0 ? "M" : "L"}${xs(i).toFixed(1)},${ys(s).toFixed(1)}`).join(" ");
  const area = `${line} L${xs(recent.length - 1).toFixed(1)},${H - B} L${xs(0).toFixed(1)},${H - B} Z`;
  const last = scores[scores.length - 1]!;
  const lastColor = gradeHex(recent[recent.length - 1]!.grade);
  const delta = last - scores[0]!;
  const date = (iso: string) => new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" });

  return (
    <div>
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">Security score · last {recent.length} scans</span>
        <span className={cn("text-xs font-semibold tabular-nums", delta > 0 ? "text-emerald-400" : delta < 0 ? "text-red-400" : "text-muted-foreground")}>
          {delta === 0 ? "No change" : `${delta > 0 ? "+" : ""}${delta} points since ${date(recent[0]!.scannedAt)}`}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" className="block" role="img" aria-label={`Security score over the last ${recent.length} scans, now ${last} out of 100`}>
        <defs>
          <linearGradient id={`g${gid}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={lastColor} stopOpacity="0.32" />
            <stop offset="100%" stopColor={lastColor} stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 50, 100].map((v) => (
          <g key={v}>
            <line x1={L} x2={W - R} y1={ys(v)} y2={ys(v)} stroke="currentColor" strokeDasharray="3 5" className="text-white/10" />
            <text x={L - 8} y={ys(v) + 3} textAnchor="end" fontSize="10" fill="currentColor" className="text-muted-foreground">{v}</text>
          </g>
        ))}
        <path d={area} fill={`url(#g${gid})`} />
        <path d={line} fill="none" stroke={lastColor} strokeWidth="2.25" strokeLinecap="round" strokeLinejoin="round" />
        {recent.map((p, i) => (
          <g key={p.id}>
            {p.criticalCount > 0 && <circle cx={xs(i)} cy={ys(scores[i]!)} r="7.5" fill="none" stroke="#f87171" strokeWidth="1.5" />}
            <circle cx={xs(i)} cy={ys(scores[i]!)} r={i === recent.length - 1 ? 4.5 : 3.2} fill={gradeHex(p.grade)} stroke="#06151c" strokeWidth="1.5">
              <title>{`${date(p.scannedAt)} · grade ${p.grade} · score ${scores[i]} · ${p.criticalCount} critical, ${p.highCount} high`}</title>
            </circle>
          </g>
        ))}
        <text x={xs(recent.length - 1)} y={ys(last) - 12} textAnchor="end" fontSize="11" fontWeight="700" fill={lastColor}>{`${recent[recent.length - 1]!.grade} · ${last}`}</text>
        <text x={L} y={H - 8} fontSize="10" fill="currentColor" className="text-muted-foreground">{date(recent[0]!.scannedAt)}</text>
        <text x={W - R} y={H - 8} textAnchor="end" fontSize="10" fill="currentColor" className="text-muted-foreground">{date(recent[recent.length - 1]!.scannedAt)}</text>
      </svg>
      {recent.some((p) => p.criticalCount > 0) && (
        <p className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <span className="inline-block h-2.5 w-2.5 rounded-full border border-red-400" /> a scan that had critical findings
        </p>
      )}
    </div>
  );
}

/** The last day of hourly checks: response time as an area, missed checks marked along the bottom, and the headline numbers. */
export function ResponsePanel({ sub }: { sub: MonitorSubscription }) {
  const gid = useId().replace(/:/g, "");
  const t = sub.pulseTimeline;
  if (t.length === 0) return null;

  const W = 560, H = 112, L = 4, R = 4, T = 10, B = 18;
  const ms = t.filter((p) => p.reachable && p.responseTimeMs != null).map((p) => p.responseTimeMs as number);
  const top = Math.max(150, (ms.length ? Math.max(...ms) : 150) * 1.2);
  const xs = (i: number) => L + (i * (W - L - R)) / Math.max(1, t.length - 1);
  const ys = (v: number) => T + (1 - v / top) * (H - T - B);

  // Break the line at a missed check rather than drawing across the outage.
  const segments: Array<Array<[number, number]>> = [];
  let cur: Array<[number, number]> = [];
  t.forEach((p, i) => {
    if (p.reachable && p.responseTimeMs != null) cur.push([xs(i), ys(p.responseTimeMs)]);
    else if (cur.length) { segments.push(cur); cur = []; }
  });
  if (cur.length) segments.push(cur);
  const path = (seg: Array<[number, number]>) => seg.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const missed = t.map((p, i) => ({ p, i })).filter(({ p }) => !p.reachable);
  const hour = (iso: string) => new Date(iso).toLocaleTimeString("en-US", { hour: "numeric" });
  const stat = (label: string, value: string, tone = "text-foreground") => (
    <div className="min-w-0">
      <div className={cn("text-lg font-black tabular-nums leading-tight", tone)}>{value}</div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
    </div>
  );

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
        <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">Availability &amp; response · last 24h</span>
        <div className="flex gap-6">
          {stat("Uptime", sub.uptime24h == null ? "—" : `${sub.uptime24h}%`, sub.uptime24h == null ? "text-muted-foreground" : sub.uptime24h >= 99.9 ? "text-emerald-400" : sub.uptime24h >= 95 ? "text-amber-400" : "text-red-400")}
          {stat("Median", formatMs(sub.medianResponseMs))}
          {stat("Slowest", ms.length ? formatMs(Math.max(...ms)) : "—")}
        </div>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" className="block" role="img" aria-label="Response time of each hourly check over the last 24 hours">
        <defs>
          <linearGradient id={`r${gid}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#2dd4bf" stopOpacity="0.30" />
            <stop offset="100%" stopColor="#2dd4bf" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 0.5, 1].map((f) => (
          <line key={f} x1={L} x2={W - R} y1={ys(top * f)} y2={ys(top * f)} stroke="currentColor" strokeDasharray="3 5" className="text-white/8" />
        ))}
        {segments.map((seg, k) => seg.length > 1 && (
          <g key={k}>
            <path d={`${path(seg)} L${seg[seg.length - 1]![0].toFixed(1)},${H - B} L${seg[0]![0].toFixed(1)},${H - B} Z`} fill={`url(#r${gid})`} />
            <path d={path(seg)} fill="none" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </g>
        ))}
        {t.map((p, i) => p.reachable && p.responseTimeMs != null && (
          <circle key={i} cx={xs(i)} cy={ys(p.responseTimeMs)} r={i === t.length - 1 ? 3.6 : 1.6} fill="#2dd4bf">
            <title>{`${hour(p.checkedAt)} · ${formatMs(p.responseTimeMs)}`}</title>
          </circle>
        ))}
        {missed.map(({ p, i }) => (
          <g key={i}>
            <rect x={xs(i) - 3} y={T} width="6" height={H - T - B} rx="2" fill="#f87171" fillOpacity="0.28" />
            <circle cx={xs(i)} cy={H - B - 4} r="3" fill="#f87171"><title>{`${hour(p.checkedAt)} · no response`}</title></circle>
          </g>
        ))}
        <text x={L} y={H - 4} fontSize="10" fill="currentColor" className="text-muted-foreground">{hour(t[0]!.checkedAt)}</text>
        <text x={W - R} y={H - 4} textAnchor="end" fontSize="10" fill="currentColor" className="text-muted-foreground">now</text>
      </svg>
    </div>
  );
}

/** Days left on the TLS certificate, as a bar against the usual 90-day lifetime. */
export function CertBar({ days }: { days: number | null }) {
  const pct = days == null ? 0 : Math.max(4, Math.min(100, (days / 90) * 100));
  const color = days == null ? "#64748b" : days <= 7 ? "#f87171" : days <= 30 ? "#fbbf24" : "#34d399";
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">TLS certificate</span>
        <span className="text-sm font-black tabular-nums" style={{ color }}>{days == null ? "—" : `${days} day${days === 1 ? "" : "s"} left`}</span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-white/8">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}
