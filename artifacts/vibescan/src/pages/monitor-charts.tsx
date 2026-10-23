/** Score trend, uptime strip and response-time chart. */
import { cn } from "@/lib/utils";
import { type MonitorSubscription, type ScoreHistoryPoint } from "@/lib/monitor-api";
import { GRADE_NUMERIC, formatMs } from "./monitor-format";

/**
 * Risk score over time, drawn to the scale the axis labels name.
 *
 * Replaces a 72px sparkline with no axis and no labels, which could show that
 * something had changed but never what or when.
 */
export function ScoreTrend({ points }: { points: ScoreHistoryPoint[] }) {
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
export function UptimeStrip({ timeline }: { timeline: MonitorSubscription["pulseTimeline"] }) {
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

export function ResponseTimeChart({ pulses }: { pulses: Array<{ checkedAt: string; responseTimeMs: number | null; reachable: boolean }> }) {
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
