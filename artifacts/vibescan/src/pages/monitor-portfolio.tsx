/** The portfolio summary across all monitored sites. */
import { Activity } from "lucide-react";
import { cn } from "@/lib/utils";
import { type MonitorSubscription } from "@/lib/monitor-api";
import { GRADE_ORDER, hostOf, untilLabel, relativeTime } from "./monitor-format";

/**
 * The state of everything being monitored, above the per-site cards.
 *
 * Someone watching eight sites should not have to read eight cards to find out
 * whether anything needs them today.
 */
export function PortfolioSummary({ subs }: { subs: MonitorSubscription[] }) {
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
