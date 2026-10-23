/** The portfolio overview across all monitored sites: the numbers, the sites ranked by risk, and what needs you. */
import { Activity, AlertTriangle, CheckCircle2, Clock, Gauge, Lock, ShieldCheck, TrendingDown, Wifi, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { type MonitorSubscription } from "@/lib/monitor-api";
import { GRADE_ORDER, hostOf, untilLabel, relativeTime, formatMs } from "./monitor-format";
import { gradeHex, scoreOf } from "./monitor-viz";

type Tone = "good" | "warn" | "bad" | "plain";
const TONE_TEXT: Record<Tone, string> = { good: "text-emerald-300", warn: "text-amber-300", bad: "text-red-300", plain: "text-foreground" };
const TONE_ICON: Record<Tone, string> = { good: "text-emerald-400 bg-emerald-400/10", warn: "text-amber-400 bg-amber-400/10", bad: "text-red-400 bg-red-400/10", plain: "text-primary bg-primary/10" };

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
  const worstGrade = grades.length ? grades.reduce((w, g) => (GRADE_ORDER.indexOf(g) < GRADE_ORDER.indexOf(w) ? g : w), grades[0]!) : null;

  const down = active.filter((s) => s.pulseReachable === false);
  const reporting = active.filter((s) => s.pulseReachable !== null);
  const openCves = active.reduce((sum, s) => sum + s.alertCount, 0);
  const regressions = active.reduce((sum, s) => sum + s.regressionCount, 0);

  const uptimes = active.map((s) => s.uptime24h).filter((u): u is number => u != null);
  const avgUptime = uptimes.length ? Math.round((uptimes.reduce((a, b) => a + b, 0) / uptimes.length) * 10) / 10 : null;
  const medians = active.map((s) => s.medianResponseMs).filter((m): m is number => m != null);
  const avgResponse = medians.length ? Math.round(medians.reduce((a, b) => a + b, 0) / medians.length) : null;

  const certs = active.map((s) => s.certExpiryDays).filter((d): d is number => d != null && d >= 0);
  const soonestCert = certs.length ? Math.min(...certs) : null;
  const lastChecked = active.map((s) => s.lastPulseAt).filter((t): t is string => Boolean(t)).sort().pop() ?? null;
  const nextScan = active.map((s) => s.nextScanAt).filter((t): t is string => Boolean(t)).sort().shift() ?? null;

  const tiles: Array<{ label: string; value: string; tone: Tone; icon: LucideIcon; hint?: string }> = [
    { label: "Sites up", value: reporting.length ? `${reporting.length - down.length}/${reporting.length}` : "—", tone: down.length > 0 ? "bad" : reporting.length ? "good" : "plain", icon: Wifi, hint: down.length ? `${down.map((s) => hostOf(s.targetUrl)).join(", ")} not responding` : "every site answered its last check" },
    { label: "Avg uptime · 24h", value: avgUptime == null ? "—" : `${avgUptime}%`, tone: avgUptime == null ? "plain" : avgUptime >= 99.9 ? "good" : avgUptime >= 95 ? "warn" : "bad", icon: Activity },
    { label: "Worst grade", value: worstGrade ?? "—", tone: !worstGrade ? "plain" : worstGrade === "A" || worstGrade === "B" ? "good" : worstGrade === "C" ? "warn" : "bad", icon: ShieldCheck },
    { label: "Avg response", value: avgResponse == null ? "—" : formatMs(avgResponse), tone: "plain", icon: Gauge },
    { label: "Open CVEs", value: String(openCves), tone: openCves > 0 ? "bad" : "good", icon: AlertTriangle },
    { label: "Regressions", value: String(regressions), tone: regressions > 0 ? "warn" : "good", icon: TrendingDown },
    { label: "Cert expires", value: soonestCert == null ? "—" : `${soonestCert}d`, tone: soonestCert == null ? "plain" : soonestCert <= 7 ? "bad" : soonestCert <= 30 ? "warn" : "good", icon: Lock },
    { label: "Next full scan", value: untilLabel(nextScan).replace(/^in /, ""), tone: "plain", icon: Clock },
  ];

  // Ranked worst first, so the site that needs the most is on top.
  const ranked = [...active].sort((a, b) => (scoreOf(a.lastReport?.riskScore) ?? 101) - (scoreOf(b.lastReport?.riskScore) ?? 101));

  const attention: Array<{ key: string; tone: "bad" | "warn" | "info"; text: string }> = [];
  for (const s of active) {
    const h = hostOf(s.targetUrl);
    if (s.pulseReachable === false) attention.push({ key: `${s.id}-down`, tone: "bad", text: `${h} is not responding${s.pulseFailureReason ? `: ${s.pulseFailureReason}` : ""}` });
    if (s.alertCount > 0) attention.push({ key: `${s.id}-cve`, tone: "bad", text: `${h}: ${s.alertCount} CVE${s.alertCount === 1 ? "" : "s"} match its software` });
    if (s.certExpiryDays != null && s.certExpiryDays <= 14) attention.push({ key: `${s.id}-cert`, tone: s.certExpiryDays <= 7 ? "bad" : "warn", text: `${h}: certificate expires in ${s.certExpiryDays} day${s.certExpiryDays === 1 ? "" : "s"}` });
    if (s.regressionCount > 0) attention.push({ key: `${s.id}-reg`, tone: "warn", text: `${h}: ${s.regressionCount} regression${s.regressionCount === 1 ? "" : "s"} since the previous scan` });
    if (s.scanInProgress) attention.push({ key: `${s.id}-scan`, tone: "info", text: `${h}: a scan is running now` });
  }
  const dot = { bad: "bg-red-400", warn: "bg-amber-400", info: "bg-sky-400" } as const;

  return (
    <section className="glass-card rounded-2xl p-5 sm:p-6" aria-label="Overview of everything you are watching">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
          <Activity className="h-4 w-4 text-primary" /> Overview · {active.length} site{active.length === 1 ? "" : "s"}
        </h2>
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <span className={cn("h-1.5 w-1.5 rounded-full", lastChecked ? "bg-emerald-400" : "bg-zinc-500")} />
          Last checked {relativeTime(lastChecked)}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {tiles.map((t) => (
          <div key={t.label} className="flex items-center gap-3 rounded-xl bg-background/40 p-3.5" title={t.hint}>
            <span className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-lg", TONE_ICON[t.tone])}><t.icon className="h-4.5 w-4.5" /></span>
            <div className="min-w-0">
              <div className={cn("truncate text-xl font-black leading-tight tabular-nums", TONE_TEXT[t.tone])}>{t.value}</div>
              <div className="truncate text-[11px] text-muted-foreground">{t.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl bg-background/40 p-4">
          <h3 className="mb-3 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">Sites by security score</h3>
          <ul className="space-y-2.5">
            {ranked.map((s) => {
              const score = scoreOf(s.lastReport?.riskScore);
              const color = gradeHex(s.lastReport?.grade);
              return (
                <li key={s.id} className="flex items-center gap-3">
                  <span className="w-5 text-center text-sm font-black" style={{ color }}>{s.lastReport?.grade ?? "–"}</span>
                  <span className="w-36 shrink-0 truncate text-sm sm:w-44" title={s.targetUrl}>{hostOf(s.targetUrl)}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/8">
                    {score != null && <div className="h-full rounded-full" style={{ width: `${Math.max(3, score)}%`, background: color }} />}
                  </div>
                  <span className="w-14 text-right text-xs tabular-nums text-muted-foreground">{score != null ? `${score}/100` : s.scanInProgress ? "scanning" : "no scan"}</span>
                </li>
              );
            })}
          </ul>
        </div>

        <div className="rounded-xl bg-background/40 p-4">
          <h3 className="mb-3 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">Needs attention</h3>
          {attention.length === 0 ? (
            <p className="flex items-start gap-2 text-sm text-emerald-200">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
              Nothing needs you. Every site is answering, no certificate is close to expiring, and no new CVEs match your stacks.
            </p>
          ) : (
            <ul className="space-y-2.5">
              {attention.slice(0, 6).map((a) => (
                <li key={a.key} className="flex items-start gap-2.5 text-sm">
                  <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", dot[a.tone])} />
                  <span className="leading-snug">{a.text}</span>
                </li>
              ))}
              {attention.length > 6 && <li className="text-xs text-muted-foreground">and {attention.length - 6} more, on the cards below</li>}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}
