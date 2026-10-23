/** The category bar chart, OWASP coverage ring and OWASP breakdown. */
import { CheckCircle2, Activity } from "lucide-react";
import { cn } from "@/lib/utils";
import { useMemo } from "react";
import type { Vulnerability } from "@workspace/api-client-react";
import { owaspCoverage, owaspFindingCounts, CATEGORY_TO_OWASP, OWASP_CATEGORIES, type OwaspState } from "@/lib/owaspCoverage";
import { SEVERITY_HEX, type CoverageTest } from "./shared-report-components";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Cell, RadialBarChart, RadialBar, PolarAngleAxis } from "recharts";
import { SEVERITY_ORDER, getCategoryMeta } from "./report-viewer-data";

// ─── Category breakdown bar chart ─────────────────────────────────────────────

/** Horizontal bars, one per finding category, ranked worst-severity-first so
 *  the chart reads the same priority order as the findings list below it. */
export function CategoryBarChart({
  categoryCounts,
  vulnerabilities,
  activeCategory,
  onSelect,
}: {
  categoryCounts: Record<string, number>;
  vulnerabilities: Vulnerability[];
  activeCategory: string | null;
  onSelect: (category: string) => void;
}) {
  const data = useMemo(() => {
    const worst: Record<string, string> = {};
    for (const v of vulnerabilities) {
      const order = SEVERITY_ORDER[v.severity] ?? 99;
      const current = worst[v.category] ? (SEVERITY_ORDER[worst[v.category]!] ?? 99) : 100;
      if (order < current) worst[v.category] = v.severity;
    }
    return Object.entries(categoryCounts)
      .map(([category, count]) => ({
        category,
        label: getCategoryMeta(category).label,
        count,
        severity: worst[category] ?? "info",
      }))
      .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99) || b.count - a.count)
      .slice(0, 8);
  }, [categoryCounts, vulnerabilities]);

  if (data.length === 0) return null;

  return (
    <div style={{ height: Math.max(120, data.length * 32) }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 24, bottom: 0, left: 0 }}>
          <CartesianGrid horizontal={false} stroke="rgba(255,255,255,0.06)" />
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="label"
            width={140}
            tick={{ fill: "#a1a1aa", fontSize: 11 }}
            tickLine={false}
            axisLine={false}
          />
          <RechartsTooltip
            cursor={{ fill: "rgba(255,255,255,0.04)" }}
            formatter={(value: number) => [`${value} finding${value === 1 ? "" : "s"}`, ""]}
            contentStyle={{
              background: "rgba(15, 15, 20, 0.95)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 8,
              fontSize: 12,
            }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={16} cursor="pointer">
            {data.map((d) => (
              <Cell
                key={d.category}
                fill={SEVERITY_HEX[d.severity]}
                fillOpacity={activeCategory && activeCategory !== d.category ? 0.35 : 1}
                onClick={() => onSelect(d.category)}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ─── OWASP coverage radial ─────────────────────────────────────────────────────

/** One ring: how many of the ten OWASP categories came back clean. Sits above
 *  the per-category list in OwaspBreakdown as the one-glance version of it. */
export function OwaspCoverageRing({ passed, total }: { passed: number; total: number }) {
  const pct = total === 0 ? 100 : Math.round((passed / total) * 100);
  const color = pct === 100 ? "#4ade80" : pct >= 70 ? "#facc15" : "#f87171";
  const data = [{ name: "coverage", value: pct, fill: color }];

  return (
    <div className="relative w-20 h-20 shrink-0">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          data={data}
          startAngle={90}
          endAngle={-270}
          innerRadius="72%"
          outerRadius="100%"
        >
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar dataKey="value" cornerRadius={8} background={{ fill: "rgba(255,255,255,0.06)" }} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-sm font-black tabular-nums">{pct}%</span>
      </div>
    </div>
  );
}

// ─── OWASP Top 10 breakdown ───────────────────────────────────────────────────

/** Maps each scanner internal category → the OWASP 2021 code(s) it covers */
export function OwaspBreakdown({ vulnerabilities, tests }: { vulnerabilities: Vulnerability[]; tests?: CoverageTest[] | null }) {
  // Build per-OWASP-code: { count, worstSeverity }
  const owaspMap = useMemo(() => {
    const map: Record<string, { count: number; worstSeverity: string }> = {};
    for (const v of vulnerabilities) {
      const codes = CATEGORY_TO_OWASP[v.category] ?? [];
      for (const code of codes) {
        if (!map[code]) map[code] = { count: 0, worstSeverity: "info" };
        map[code].count += 1;
        const order = SEVERITY_ORDER[v.severity] ?? 99;
        const currentOrder = SEVERITY_ORDER[map[code].worstSeverity] ?? 99;
        if (order < currentOrder) map[code].worstSeverity = v.severity;
      }
    }
    return map;
  }, [vulnerabilities]);

  const SEV_DOT: Record<string, string> = {
    critical: "bg-red-500",
    high:     "bg-orange-500",
    medium:   "bg-yellow-500",
    low:      "bg-blue-500",
    info:     "bg-zinc-400",
  };

  const SEV_TEXT: Record<string, string> = {
    critical: "text-red-400",
    high:     "text-orange-400",
    medium:   "text-yellow-400",
    low:      "text-blue-400",
    info:     "text-zinc-400",
  };

  // Informational notes do not flag a category; see owaspFindingCounts.
  const actionable = useMemo(() => owaspFindingCounts(vulnerabilities), [vulnerabilities]);
  // "No findings" is not "passed": a category nothing tested has no findings either. Each row
  // is judged by whether the tests that cover it ran (see lib/owaspCoverage.ts).
  const coverage = Object.fromEntries(
    OWASP_CATEGORIES.map((c) => [c.code, owaspCoverage(c.code, actionable[c.code]?.actionable ?? 0, tests)]),
  ) as Record<string, ReturnType<typeof owaspCoverage>>;
  const countOf = (s: OwaspState) => OWASP_CATEGORIES.filter((c) => coverage[c.code]!.state === s).length;
  const failing = countOf("flagged");
  const clear = countOf("clear");
  const notFullyTested = OWASP_CATEGORIES.length - failing - clear;

  return (
    <div className="glass-card rounded-2xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <OwaspCoverageRing passed={clear} total={OWASP_CATEGORIES.length} />
          <div>
            <h3 className="text-sm font-bold flex items-center gap-2 text-muted-foreground uppercase tracking-wider mb-1.5">
              <Activity className="w-4 h-4" /> OWASP Top 10
            </h3>
            <div className="flex items-center gap-2 text-xs">
              {failing > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 font-medium">
                  {failing} flagged
                </span>
              )}
              <span className="px-2 py-0.5 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 font-medium">
                {clear} clear
              </span>
              {notFullyTested > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-medium">
                  {notFullyTested} not fully tested
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-1">
        {OWASP_CATEGORIES.map(({ code, name }) => {
          const data = owaspMap[code];
          const hasFinding = data && data.count > 0;
          return (
            <div
              key={code}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg",
                hasFinding ? "bg-white/[0.02]" : "",
              )}
            >
              <span className="font-mono text-[11px] font-bold text-muted-foreground/50 w-7 shrink-0">
                {code}
              </span>
              <span className={cn(
                "flex-1 text-xs truncate",
                hasFinding ? "text-foreground/80" : "text-muted-foreground/50",
              )}>
                {name}
              </span>
              {hasFinding ? (
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className={cn("w-1.5 h-1.5 rounded-full", SEV_DOT[data.worstSeverity])} />
                  <span className={cn("text-xs font-bold", SEV_TEXT[data.worstSeverity])}>
                    {data.count}
                  </span>
                </div>
              ) : coverage[code]!.state === "clear" ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-green-500/60 shrink-0" aria-label="Tested, no findings" />
              ) : (
                <span
                  className="text-[10px] font-medium text-amber-400/80 shrink-0"
                  title={
                    coverage[code]!.notRun.length > 0
                      ? `Not run: ${coverage[code]!.notRun.join(", ")}`
                      : coverage[code]!.state === "unknown"
                        ? "This scan kept no test record"
                        : "No recorded test covers this category"
                  }
                >
                  {coverage[code]!.state === "partial" ? "partly tested" : coverage[code]!.state === "unknown" ? "no record" : "not tested"}
                </span>
              )}
            </div>
          );
        })}
      </div>

      <p className="mt-3 text-[10px] text-muted-foreground/40 leading-relaxed">
        &ldquo;Clear&rdquo; means every test covering the category ran and found nothing; it is not a statement of security. Categories marked not tested or partly tested had tests that were skipped, listed under &ldquo;What this scan tested&rdquo;. Based on OWASP Top 10 2021. A04, A09, A10 require authenticated or server-side testing — not in scope for black-box scans.
      </p>
    </div>
  );
}
