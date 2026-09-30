import type { SubscriptionCardState } from "./monitor-card-state";
import { motion, AnimatePresence } from "framer-motion";
import { Bell, XCircle, ExternalLink, Loader2, RefreshCw, TrendingDown, Gauge } from "lucide-react";
import { cn } from "@/lib/utils";
import { gradeColor, formatDate, formatMs } from "./monitor-format";
import { ResponseTimeChart } from "./monitor-charts";
import { CveAlertRow, RegressionRow } from "./monitor-rows";

/** The expandable detail drawers: uptime, history, regressions and CVEs. */
export function SubscriptionDrawers({ card }: { card: SubscriptionCardState }) {
  const { drawer, alertsQuery, historyQuery, regressionQuery, pulseQuery, historyPoints } = card;
  return (
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
  );
}
