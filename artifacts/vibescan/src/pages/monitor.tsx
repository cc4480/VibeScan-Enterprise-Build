import { SubscriptionCard } from "./monitor-card";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { useSeo } from "@/lib/seo";
import { AnimatePresence } from "framer-motion";
import { Bell, CheckCircle2, XCircle, Loader2, RefreshCw, ShieldAlert, ArrowLeft, TrendingDown, Gauge } from "lucide-react";
import { cn } from "@/lib/utils";
import { listMonitorSubscriptions } from "@/lib/monitor-api";
import { PortfolioSummary } from "./monitor-portfolio";
import { AddSubscriptionForm } from "./monitor-add";

// ── Main page ─────────────────────────────────────────────────────────────────

export default function MonitorPage() {
  useSeo({ title: "Monitor — SecScan.us", noindex: true });
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
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-10 space-y-6">
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

      {/* How it works: one collapsed line, so the data is the first thing on the page and the explanation is there when wanted. */}
      <details className="group glass-card rounded-2xl px-5 py-3.5 text-sm">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 font-semibold text-muted-foreground hover:text-foreground">
          <span className="flex items-center gap-2"><Gauge className="h-4 w-4 text-primary" /> How monitoring works</span>
          <span className="text-xs font-normal group-open:hidden">hourly checks · adaptive deep scans · CVE alerts · regression detection</span>
        </summary>
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { icon: Gauge, title: "Hourly checks", desc: "Every URL is checked once an hour: is it up, how fast did it answer, is the certificate valid, and did a security header disappear.", color: "text-primary", bg: "bg-primary/10" },
            { icon: RefreshCw, title: "Adaptive deep scans", desc: "Full scans follow the grade: A every 14 days, B and C every 7, D and F every 3. Deep scans are heavy, so they are scheduled, not hourly.", color: "text-emerald-300", bg: "bg-emerald-400/10" },
            { icon: ShieldAlert, title: "CVE alerts + EPSS", desc: "The NVD feed is checked hourly against the software detected on your site and enriched with EPSS exploit probability. A new match triggers a rescan.", color: "text-teal-300", bg: "bg-teal-400/10" },
            { icon: TrendingDown, title: "Regressions & drift", desc: "Each scan is compared with the last. Anything that weakens your posture is emailed and posted to your webhook.", color: "text-amber-300", bg: "bg-amber-400/10" },
          ].map((item) => (
            <div key={item.title} className="flex gap-3">
              <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg", item.bg, item.color)}><item.icon className="h-4 w-4" /></div>
              <div>
                <h3 className="mb-0.5 text-sm font-semibold">{item.title}</h3>
                <p className="text-xs leading-relaxed text-muted-foreground">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </details>

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
        <div className="space-y-5">
          <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Active sites ({active.length})
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