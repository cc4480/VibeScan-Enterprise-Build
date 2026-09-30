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
    <div className="max-w-3xl mx-auto px-4 py-10 space-y-8">
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

      {/* How it works */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {[
          {
            icon: Gauge,
            title: "Hourly Checks",
            desc: "Every monitored URL is checked once an hour: is it up, how fast did it answer, is the certificate still valid, and did any security header disappear.",
            color: "text-primary",
            bg: "bg-primary/10",
          },
          {
            icon: RefreshCw,
            title: "Adaptive Deep Scans",
            desc: "Full scans follow your risk grade: A every 14 days, B and C every 7, D and F every 3. A deep scan is heavy, so it is scheduled — not run hourly.",
            color: "text-green-400",
            bg: "bg-green-400/10",
          },
          {
            icon: ShieldAlert,
            title: "CVE Alerts + EPSS",
            desc: "The NVD feed is checked hourly against your detected stack and enriched with EPSS exploit probability. A new match triggers an immediate rescan.",
            color: "text-indigo-400",
            bg: "bg-indigo-400/10",
          },
          {
            icon: TrendingDown,
            title: "Regressions & Drift",
            desc: "Each scan is compared with the last, and each hourly check with the one before. Anything that weakens your posture is emailed and posted to your webhook.",
            color: "text-orange-400",
            bg: "bg-orange-400/10",
          },
        ].map((item) => (
          <div key={item.title} className="glass-card p-5 rounded-2xl flex gap-4">
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
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-400" /> Active ({active.length})
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