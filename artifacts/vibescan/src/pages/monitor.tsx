import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { AnimatePresence } from "framer-motion";
import {
  Bell, CheckCircle2, XCircle, Loader2, ArrowLeft,
  RefreshCw, CalendarClock, ShieldAlert, Globe,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { listMonitorSubscriptions } from "@/lib/monitor-api";
import {
  SubscriptionCard,
  AddSubscriptionForm,
} from "./monitor-components";

export default function MonitorPage() {
  const queryClient = useQueryClient();

  const { data: subscriptions, isLoading, error } = useQuery({
    queryKey: ["monitor-subscriptions"],
    queryFn: listMonitorSubscriptions,
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
      <div>
        <Link href="/dashboard" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground mb-6 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-black mb-2 flex items-center gap-3">
              <Bell className="w-7 h-7 text-primary" /> Continuous Monitoring
            </h1>
            <p className="text-muted-foreground max-w-lg">
              Weekly automated rescans + instant alerts when new CVEs match your tech stack.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {[
          {
            icon: RefreshCw,
            title: "Weekly Rescans",
            desc: "Your site is automatically re-scanned every 7 days. New findings trigger an email.",
            color: "text-emerald-400",
            bg: "bg-emerald-400/10",
          },
          {
            icon: ShieldAlert,
            title: "CVE Alerts",
            desc: "We monitor the NVD feed daily. When a new CVE matches your stack, a targeted scan fires immediately.",
            color: "text-indigo-400",
            bg: "bg-indigo-400/10",
          },
          {
            icon: CalendarClock,
            title: "Always-On Coverage",
            desc: "Set it and forget it — continuous monitoring with no manual re-runs needed. Cancel any time.",
            color: "text-amber-400",
            bg: "bg-amber-400/10",
          },
          {
            icon: Globe,
            title: "Full Deep Scan",
            desc: "Every automated rescan runs the full Deep Scan with AI analysis — not a basic check.",
            color: "text-sky-400",
            bg: "bg-sky-400/10",
          },
        ].map((item, i) => (
          <div key={i} className="glass-card p-5 rounded-2xl flex gap-4">
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
          Failed to load subscriptions. Please refresh.
        </div>
      )}

      {!isLoading && active.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Active ({active.length})
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
            <XCircle className="w-4 h-4 text-slate-500" /> Inactive ({inactive.length})
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
