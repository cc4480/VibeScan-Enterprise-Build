import { Link, useParams } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { ArrowLeft, Loader2 } from "lucide-react";
import { useSeo } from "@/lib/seo";
import { cn, getGradeColor } from "@/lib/utils";
import { monitorFacts, monitorState, type MonitorTone, type SharedMonitor, type SharedReport } from "@/lib/team";
import { relativeTime } from "./monitor-format";

const TONE: Record<MonitorTone, string> = {
  good: "bg-green-400/10 border-green-400/20 text-green-400",
  warn: "bg-orange-400/10 border-orange-400/20 text-orange-400",
  bad: "bg-red-400/10 border-red-400/20 text-red-400",
  idle: "bg-white/5 border-white/10 text-muted-foreground",
};

/** The reports of a team you were invited onto: newest first, each opening the same read-only report page. */
export default function TeamSharedPage() {
  useSeo({ title: "Shared reports — SecScan.us", noindex: true });
  const { id } = useParams<{ id: string }>();
  const reports = useQuery({
    queryKey: ["team-shared-reports", id],
    queryFn: () => customFetch<{ reports: SharedReport[] }>(`/api/team/shared/${encodeURIComponent(id ?? "")}/reports`),
    enabled: Boolean(id),
    retry: false,
  });

  // A teammate sees the sites read-only; the section is simply absent when there are none or the request fails.
  const monitors = useQuery({
    queryKey: ["team-shared-monitors", id],
    queryFn: () => customFetch<{ monitors: SharedMonitor[] }>(`/api/team/shared/${encodeURIComponent(id ?? "")}/monitors`),
    enabled: Boolean(id),
    retry: false,
  });

  return (
    <div className="max-w-3xl mx-auto px-4 py-10">
      <Link href="/settings" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground mb-6"><ArrowLeft className="w-4 h-4" /> Settings</Link>
      <h1 className="text-2xl font-bold mb-1">Shared reports</h1>
      <p className="text-sm text-muted-foreground mb-6">You can read these monitored sites and reports, and download evidence packs. You cannot change anything.</p>

      {monitors.data && monitors.data.monitors.length > 0 && (
        <section className="mb-10" aria-label="Monitored sites">
          <h2 className="text-lg font-semibold mb-3">Monitored sites</h2>
          <div className="space-y-3">
            {monitors.data.monitors.map((m) => {
              const state = monitorState(m);
              const facts = monitorFacts(m);
              return (
                <div key={m.targetUrl} className="flex items-center gap-4 rounded-xl border border-white/10 px-4 py-3">
                  <div className={cn("text-3xl font-black w-10 text-center", m.grade ? getGradeColor(m.grade) : "text-muted-foreground")}>{m.grade ?? "—"}</div>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium truncate">{m.targetUrl}</div>
                    <div className="text-xs text-muted-foreground">
                      {facts.length > 0 ? facts.join(" · ") : "No checks yet"}
                      {m.lastCheckedAt && ` · checked ${relativeTime(m.lastCheckedAt)}`}
                    </div>
                  </div>
                  <span className={cn("px-2 py-0.5 rounded-full text-xs font-semibold border shrink-0", TONE[state.tone])}>{state.label}</span>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {reports.isLoading && <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />}
      {reports.isError && <p className="text-sm text-muted-foreground">These reports are not available. You may no longer be on this team.</p>}
      {reports.data && reports.data.reports.length === 0 && <p className="text-sm text-muted-foreground">No reports yet.</p>}
      <div className="space-y-3">
        {reports.data?.reports.map((r) => (
          <Link key={r.id} href={`/report/${r.id}`} className="flex items-center gap-4 rounded-xl border border-white/10 px-4 py-3 hover:bg-white/[0.03]">
            <div className={cn("text-3xl font-black w-10 text-center", r.grade ? getGradeColor(r.grade) : "text-muted-foreground")}>{r.grade ?? "—"}</div>
            <div className="flex-1 min-w-0">
              <div className="font-medium truncate">{r.targetUrl}</div>
              <div className="text-xs text-muted-foreground">{new Date(r.scannedAt).toLocaleDateString()} · {r.tier}</div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
