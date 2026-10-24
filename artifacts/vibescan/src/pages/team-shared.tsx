import { useState } from "react";
import { Link, useParams } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { ArrowLeft, Loader2, Pause, Play } from "lucide-react";
import { useSeo } from "@/lib/seo";
import { cn, getGradeColor } from "@/lib/utils";
import { monitorFacts, monitorState, teamRefusal, type MonitorTone, type SharedMonitor, type SharedReport, type SharedTeam } from "@/lib/team";
import { relativeTime } from "./monitor-format";

const TONE: Record<MonitorTone, string> = {
  good: "bg-green-400/10 border-green-400/20 text-green-400",
  warn: "bg-orange-400/10 border-orange-400/20 text-orange-400",
  bad: "bg-red-400/10 border-red-400/20 text-red-400",
  idle: "bg-white/5 border-white/10 text-muted-foreground",
};

/**
 * The reports and monitored sites of a team you were invited onto: newest first, each report opening the same report page.
 * A viewer only reads. An editor can also pause and resume the owner's sites here, and file tickets from a report.
 */
export default function TeamSharedPage() {
  useSeo({ title: "Shared reports — SecScan.us", noindex: true });
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Which role this membership has: from the teams the account is on, so it is the server's word, not the page's.
  const teams = useQuery({ queryKey: ["team-shared"], queryFn: () => customFetch<{ teams: SharedTeam[] }>("/api/team/shared") });
  const isEditor = teams.data?.teams.find((t) => t.id === id)?.role === "editor";
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

  async function setPaused(m: SharedMonitor, paused: boolean) {
    if (!m.id) return;
    setError(null);
    setBusyId(m.id);
    try {
      await customFetch(`/api/monitor/subscriptions/${encodeURIComponent(m.id)}/pause`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paused }) });
      await queryClient.invalidateQueries({ queryKey: ["team-shared-monitors", id] });
    } catch (err) {
      setError(teamRefusal(err));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="max-w-3xl mx-auto px-4 py-10">
      <Link href="/settings" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground mb-6"><ArrowLeft className="w-4 h-4" /> Settings</Link>
      <h1 className="text-2xl font-bold mb-1">Shared reports</h1>
      <p className="text-sm text-muted-foreground mb-6">
        {isEditor
          ? "You can read these monitored sites and reports, pause and resume the sites, file tickets from a report, and download evidence packs. Everything else stays with the owner."
          : "You can read these monitored sites and reports, and download evidence packs. You cannot change anything."}
      </p>
      {error && <p role="alert" className="text-sm text-red-400 mb-4">{error}</p>}

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
                  {isEditor && m.id && (
                    <button
                      type="button"
                      onClick={() => void setPaused(m, !m.paused)}
                      disabled={busyId === m.id}
                      aria-label={`${m.paused ? "Resume" : "Pause"} ${m.targetUrl}`}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/15 text-xs font-semibold disabled:opacity-60 shrink-0"
                    >
                      {busyId === m.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : m.paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                      {m.paused ? "Resume" : "Pause"}
                    </button>
                  )}
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
