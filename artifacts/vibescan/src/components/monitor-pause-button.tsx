import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Loader2, Pause, Play } from "lucide-react";
import { setMonitorPaused, type MonitorSubscription } from "@/lib/monitor-api";

/**
 * Pause or resume one monitored site. Paused means no scans, uptime checks or alerts for it,
 * and nothing is deleted; resuming carries on. The button says what pressing it does, and
 * the paused state has its own badge on the card so a site is never silently unwatched.
 */
export function MonitorPauseButton({ sub }: { sub: MonitorSubscription }) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const paused = Boolean(sub.pausedAt);

  async function toggle() {
    setBusy(true);
    setError(null);
    try {
      await setMonitorPaused(sub.id, !paused);
      await queryClient.invalidateQueries({ queryKey: ["monitor-subscriptions"] });
    } catch {
      setError("Could not change this monitor. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={toggle}
        disabled={busy}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 hover:bg-white/[0.08] text-xs font-semibold transition-colors disabled:opacity-50"
        title={paused ? "Start scanning and alerting for this site again" : "Stop scans, uptime checks and alerts for this site until you resume"}
      >
        {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
        {paused ? "Resume" : "Pause"}
      </button>
      {error && <span role="alert" className="text-xs text-red-400">{error}</span>}
    </>
  );
}
