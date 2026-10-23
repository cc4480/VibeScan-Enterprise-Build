import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { SCAN_INTERVAL_CHOICES, setMonitorInterval, type MonitorSubscription } from "@/lib/monitor-api";

/**
 * How often one monitored site gets a full rescan. "Automatic" is the default: the site's grade sets
 * it (a better grade is rescanned less often). A fixed choice replaces that after a graded scan.
 */
export function MonitorIntervalSelect({ sub }: { sub: MonitorSubscription }) {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function change(value: string) {
    setBusy(true);
    setError(null);
    try {
      await setMonitorInterval(sub.id, value === "auto" ? null : Number(value));
      await queryClient.invalidateQueries({ queryKey: ["monitor-subscriptions"] });
    } catch {
      setError("Could not change this. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <select
        aria-label={`How often to rescan ${sub.targetUrl}`}
        value={sub.scanIntervalDays ? String(sub.scanIntervalDays) : "auto"}
        onChange={(e) => void change(e.target.value)}
        disabled={busy}
        className="px-2 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 text-xs font-semibold disabled:opacity-50"
        title="How often this site gets a full rescan"
      >
        <option value="auto">Rescan: automatic</option>
        {SCAN_INTERVAL_CHOICES.map((d) => <option key={d} value={d}>Rescan: every {d} days</option>)}
      </select>
      {error && <span role="alert" className="text-xs text-red-400">{error}</span>}
    </>
  );
}
