import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { Loader2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * The one privacy choice an account has: whether a scan's findings go to a third-party AI
 * provider to write the plain-English analysis. Says what is sent and what is not, and
 * that turning it off changes nothing about the scan itself.
 */
export function PrivacyCard() {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { data } = useQuery({
    queryKey: ["account-privacy"],
    queryFn: () => customFetch<{ aiAnalysis: boolean }>("/api/account/privacy"),
  });
  const on = data?.aiAnalysis ?? true;

  async function toggle() {
    setBusy(true);
    setError(null);
    try {
      await customFetch("/api/account/privacy", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ aiAnalysis: !on }),
      });
      await queryClient.invalidateQueries({ queryKey: ["account-privacy"] });
    } catch {
      setError("Could not save that. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="glass-panel p-6 sm:p-10 rounded-3xl mb-8">
      <div className="flex items-start gap-4 mb-6">
        <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
          <ShieldCheck className="w-6 h-6 text-primary" />
        </div>
        <div>
          <h2 className="text-xl font-bold mb-1">Privacy</h2>
          <p className="text-sm text-muted-foreground">Who sees what a scan finds.</p>
        </div>
      </div>

      <div className="flex items-start justify-between gap-4">
        <div className="text-sm leading-relaxed">
          <div className="font-semibold">Written analysis by an AI provider</div>
          <p className="text-muted-foreground mt-1">
            The summary, priorities and fix prompts at the top of a report are written by a third-party AI provider. It is sent the
            findings (names, descriptions and evidence, with anything shaped like a password or key removed), and never the
            credentials you scan with. Turn this off and none of that is sent. The scan and every finding stay exactly the same; the report
            just has no written summary or fix prompts.
          </p>
          {error && <p role="alert" className="text-red-400 mt-2">{error}</p>}
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={on}
          aria-label="Written analysis by an AI provider"
          onClick={toggle}
          disabled={busy || data === undefined}
          className={cn(
            "relative shrink-0 w-11 h-6 rounded-full border transition-colors disabled:opacity-50",
            on ? "bg-primary border-primary" : "bg-white/10 border-white/20",
          )}
        >
          {busy ? (
            <Loader2 className="absolute inset-0 m-auto w-3.5 h-3.5 animate-spin" />
          ) : (
            <span className={cn("absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all", on ? "left-[22px]" : "left-0.5")} />
          )}
        </button>
      </div>
    </div>
  );
}
