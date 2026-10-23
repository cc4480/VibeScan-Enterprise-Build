import { useState } from "react";
import { useParams } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { CheckCircle2, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { refusalMessage, viewOf } from "@/lib/verify-fix";
import { useVerifications } from "@/lib/use-verifications";
import { useViewOnly } from "@/lib/use-view-only";

const TONE: Record<string, string> = {
  idle: "border-white/10 bg-white/[0.02]",
  busy: "border-primary/30 bg-primary/5",
  good: "border-green-500/30 bg-green-500/5",
  warn: "border-amber-500/30 bg-amber-500/5",
  neutral: "border-white/10 bg-white/[0.03]",
};

/**
 * "Fixed this? Check it." under a finding's recommended fix. The check is a re-scan of
 * the site judged against this finding alone (see lib/verify-fix.ts for the words and
 * the server's lib/verifyFix.ts for the rules). It does not use a scan.
 */
export function VerifyFixButton({ findingId }: { findingId: string }) {
  const { id: reportId } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { known, viewOnly } = useViewOnly(reportId);
  const query = useVerifications(reportId);
  const status = query.data?.verifications.find((v) => v.findingId === findingId);
  const view = viewOf(status, starting);

  async function start() {
    setError(null);
    setStarting(true);
    try {
      await customFetch(`/api/reports/${reportId}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingId }),
      });
      await queryClient.invalidateQueries({ queryKey: ["verifications", reportId] });
    } catch (err) {
      setError(refusalMessage(err));
    } finally {
      setStarting(false);
    }
  }

  // Re-checking a fix runs a scan for the owner, so a teammate reading the report is not offered it.
  if (!reportId || !known || viewOnly) return null;
  const Icon = view.tone === "good" ? CheckCircle2 : view.tone === "busy" ? Loader2 : view.tone === "idle" ? ShieldCheck : RefreshCw;

  return (
    <div className={cn("mt-4 rounded-lg border px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-3", TONE[view.tone])}>
      <Icon className={cn("w-5 h-5 shrink-0", view.tone === "busy" && "animate-spin text-primary", view.tone === "good" && "text-green-400", view.tone === "warn" && "text-amber-400", (view.tone === "idle" || view.tone === "neutral") && "text-muted-foreground")} />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-semibold">{view.label}</div>
        <div className="text-xs text-muted-foreground">{error ?? view.detail}</div>
      </div>
      {view.action && (
        <button type="button" onClick={start} disabled={starting} className="px-3.5 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 shrink-0">
          {view.action}
        </button>
      )}
    </div>
  );
}
