import { useEffect, useMemo, useRef } from "react";
import { useLocation, useParams } from "wouter";
import { useGetScanStatus } from "@workspace/api-client-react";
import { CheckCircle2, XCircle, Loader2, Clock, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSeo } from "@/lib/seo";
import { ScanTerminal } from "@/components/scan-terminal";
import { EXPECTED_REPO_STEPS, flattenItems, orderForDisplay, progressPercent, revealDelayMs } from "@/lib/scan-terminal";
import { repoNameFromAddress } from "@/lib/repo-only-report";
import { useLiveTests, useRevealed } from "@/lib/use-live-tests";

const STATUS_LABEL: Record<string, string> = {
  pending: "Waiting…",
  paid: "Scan accepted — queuing…",
  queued: "In queue — waiting for a worker slot",
  scanning: "Scanning your site…",
  analyzing: "Generating your security report…",
  complete: "All done — opening your report",
  failed: "Scan failed",
};

function getDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

/**
 * The scan-in-progress page. The terminal shows the tests the scanner really
 * finished, live, at a readable pace (see lib/scan-terminal.ts). It used to play
 * a scripted animation on a timer that had no connection to the scan.
 */
export default function ScanProgressPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const [, setLocation] = useLocation();
  useSeo({ title: "Scan in progress", noindex: true });

  const { data, isLoading, isError } = useGetScanStatus(scanId, {
    query: {
      queryKey: ["scan-status", scanId],
      refetchInterval: (query) => {
        const s = (query.state.data as { status?: string } | undefined)?.status;
        return s === "complete" || s === "failed" ? false : 2000;
      },
    },
  });

  const status = data?.status ?? "queued";
  const { tests: liveTests, totalChecks, repository: liveRepository } = useLiveTests(scanId, data?.status);
  const scanOver = status === "analyzing" || status === "complete" || status === "failed";
  const tests = useMemo(() => orderForDisplay(liveTests, scanOver), [liveTests, scanOver]);
  // Each test, then the checks inside it: the terminal steps through these one line at a time.
  const items = useMemo(() => flattenItems(tests), [tests]);

  // A scan that was already over when this page opened has nothing to watch:
  // show everything at once instead of replaying it.
  const openedFinished = useRef<boolean | null>(null);
  if (openedFinished.current === null && data) openedFinished.current = status === "complete" || status === "failed";
  const { shown, caughtUp } = useRevealed(items, openedFinished.current === true, revealDelayMs);

  const isComplete = status === "complete";

  // The scan can be over long before the terminal has shown its results. Until it has,
  // the page says "scanning" rather than announcing a finish it is still replaying.
  const replaying = (status === "analyzing" || isComplete) && !caughtUp && openedFinished.current !== true;
  const uiStatus = replaying ? "scanning" : status;
  const isFailed = uiStatus === "failed";
  const isQueued = ["queued", "paid", "pending"].includes(uiStatus);
  const uiComplete = uiStatus === "complete";

  // Open the report once the terminal has shown every test, so the viewer sees
  // what was checked before it disappears.
  const redirected = useRef(false);
  useEffect(() => {
    if (!isComplete || !data?.reportId || !caughtUp || redirected.current) return undefined;
    redirected.current = true;
    const t = setTimeout(() => setLocation(`/report/${data.reportId}`), openedFinished.current ? 600 : 2500);
    return () => clearTimeout(t);
  }, [isComplete, data?.reportId, caughtUp, setLocation]);

  if (isLoading && !data) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-12 text-center">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <p className="text-muted-foreground">Could not load scan status.</p>
        <button onClick={() => setLocation("/dashboard")} className="mt-4 text-sm text-primary hover:underline">
          Back to dashboard
        </button>
      </div>
    );
  }

  const repository = repoNameFromAddress(data?.targetUrl);
  const domain = repository ?? getDomain(data?.targetUrl ?? "");
  const progress = progressPercent(uiStatus, shown.filter((i) => i.kind === "test").length, repository ? EXPECTED_REPO_STEPS : undefined);

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8">
      <div className="text-center mb-6">
        <div
          className={cn(
            "w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4 border",
            uiComplete ? "bg-green-500/10 border-green-500/20" : isFailed ? "bg-red-500/10 border-red-500/20" : "bg-primary/10 border-primary/20",
          )}
        >
          {uiComplete ? (
            <CheckCircle2 className="w-7 h-7 text-green-500" />
          ) : isFailed ? (
            <XCircle className="w-7 h-7 text-red-400" />
          ) : isQueued ? (
            <Clock className="w-7 h-7 text-primary" />
          ) : (
            <Loader2 className="w-7 h-7 text-primary animate-spin" />
          )}
        </div>
        <h1 className="text-xl font-bold tracking-tight">
          {uiComplete ? "Scan Complete" : isFailed ? "Scan Failed" : domain || "Security Scan"}
        </h1>
        <p className="text-sm text-muted-foreground">
          {replaying ? "Showing every check as it was run…" : repository && uiStatus === "scanning" ? "Reading your repository…" : (STATUS_LABEL[uiStatus] ?? "Processing…")}
        </p>
      </div>

      <ScanTerminal
        domain={domain}
        sessionId={data?.id ?? ""}
        status={uiStatus}
        error={data?.error}
        shown={shown}
        all={tests}
        totalChecks={totalChecks}
        caughtUp={caughtUp}
        progress={progress}
        repository={repository}
        sourceRepository={repository ? null : liveRepository}
      />

      <div className="text-center">
        <button onClick={() => setLocation("/dashboard")} className="text-sm text-muted-foreground hover:text-foreground transition-colors">
          ← Back to dashboard
        </button>
      </div>
    </div>
  );
}
