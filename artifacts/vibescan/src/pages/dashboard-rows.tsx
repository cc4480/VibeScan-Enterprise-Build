/** A scan row in the dashboard list, with its grade badge. */
import { useEffect, useRef, useState } from "react";
import { Link } from "wouter";
import { useGetScanStatus, getGetScanStatusQueryKey, Scan } from "@workspace/api-client-react";
import { Shield, Clock, CheckCircle2, AlertCircle, FileText, Loader2, Info } from "lucide-react";
import { format } from "date-fns";
import { cn } from "@/lib/utils";

export const GRADE_COLORS: Record<string, string> = {
  A: "text-green-400 bg-green-400/10 border-green-400/30",
  B: "text-green-400 bg-green-400/10 border-green-400/30",
  C: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  D: "text-orange-400 bg-orange-400/10 border-orange-400/30",
  F: "text-red-400 bg-red-400/10 border-red-400/30",
};

export function GradeBadge({ grade }: { grade: string | null | undefined }) {
  const key = grade ?? "";
  const colors = GRADE_COLORS[key] ?? "text-muted-foreground bg-secondary border-white/10";
  // "N/A" is the sentinel for a bot-intercepted scan that could not be graded;
  // show it as a dash so the badge does not read as a real letter grade.
  const label = grade == null ? "?" : key in GRADE_COLORS ? grade : "—";
  return (
    <div
      className={cn("w-9 h-9 rounded-lg border flex items-center justify-center font-bold text-lg", colors)}
      title={grade === "N/A" ? "Coverage incomplete — scan was intercepted" : undefined}
    >
      {label}
    </div>
  );
}

export function ScanRow({ initialScan, highlight }: { initialScan: Scan; highlight?: boolean }) {
  const rowRef = useRef<HTMLTableRowElement>(null);
  // Why a scan failed was revealed by CSS hover alone, which no touch device and
  // no keyboard can produce — the only explanation available was unreachable for
  // most of the people who needed it.
  const [showError, setShowError] = useState(false);
  const isPolling = ['pending', 'paid', 'queued', 'scanning', 'analyzing'].includes(initialScan.status);

  const { data: statusData } = useGetScanStatus(initialScan.id, {
    query: {
      queryKey: getGetScanStatusQueryKey(initialScan.id),
      refetchInterval: isPolling ? 3000 : false,
    },
  });

  const scan = statusData ?? initialScan;

  // Note: a scan completing deliberately does NOT navigate away from the
  // dashboard. Auto-redirecting on completion pulled the user off the scan
  // list mid-session, which read as the list "disappearing". The completed
  // row now just updates in place and links to its report.

  // Scroll into view when highlighted (new scan from checkout)
  useEffect(() => {
    if (highlight && rowRef.current) {
      rowRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [highlight]);

  const getStatusDisplay = (status: string, progress?: number) => {
    switch (status) {
      case 'complete':
        return (
          <div className="flex items-center gap-1.5 text-green-400">
            <CheckCircle2 className="w-4 h-4" /> Complete
          </div>
        );
      case 'failed':
        return (
          <div className="flex items-center gap-1.5 text-red-400">
            <AlertCircle className="w-4 h-4" /> Failed
          </div>
        );
      case 'pending':
      case 'paid':
      case 'queued':
        return (
          <div className="flex items-center gap-1.5 text-muted-foreground">
            <Clock className="w-4 h-4" /> Queued
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-2 text-primary">
            <Loader2 className="w-4 h-4 animate-spin" />
            <div className="flex flex-col gap-1 w-24">
              <span className="text-xs capitalize">{status}…</span>
              <div className="h-1 w-full bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-500"
                  style={{ width: `${progress ?? 0}%` }}
                />
              </div>
            </div>
          </div>
        );
    }
  };

  const errorMsg = 'error' in scan ? scan.error : null;

  return (
    <tr
      ref={rowRef}
      className={cn(
        "border-b border-white/5 hover:bg-white/[0.02] transition-colors group",
        highlight && "ring-1 ring-primary/30 bg-primary/5",
      )}
    >
      <td className="p-4 py-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center border border-white/5 shrink-0">
            <GlobeIcon className="w-5 h-5 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <div className="font-medium text-foreground truncate max-w-[180px] sm:max-w-[280px] lg:max-w-[360px]">
              {scan.targetUrl}
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {format(new Date(scan.createdAt), "MMM d, yyyy h:mm a")}
            </div>
          </div>
        </div>
      </td>

      <td className="p-4 hidden sm:table-cell">
        <span className="px-2.5 py-1 rounded-md text-xs font-medium bg-secondary border border-white/5 uppercase tracking-wider">
          {scan.tier === 'deep' ? 'Full scan' : scan.tier.replace('_', ' ')}
        </span>
      </td>

      <td className="p-4">
        {getStatusDisplay(scan.status, 'progress' in scan ? scan.progress : undefined)}
      </td>

      <td className="p-4 hidden md:table-cell">
        {(() => {
          const grade = 'grade' in scan ? (scan as { grade?: string | null }).grade : null;
          if (scan.status === 'complete' && grade) return <GradeBadge grade={grade} />;
          if (scan.status === 'complete') return <Shield className="w-5 h-5 text-green-400" />;
          if (scan.status === 'failed') return <AlertCircle className="w-5 h-5 text-red-400/50" />;
          return <span className="text-muted-foreground">—</span>;
        })()}
      </td>

      <td className="p-4 text-right">
        {scan.status === 'complete' && 'reportId' in scan && scan.reportId ? (
          <Link
            href={`/report/${scan.reportId}`}
            className="inline-flex items-center gap-2 px-4 py-2 bg-secondary hover:bg-white/10 text-foreground text-sm font-medium rounded-lg transition-colors border border-white/5"
          >
            <FileText className="w-4 h-4" /> View Report
          </Link>
        ) : scan.status === 'failed' ? (
          <div className="flex items-center justify-end gap-2">
            {errorMsg && (
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowError((v) => !v)}
                  aria-expanded={showError}
                  className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  <Info className="w-4 h-4" /> Details
                </button>
                {showError && (
                  <div className="absolute right-0 bottom-full mb-2 w-64 p-3 bg-card border border-white/10 rounded-xl shadow-xl text-xs text-muted-foreground z-50 text-left">
                    <p className="font-semibold text-foreground mb-1">Error Details</p>
                    <p>{errorMsg}</p>
                  </div>
                )}
              </div>
            )}
            <Link
              href="/scan"
              className="text-xs text-primary hover:underline underline-offset-4"
            >
              Retry
            </Link>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">Processing…</span>
        )}
      </td>
    </tr>
  );
}

export function GlobeIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24" height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
      <path d="M2 12h20" />
    </svg>
  );
}
