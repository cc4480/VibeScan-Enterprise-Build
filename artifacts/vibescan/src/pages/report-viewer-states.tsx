import type { MutableRefObject } from "react";
import { Vulnerability } from "@workspace/api-client-react";
import { Loader2 } from "lucide-react";

export function ReportLoading() {
  return (
    <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4">
      <Loader2 className="w-8 h-8 animate-spin text-primary" />
      <p className="text-sm text-muted-foreground">Loading report…</p>
    </div>
  );
}

/** Why a report could not be shown, named by cause: not signed in, wrong account, or a plain failure. */
export function ReportLoadFailure({ error, reportId, signedInAs }: { error: unknown; reportId: string; signedInAs: string | null | undefined }) {
  // "Failed to load report." told the reader nothing, and the two most common
  // causes are both about WHO is signed in rather than anything being broken: a
  // 401 because this browser has no session, and a 404 because the report
  // belongs to a different account than the one signed in here. Both happen
  // routinely when a report link is opened on a phone. Name the actual cause and
  // the action, so the reader is not left staring at a dead end.
  const status = (error as { status?: number } | null | undefined)?.status;

  if (status === 401) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-3 px-6 text-center">
        <p className="text-base font-medium">Sign in to view this report</p>
        <p className="max-w-md text-sm text-muted-foreground">
          You're not signed in on this device. Reports are private to the account that ran the scan.
        </p>
        <a
          href={`/sign-in?returnTo=${encodeURIComponent(`/report/${reportId}`)}`}
          className="text-sm text-primary underline underline-offset-4"
        >
          Sign in to see it
        </a>
      </div>
    );
  }

  if (status === 404) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-3 px-6 text-center">
        <p className="text-base font-medium">This report belongs to a different account</p>
        <p className="max-w-md text-sm text-muted-foreground">
          {signedInAs
            ? `You're signed in as ${signedInAs}. Sign out, then sign in with the account that ran this scan.`
            : "Sign in with the account that ran this scan."}
        </p>
        <a href="/dashboard" className="text-sm text-primary underline underline-offset-4">Go to your dashboard</a>
      </div>
    );
  }

  return (
    <div className="min-h-[80vh] flex flex-col items-center justify-center gap-3 px-6 text-center">
      <p className="text-base font-medium">Couldn't load this report</p>
      <p className="max-w-md text-sm text-muted-foreground">
        Something went wrong fetching it. Refresh to try again — if it keeps happening, the report may not have finished saving.
      </p>
    </div>
  );
}

/** The timed toast shown for five seconds after a finding is dismissed. */
export function UndoToast({ undoToast, undoToastTimerRef, setUndoToast, undismissFinding }: {
  undoToast: { key: string; vuln: Vulnerability } | null;
  undoToastTimerRef: MutableRefObject<ReturnType<typeof setTimeout> | null>;
  setUndoToast: (t: { key: string; vuln: Vulnerability } | null) => void;
  undismissFinding: (v: Vulnerability) => Promise<void>;
}) {
  if (!undoToast) return null;
  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-background border border-border rounded-xl px-4 py-3 shadow-2xl text-sm animate-in slide-in-from-bottom-2 duration-200">
      <span className="text-muted-foreground">
        <span className="font-semibold text-foreground truncate max-w-[200px] inline-block align-bottom">{undoToast.vuln.name}</span>
        {" "}dismissed as false positive
      </span>
      <button
        onClick={async () => {
          if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
          const toastVuln = undoToast.vuln;
          setUndoToast(null);
          await undismissFinding(toastVuln);
        }}
        className="text-primary hover:text-primary/80 font-bold underline underline-offset-2 shrink-0"
      >
        Undo
      </button>
    </div>
  );
}
