import { ApiError } from "@workspace/api-client-react";
import { Loader2, Plus, BadgeCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { getReportBadge, removeReportBadge, type ReportBadge } from "@/lib/badge-api";

/**
 * The grade badge's state and actions. A hook, called by ShareButton, rather than a component with its own
 * state: the badge has to survive the dialog being closed and reopened, which it only does while the state
 * lives in the component that stays mounted.
 */
export function useReportBadge(reportId: string) {
  // The badge is separate from share links: its token opens an image and nothing else.
  const [badge, setBadge] = useState<ReportBadge | null>(null);
  const [badgeBusy, setBadgeBusy] = useState(false);
  const [badgeError, setBadgeError] = useState<string | null>(null);
  const [copiedBadge, setCopiedBadge] = useState<"markdown" | "html" | null>(null);

  const handleGetBadge = async () => {
    setBadgeBusy(true);
    setBadgeError(null);
    try {
      setBadge(await getReportBadge(reportId));
    } catch (err) {
      // A scan of an unverified domain is refused with a reason the person can act on; say it.
      const data = err instanceof ApiError ? (err.data as { code?: unknown; error?: unknown } | null) : null;
      setBadgeError(
        data?.code === "badge_needs_verified_scan" && typeof data.error === "string"
          ? data.error
          : "Could not create the badge. Try again.",
      );
    } finally {
      setBadgeBusy(false);
    }
  };

  const handleRemoveBadge = async () => {
    setBadgeBusy(true);
    setBadgeError(null);
    try {
      await removeReportBadge(reportId);
      setBadge(null);
    } catch {
      setBadgeError("Could not remove the badge. Try again.");
    } finally {
      setBadgeBusy(false);
    }
  };

  const copyBadge = async (kind: "markdown" | "html") => {
    if (!badge) return;
    const text = kind === "markdown" ? badge.markdown : badge.html;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard refused (some app views do): the field below is selectable instead.
      return;
    }
    setCopiedBadge(kind);
    setTimeout(() => setCopiedBadge(null), 2000);
  };

  return { badge, badgeBusy, badgeError, copiedBadge, handleGetBadge, handleRemoveBadge, copyBadge };
}

export type ReportBadgeState = ReturnType<typeof useReportBadge>;

/** The "Grade badge" block of the share dialog. */
export function BadgeSection({ state }: { state: ReportBadgeState }) {
  const { badge, badgeBusy, badgeError, copiedBadge, handleGetBadge, handleRemoveBadge, copyBadge } = state;
  return (
    <div className="px-5 pb-5 space-y-3 border-t border-white/5 pt-5">
      <label className="flex items-center gap-1.5 text-xs font-bold text-muted-foreground uppercase tracking-wider">
        <BadgeCheck className="w-3.5 h-3.5" /> Grade badge
      </label>
      <p className="text-sm text-muted-foreground">
        A small image for your README or footer, for a scan of a domain you have verified. It
        shows your grade and the scan date, and nothing else: no address, no findings. It turns
        grey and says "old scan" after 30 days.
      </p>
      {!badge ? (
        <button
          onClick={() => void handleGetBadge()}
          disabled={badgeBusy}
          className="px-4 py-2 bg-secondary border border-white/10 rounded-lg text-sm font-semibold hover:bg-white/10 disabled:opacity-60 transition-colors inline-flex items-center gap-2"
        >
          {badgeBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          Get badge
        </button>
      ) : (
        <div className="space-y-3">
          <img src={badge.imageUrl} alt="Your SecScan grade badge" height={20} className="h-5" />
          {(["markdown", "html"] as const).map((kind) => (
            <div key={kind} className="flex items-center gap-2">
              <input
                readOnly
                aria-label={kind === "markdown" ? "Markdown snippet" : "HTML snippet"}
                value={kind === "markdown" ? badge.markdown : badge.html}
                onFocus={(e) => e.currentTarget.select()}
                className="flex-1 min-w-0 px-3 py-2 rounded-lg bg-secondary/50 border border-white/5 text-xs font-mono text-foreground/80"
              />
              <button
                onClick={() => void copyBadge(kind)}
                title={`Copy ${kind === "markdown" ? "Markdown" : "HTML"}`}
                className={cn(
                  "shrink-0 px-2.5 py-2 rounded-lg text-xs font-semibold transition-all",
                  copiedBadge === kind
                    ? "bg-green-500/20 text-green-400"
                    : "bg-secondary border border-white/10 hover:bg-white/10",
                )}
              >
                {copiedBadge === kind ? "Copied" : kind === "markdown" ? "Markdown" : "HTML"}
              </button>
            </div>
          ))}
          <button
            onClick={() => void handleRemoveBadge()}
            disabled={badgeBusy}
            className="text-xs text-muted-foreground hover:text-red-400 underline underline-offset-2 transition-colors"
          >
            Remove badge
          </button>
        </div>
      )}
      {badgeError && <p className="text-sm text-red-400">{badgeError}</p>}
    </div>

  );
}
