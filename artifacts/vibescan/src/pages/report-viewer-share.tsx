/** Create and revoke a public share link for the report. */
import { useCreateReportShare, useListReportShares, useRevokeReportShare, getListReportSharesQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Loader2, Share2, Plus, X, Copy, Check, BadgeCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { getReportBadge, removeReportBadge, type ReportBadge } from "@/lib/badge-api";

// ─── Share dialog ─────────────────────────────────────────────────────────────

export interface ShareLink {
  id: string;
  token: string;
  expiresAt: string | null;
  createdAt: string;
  revokedAt: string | null;
}

export function ShareButton({ reportId }: { reportId: string }) {
  const [open, setOpen] = useState(false);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<"7d" | "30d" | "never">("never");
  const queryClient = useQueryClient();

  // The badge is separate from share links: its token opens an image and nothing else.
  const [badge, setBadge] = useState<ReportBadge | null>(null);
  const [badgeBusy, setBadgeBusy] = useState(false);
  const [badgeError, setBadgeError] = useState<string | null>(null);
  const [copiedBadge, setCopiedBadge] = useState<"markdown" | "html" | null>(null);

  const { data: shares = [], isLoading: loadingShares } = useListReportShares(reportId, {
    query: {
      queryKey: getListReportSharesQueryKey(reportId),
      enabled: open,
    },
  });

  const { mutate: createShare, isPending: creating } = useCreateReportShare({
    mutation: {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: getListReportSharesQueryKey(reportId) });
      },
    },
  });

  const { mutate: revokeShare, isPending: revoking } = useRevokeReportShare({
    mutation: {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: getListReportSharesQueryKey(reportId) });
      },
    },
  });

  const copyLink = async (token: string) => {
    const url = `${window.location.origin}/share/${token}`;
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      prompt("Copy this link:", url);
    }
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2000);
  };

  const handleGetBadge = async () => {
    setBadgeBusy(true);
    setBadgeError(null);
    try {
      setBadge(await getReportBadge(reportId));
    } catch {
      setBadgeError("Could not create the badge. Try again.");
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

  const handleCreate = () => {
    createShare({ id: reportId, data: { expiresIn } });
  };

  const handleRevoke = (token: string) => {
    revokeShare({ id: reportId, token });
  };

  const activeShares = (shares as ShareLink[]).filter((s) => !s.revokedAt);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors"
      >
        <Share2 className="w-4 h-4" />
        Share Report
      </button>

      {/* Dialog overlay */}
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}
        >
          <div
            className="relative w-full max-w-md bg-background border border-white/10 rounded-2xl shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between p-5 border-b border-white/5">
              <div className="flex items-center gap-2">
                <Share2 className="w-4 h-4 text-primary" />
                <h2 className="font-bold text-base">Share Report</h2>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="p-1.5 hover:bg-white/5 rounded-lg transition-colors"
              >
                <X className="w-4 h-4 text-muted-foreground" />
              </button>
            </div>

            {/* Body */}
            <div className="p-5 space-y-5">
              <p className="text-sm text-muted-foreground">
                Share links let anyone view this report without logging in. You can revoke them at any time.
              </p>

              {/* Create new link */}
              <div className="space-y-3">
                <label className="block text-xs font-bold text-muted-foreground uppercase tracking-wider">
                  Create New Link
                </label>
                <div className="flex gap-2">
                  <select
                    value={expiresIn}
                    onChange={(e) => setExpiresIn(e.target.value as "7d" | "30d" | "never")}
                    className="flex-1 px-3 py-2 rounded-lg bg-secondary border border-white/10 text-sm text-foreground focus:outline-none focus:border-primary/50"
                  >
                    <option value="never">Never expires</option>
                    <option value="7d">Expires in 7 days</option>
                    <option value="30d">Expires in 30 days</option>
                  </select>
                  <button
                    onClick={handleCreate}
                    disabled={creating}
                    className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-semibold hover:opacity-90 disabled:opacity-60 transition-all flex items-center gap-2 shrink-0"
                  >
                    {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    Create
                  </button>
                </div>
              </div>

              {/* Existing links */}
              <div className="space-y-2">
                <label className="block text-xs font-bold text-muted-foreground uppercase tracking-wider">
                  Active Links {activeShares.length > 0 && `(${activeShares.length})`}
                </label>

                {loadingShares ? (
                  <div className="py-4 flex justify-center">
                    <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                  </div>
                ) : activeShares.length === 0 ? (
                  <div className="py-4 text-center text-sm text-muted-foreground border border-dashed border-white/10 rounded-xl">
                    No active share links yet.
                  </div>
                ) : (
                  <div className="space-y-2 max-h-52 overflow-y-auto">
                    {activeShares.map((share) => {
                      const shortToken = share.token.slice(0, 12) + "…";
                      const expires = share.expiresAt
                        ? new Date(share.expiresAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
                        : "Never";
                      const isExpired = share.expiresAt ? new Date(share.expiresAt) < new Date() : false;

                      return (
                        <div
                          key={share.id}
                          className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-secondary/50 border border-white/5"
                        >
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-mono text-foreground/70 truncate">{shortToken}</p>
                            <p className={cn(
                              "text-[10px] mt-0.5",
                              isExpired ? "text-red-400" : "text-muted-foreground/60",
                            )}>
                              {isExpired ? "Expired" : `Expires: ${expires}`}
                            </p>
                          </div>
                          <button
                            onClick={() => void copyLink(share.token)}
                            title="Copy link"
                            className={cn(
                              "shrink-0 p-1.5 rounded-lg transition-all",
                              copiedToken === share.token
                                ? "bg-green-500/20 text-green-400"
                                : "hover:bg-white/10 text-muted-foreground hover:text-foreground",
                            )}
                          >
                            {copiedToken === share.token ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                          <button
                            onClick={() => handleRevoke(share.token)}
                            disabled={revoking}
                            title="Revoke link"
                            className="shrink-0 p-1.5 rounded-lg hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-all"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Grade badge */}
            <div className="px-5 pb-5 space-y-3 border-t border-white/5 pt-5">
              <label className="flex items-center gap-1.5 text-xs font-bold text-muted-foreground uppercase tracking-wider">
                <BadgeCheck className="w-3.5 h-3.5" /> Grade badge
              </label>
              <p className="text-sm text-muted-foreground">
                A small image for your README or footer. It shows your grade and the scan date, and
                nothing else: no address, no findings. It turns grey and says "old scan" after 30 days.
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

            {/* Footer note */}
            <div className="px-5 pb-4 text-xs text-muted-foreground/50">
              Recipients can view the report and download a PDF — they cannot modify findings or access your account.
            </div>
          </div>
        </div>
      )}
    </>
  );
}
