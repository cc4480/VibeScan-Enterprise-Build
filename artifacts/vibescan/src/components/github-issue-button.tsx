import { useState } from "react";
import { Link } from "wouter";
import { useParams } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { ExternalLink, Github, Loader2 } from "lucide-react";
import { useViewOnly } from "@/lib/use-view-only";
import { issueRefusal, issueView, type FiledIssue, type GithubIssueDestination } from "@/lib/github-issues";

type Destination = Pick<GithubIssueDestination, "configured" | "repo" | "available">;

/**
 * "Create GitHub issue" under a finding's recommended fix. Shows the issue when one already exists for this problem on this
 * site (from this report or an earlier scan), and offers to connect a repository when there is none. Nothing is shown to
 * someone who is not signed in or on a server that cannot store a token.
 */
export function GithubIssueButton({ findingId }: { findingId: string }) {
  const { id: reportId } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { known, canFile, viewOnly } = useViewOnly(reportId);

  // The report's own answer: its issues and where they would go. For an editor that is the owner's repository.
  const issues = useQuery({
    queryKey: ["github-issues", reportId],
    queryFn: () => customFetch<{ issues: Record<string, FiledIssue>; destination: Destination | null }>(`/api/reports/${reportId}/github-issues`),
    enabled: Boolean(reportId) && canFile,
    retry: false,
  });

  const view = issueView({ destination: issues.data?.destination ?? undefined, filed: issues.data?.issues[findingId], starting });
  if (!reportId || !known || !canFile || view.kind === "hidden") return null;
  // An editor is on someone else's team: with no repository connected there is nothing for them to do, and Settings is not theirs.
  if (viewOnly && view.kind === "connect") return null;

  async function create() {
    setError(null);
    setStarting(true);
    try {
      await customFetch(`/api/reports/${reportId}/github-issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingId }),
      });
      await queryClient.invalidateQueries({ queryKey: ["github-issues", reportId] });
    } catch (err) {
      setError(issueRefusal(err));
    } finally {
      setStarting(false);
    }
  }

  if (view.kind === "filed") {
    return (
      <a href={view.href} target="_blank" rel="noopener noreferrer" className="mt-3 inline-flex items-center gap-2 text-sm font-semibold text-primary hover:underline">
        <Github className="w-4 h-4" /> {view.label} <ExternalLink className="w-3.5 h-3.5" />
      </a>
    );
  }

  return (
    <div className="mt-3 rounded-lg border border-white/10 bg-white/[0.02] px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-3">
      <Github className="w-5 h-5 shrink-0 text-muted-foreground" />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-semibold">{view.label}</div>
        <div className="text-xs text-muted-foreground">{error ?? view.detail}</div>
      </div>
      {view.kind === "connect" ? (
        <Link href="/settings" className="px-3.5 py-1.5 rounded-lg border border-white/15 text-sm font-semibold shrink-0">Open Settings</Link>
      ) : (
        <button type="button" onClick={create} disabled={view.busy} className="px-3.5 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 shrink-0 inline-flex items-center gap-2">
          {view.busy && <Loader2 className="w-4 h-4 animate-spin" />} Create issue
        </button>
      )}
    </div>
  );
}
