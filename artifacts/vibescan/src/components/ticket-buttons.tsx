import { useState } from "react";
import { useParams } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { ExternalLink, Loader2, Ticket } from "lucide-react";
import { useViewOnly } from "@/lib/use-view-only";
import { issueRefusal } from "@/lib/github-issues";
import { ticketViews, type Provider, type TicketDestination, type TicketRef } from "@/lib/tickets";

/**
 * "Create Linear issue" / "Create Jira ticket" under a finding, for each system the account has connected. Shows the ticket
 * when one already exists for this problem on this site (from this report or an earlier scan). Nothing is shown to someone who
 * is not signed in, on a shared view, or with neither system connected.
 */
export function TicketButtons({ findingId }: { findingId: string }) {
  const { id: reportId } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [starting, setStarting] = useState<Provider | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { known, canFile } = useViewOnly(reportId);

  // The report's own answer: its tickets and where they would go. For an editor that is the owner's destinations.
  const tickets = useQuery({
    queryKey: ["tickets", reportId],
    queryFn: () => customFetch<{ tickets: Record<string, Partial<Record<Provider, TicketRef>>>; destinations: TicketDestination[] }>(`/api/reports/${reportId}/tickets`),
    enabled: Boolean(reportId) && canFile,
    retry: false,
  });

  const views = ticketViews({ destinations: tickets.data?.destinations, filed: tickets.data?.tickets[findingId], starting });
  if (!reportId || !known || !canFile || views.length === 0) return null;

  async function create(provider: Provider) {
    setError(null);
    setStarting(provider);
    try {
      await customFetch(`/api/reports/${reportId}/ticket`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ provider, findingId }) });
      await queryClient.invalidateQueries({ queryKey: ["tickets", reportId] });
    } catch (err) {
      setError(issueRefusal(err));
    } finally {
      setStarting(null);
    }
  }

  return (
    <div className="mt-3 space-y-2">
      {views.map((v) =>
        v.kind === "filed" ? (
          <a key={v.provider} href={v.href} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm font-semibold text-primary hover:underline">
            <Ticket className="w-4 h-4" /> {v.label} <ExternalLink className="w-3.5 h-3.5" />
          </a>
        ) : (
          <div key={v.provider} className="rounded-lg border border-white/10 bg-white/[0.02] px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-3">
            <Ticket className="w-5 h-5 shrink-0 text-muted-foreground" />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold">{v.label}</div>
              <div className="text-xs text-muted-foreground">{v.detail}</div>
            </div>
            <button type="button" onClick={() => create(v.provider)} disabled={v.busy || starting !== null} className="px-3.5 py-1.5 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 shrink-0 inline-flex items-center gap-2">
              {v.busy && <Loader2 className="w-4 h-4 animate-spin" />} Create
            </button>
          </div>
        ),
      )}
      {error && <p role="alert" className="text-xs text-red-400">{error}</p>}
    </div>
  );
}
