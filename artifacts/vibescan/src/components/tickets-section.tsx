import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { Loader2, Unplug } from "lucide-react";
import { AUTO_SEVERITY_CHOICES, issueRefusal, type AutoSeverity } from "@/lib/github-issues";
import {
  PROVIDER_NAME, destinationLabel, jiraFormError, linearFormError, ticketAutoNote,
  type JiraForm, type LinearForm, type Provider, type TicketDestination, type TicketDestinations,
} from "@/lib/tickets";

const INPUT = "w-full rounded-lg bg-black/30 border border-white/10 px-3 py-2";

/**
 * Settings → Linear and Jira: where findings are filed as tickets, and the credential that lets SecScan create them. The
 * credential is checked with the provider when saved, stored encrypted, and never shown again.
 */
export function TicketsSection() {
  const destinations = useQuery({
    queryKey: ["ticket-destinations"],
    queryFn: () => customFetch<TicketDestinations>("/api/integrations/tickets"),
  });
  if (destinations.isLoading) return <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />;
  if (destinations.data && !destinations.data.available) {
    return <p className="text-sm text-muted-foreground">Filing tickets is not available on this server right now.</p>;
  }
  const by = (p: Provider) => destinations.data?.destinations.find((d) => d.provider === p) ?? null;
  return (
    <div className="space-y-8">
      <ProviderCard provider="linear" destination={by("linear")} />
      <ProviderCard provider="jira" destination={by("jira")} />
    </div>
  );
}

function ProviderCard({ provider, destination }: { provider: Provider; destination: TicketDestination | null }) {
  const queryClient = useQueryClient();
  const [linear, setLinear] = useState<LinearForm>({ team: "", apiKey: "" });
  const [jira, setJira] = useState<JiraForm>({ site: "", email: "", token: "", project: "", issueType: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const name = PROVIDER_NAME[provider];

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["ticket-destinations"] });

  async function save(e: React.FormEvent) {
    e.preventDefault();
    const problem = provider === "linear" ? linearFormError(linear) : jiraFormError(jira);
    if (problem) { setError(problem); return; }
    setError(null);
    setBusy(true);
    try {
      const body = provider === "linear"
        ? { team: linear.team.trim(), apiKey: linear.apiKey.trim() }
        : { site: jira.site.trim(), email: jira.email.trim(), token: jira.token.trim(), project: jira.project.trim(), ...(jira.issueType.trim() ? { issueType: jira.issueType.trim() } : {}) };
      await customFetch(`/api/integrations/tickets/${provider}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      setLinear({ team: "", apiKey: "" });
      setJira({ site: "", email: "", token: "", project: "", issueType: "" });
      await refresh();
    } catch (err) {
      setError(issueRefusal(err));
    } finally {
      setBusy(false);
    }
  }

  async function setAuto(enabled: boolean, minSeverity: AutoSeverity) {
    setBusy(true);
    setError(null);
    try {
      await customFetch(`/api/integrations/tickets/${provider}/auto`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled, minSeverity }) });
      await refresh();
    } catch (err) {
      setError(issueRefusal(err));
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    if (!confirm(`Disconnect ${name}? The saved credential is deleted. Tickets already filed stay in ${name}.`)) return;
    setBusy(true);
    await customFetch(`/api/integrations/tickets/${provider}`, { method: "DELETE" }).catch(() => {});
    await refresh();
    await queryClient.invalidateQueries({ queryKey: ["tickets"] });
    setBusy(false);
  }

  return (
    <section aria-label={name} className="space-y-3">
      <h3 className="font-semibold">{name}</h3>
      {destination ? (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-white/10 px-4 py-3">
          <div className="flex-1 min-w-0">
            <div className="font-medium truncate">{destinationLabel(destination)}</div>
            <div className="text-xs text-muted-foreground">Findings are filed here. Save again below to change where, or to replace the credential.</div>
          </div>
          <button type="button" onClick={disconnect} disabled={busy} className="inline-flex items-center gap-1.5 text-sm text-red-400 hover:text-red-300 disabled:opacity-60">
            <Unplug className="w-4 h-4" /> Disconnect
          </button>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          {provider === "linear"
            ? "File a finding as a Linear issue with one click. Create a personal API key in Linear (Settings, Security & access) and name the team."
            : "File a finding as a Jira ticket with one click. Create an API token for your Atlassian account, and name the site and project. The account needs permission to create issues there."}
        </p>
      )}

      {destination && (
        <div className="rounded-xl border border-white/10 px-4 py-3 space-y-2">
          <div className="flex items-center justify-between gap-4">
            <span className="font-medium text-sm">File new problems automatically</span>
            <button
              type="button"
              role="switch"
              aria-checked={destination.autoFile}
              aria-label={`File new problems in ${name} automatically`}
              disabled={busy}
              onClick={() => setAuto(!destination.autoFile, destination.autoMinSeverity)}
              className={`w-11 h-6 rounded-full border transition-colors disabled:opacity-50 shrink-0 ${destination.autoFile ? "bg-primary border-primary" : "bg-secondary border-white/10"}`}
            >
              <span className={`block w-4 h-4 rounded-full bg-white transition-transform mx-1 ${destination.autoFile ? "translate-x-5" : ""}`} />
            </button>
          </div>
          <p className="text-xs text-muted-foreground">{ticketAutoNote(destination)}</p>
          {destination.autoFile && (
            <select
              aria-label={`Lowest severity to file in ${name} automatically`}
              value={destination.autoMinSeverity}
              disabled={busy}
              onChange={(e) => setAuto(true, e.target.value as AutoSeverity)}
              className="px-2 py-1.5 rounded-lg bg-secondary border border-white/10 text-sm"
            >
              {AUTO_SEVERITY_CHOICES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
          )}
        </div>
      )}

      <form onSubmit={save} className="space-y-3">
        {provider === "linear" ? (
          <div className="grid sm:grid-cols-2 gap-3">
            <label className="block text-sm">
              <span className="block mb-1 text-muted-foreground">Team key</span>
              <input value={linear.team} onChange={(e) => setLinear({ ...linear, team: e.target.value })} placeholder="ENG" autoComplete="off" spellCheck={false} className={INPUT} />
            </label>
            <label className="block text-sm">
              <span className="block mb-1 text-muted-foreground">API key</span>
              <input value={linear.apiKey} onChange={(e) => setLinear({ ...linear, apiKey: e.target.value })} type="password" placeholder="lin_api_…" autoComplete="off" spellCheck={false} className={INPUT} />
            </label>
          </div>
        ) : (
          <div className="grid sm:grid-cols-2 gap-3">
            <label className="block text-sm">
              <span className="block mb-1 text-muted-foreground">Jira site</span>
              <input value={jira.site} onChange={(e) => setJira({ ...jira, site: e.target.value })} placeholder="acme.atlassian.net" autoComplete="off" spellCheck={false} className={INPUT} />
            </label>
            <label className="block text-sm">
              <span className="block mb-1 text-muted-foreground">Project key</span>
              <input value={jira.project} onChange={(e) => setJira({ ...jira, project: e.target.value })} placeholder="SEC" autoComplete="off" spellCheck={false} className={INPUT} />
            </label>
            <label className="block text-sm">
              <span className="block mb-1 text-muted-foreground">Atlassian account email</span>
              <input value={jira.email} onChange={(e) => setJira({ ...jira, email: e.target.value })} type="email" placeholder="you@acme.com" autoComplete="off" spellCheck={false} className={INPUT} />
            </label>
            <label className="block text-sm">
              <span className="block mb-1 text-muted-foreground">API token</span>
              <input value={jira.token} onChange={(e) => setJira({ ...jira, token: e.target.value })} type="password" autoComplete="off" spellCheck={false} className={INPUT} />
            </label>
            <label className="block text-sm sm:col-span-2">
              <span className="block mb-1 text-muted-foreground">Issue type (optional, Task by default)</span>
              <input value={jira.issueType} onChange={(e) => setJira({ ...jira, issueType: e.target.value })} placeholder="Task" autoComplete="off" spellCheck={false} className={INPUT} />
            </label>
          </div>
        )}
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
        <button type="submit" disabled={busy} className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 inline-flex items-center gap-2">
          {busy && <Loader2 className="w-4 h-4 animate-spin" />} {destination ? "Save changes" : `Connect ${name}`}
        </button>
      </form>
    </section>
  );
}
