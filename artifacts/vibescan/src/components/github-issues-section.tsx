import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { Github, Loader2, Unplug } from "lucide-react";
import { AUTO_SEVERITY_CHOICES, autoFileNote, destinationFormError, issueRefusal, type AutoSeverity, type GithubIssueDestination } from "@/lib/github-issues";

/**
 * Settings → GitHub issues: the repository findings are filed in, and the fine-grained token that lets SecScan create issues
 * there. The token is checked with GitHub when saved, stored encrypted, and never shown again.
 */
export function GithubIssuesSection() {
  const queryClient = useQueryClient();
  const destination = useQuery({
    queryKey: ["github-issue-destination"],
    queryFn: () => customFetch<GithubIssueDestination>("/api/integrations/github-issues"),
  });
  const [repo, setRepo] = useState("");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["github-issue-destination"] });

  async function save(e: React.FormEvent) {
    e.preventDefault();
    const problem = destinationFormError(repo, token);
    if (problem) { setError(problem); return; }
    setError(null);
    setBusy(true);
    try {
      await customFetch("/api/integrations/github-issues", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo: repo.trim(), token: token.trim() }),
      });
      setToken("");
      setRepo("");
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
      await customFetch("/api/integrations/github-issues/auto", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled, minSeverity }),
      });
      await refresh();
    } catch (err) {
      setError(issueRefusal(err));
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    if (!confirm("Disconnect GitHub issues? The saved token is deleted. Issues already filed stay in GitHub.")) return;
    setBusy(true);
    await customFetch("/api/integrations/github-issues", { method: "DELETE" }).catch(() => {});
    await queryClient.invalidateQueries({ queryKey: ["github-issue-destination"] });
    await queryClient.invalidateQueries({ queryKey: ["github-issues"] });
    setBusy(false);
  }

  if (destination.isLoading) return <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />;
  if (destination.data && !destination.data.available) {
    return <p className="text-sm text-muted-foreground">Filing issues is not available on this server right now.</p>;
  }
  const connected = destination.data?.configured ? destination.data.repo : null;

  return (
    <div className="space-y-3">
      {connected ? (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-white/10 px-4 py-3">
          <Github className="w-4 h-4 text-muted-foreground shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="font-medium truncate">{connected}</div>
            <div className="text-xs text-muted-foreground">Findings are filed here. Save again below to change the repository or replace the token.</div>
          </div>
          <button type="button" onClick={disconnect} disabled={busy} className="inline-flex items-center gap-1.5 text-sm text-red-400 hover:text-red-300 disabled:opacity-60">
            <Unplug className="w-4 h-4" /> Disconnect
          </button>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          File a finding as an issue with one click. Create a <strong>fine-grained personal access token</strong> on GitHub, limited to the one repository, with{" "}
          <strong>Issues: Read and write</strong> and nothing else.
        </p>
      )}

      {connected && destination.data && (
        <div className="rounded-xl border border-white/10 px-4 py-3 space-y-2">
          <div className="flex items-center justify-between gap-4">
            <span className="font-medium text-sm">File new problems automatically</span>
            <button
              type="button"
              role="switch"
              aria-checked={destination.data.autoFile}
              aria-label="File new problems automatically"
              disabled={busy}
              onClick={() => setAuto(!destination.data!.autoFile, destination.data!.autoMinSeverity)}
              className={`w-11 h-6 rounded-full border transition-colors disabled:opacity-50 shrink-0 ${destination.data.autoFile ? "bg-primary border-primary" : "bg-secondary border-white/10"}`}
            >
              <span className={`block w-4 h-4 rounded-full bg-white transition-transform mx-1 ${destination.data.autoFile ? "translate-x-5" : ""}`} />
            </button>
          </div>
          <p className="text-xs text-muted-foreground">{autoFileNote(connected, destination.data.autoMinSeverity)}</p>
          {destination.data.autoFile && (
            <select
              aria-label="Lowest severity to file automatically"
              value={destination.data.autoMinSeverity}
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
        <div className="grid sm:grid-cols-2 gap-3">
          <label className="block text-sm">
            <span className="block mb-1 text-muted-foreground">Repository</span>
            <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="acme/website" autoComplete="off" spellCheck={false}
              className="w-full rounded-lg bg-black/30 border border-white/10 px-3 py-2" />
          </label>
          <label className="block text-sm">
            <span className="block mb-1 text-muted-foreground">Token</span>
            <input value={token} onChange={(e) => setToken(e.target.value)} type="password" placeholder="github_pat_…" autoComplete="off" spellCheck={false}
              className="w-full rounded-lg bg-black/30 border border-white/10 px-3 py-2" />
          </label>
        </div>
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
        <button type="submit" disabled={busy} className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 inline-flex items-center gap-2">
          {busy && <Loader2 className="w-4 h-4 animate-spin" />} {connected ? "Save changes" : "Connect repository"}
        </button>
      </form>
    </div>
  );
}
