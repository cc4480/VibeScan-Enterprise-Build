import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Github, Lock, CheckCircle2, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  CONNECT_HREF,
  MANAGE_HREF,
  connectionNote,
  connectOutcomeMessage,
  disconnectGithub,
  getGithubRepos,
  repoFieldValue,
} from "@/lib/github-connect-api";

/** Same shape the server accepts: owner/repo, or a github.com URL. The server has the final say. */
export function looksLikeGithubRepo(value: string): boolean {
  const v = value.trim();
  if (v === "") return true;
  return /^[\w.-]+\/[\w.-]+$/.test(v) || /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/i.test(v);
}

/**
 * The repository a scan also reads. Any public repository works by its address. For a private one the person
 * connects GitHub (a trip to GitHub's own page, where they choose which repositories SecScan may read), and the
 * repositories they shared appear here to pick from.
 */
export function GithubRepoField({ value, onChange, only = false }: { value: string; onChange: (v: string) => void; only?: boolean }) {
  // `only`: the repository is the whole scan (no website), so it is the target, not an optional extra.
  const invalid = !looksLikeGithubRepo(value);
  const queryClient = useQueryClient();
  const [disconnecting, setDisconnecting] = useState<number | null>(null);

  // Signed-out visitors get a 401 here; the field then simply works for public repositories.
  const repos = useQuery({ queryKey: ["github-repos"], queryFn: getGithubRepos, retry: false, staleTime: 60_000 });
  const outcome = useMemo(() => connectOutcomeMessage(typeof window === "undefined" ? "" : window.location.search), []);

  const available = repos.data?.available === true;
  const connections = repos.data?.connections ?? [];
  const repositories = repos.data?.repositories ?? [];
  const picked = repositories.find((r) => repoFieldValue(r) === value.trim());

  async function disconnect(installationId: number) {
    setDisconnecting(installationId);
    try {
      await disconnectGithub(installationId);
      if (picked?.installationId === installationId) onChange("");
      await queryClient.invalidateQueries({ queryKey: ["github-repos"] });
    } finally {
      setDisconnecting(null);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <label htmlFor="github-repo" className="text-sm font-semibold flex items-center gap-2">
        <Github className="w-4 h-4 text-primary" /> {only ? "GitHub repository" : "Source code check"} {!only && <span className="font-normal text-muted-foreground">(optional)</span>}
      </label>

      {outcome && (
        <div
          role="status"
          className={cn(
            "flex items-start gap-2 rounded-lg border px-3 py-2 text-xs",
            outcome.tone === "good" ? "border-green-500/30 bg-green-500/5 text-green-300" : "border-amber-500/30 bg-amber-500/5 text-amber-200",
          )}
        >
          {outcome.tone === "good" ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertTriangle className="w-4 h-4 shrink-0" />}
          <span>{outcome.text}</span>
        </div>
      )}

      {repositories.length > 0 && (
        <select
          id="github-repo-pick"
          aria-label="Choose a connected repository"
          value={picked ? picked.fullName : ""}
          onChange={(e) => {
            const r = repositories.find((x) => x.fullName === e.target.value);
            onChange(r ? repoFieldValue(r) : "");
          }}
          className="w-full bg-background border-2 border-white/10 rounded-xl py-3 px-4 focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/10"
        >
          <option value="">Choose a connected repository…</option>
          {repositories.map((r) => (
            <option key={`${r.installationId}:${r.fullName}`} value={r.fullName}>
              {r.fullName}{r.private ? " (private)" : ""}
            </option>
          ))}
        </select>
      )}

      <input
        id="github-repo"
        type="text"
        inputMode="url"
        autoComplete="off"
        placeholder="https://github.com/owner/repo"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={invalid}
        aria-describedby="github-repo-help"
        className={
          "w-full bg-background border-2 rounded-xl py-3 px-4 focus:outline-none focus:ring-4 transition-all placeholder:text-muted-foreground/50 " +
          (invalid
            ? "border-red-500/60 focus:border-red-500 focus:ring-red-500/10"
            : "border-white/10 focus:border-primary focus:ring-primary/10")
        }
      />
      <p id="github-repo-help" className={invalid ? "text-xs text-red-400 ml-1" : "text-xs text-muted-foreground ml-1"}>
        {invalid
          ? "Use a repository written as https://github.com/owner/repo."
          : `${only ? "The repository to scan." : "Also read a GitHub repository's source for leaked keys and risky code."} Any public repository works by its address; for a private one, connect GitHub. Only GitHub is contacted for it${only ? "." : ", never your site."}`}
      </p>

      {available && connections.length === 0 && (
        <a
          href={CONNECT_HREF}
          className="inline-flex w-fit items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-sm font-medium hover:border-primary/50"
        >
          <Lock className="w-4 h-4 text-primary" /> Connect GitHub for private repositories
        </a>
      )}

      {available && connections.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground ml-1">
          <span>
            Connected:{" "}
            {connections.map((c, i) => (
              <span key={c.installationId}>
                {i > 0 && ", "}
                <span className="text-foreground">{c.accountLogin ?? `installation ${c.installationId}`}</span>{" "}
                <button
                  type="button"
                  onClick={() => disconnect(c.installationId)}
                  disabled={disconnecting === c.installationId}
                  className="underline underline-offset-2 hover:text-foreground disabled:opacity-60"
                >
                  {disconnecting === c.installationId ? "disconnecting…" : "disconnect"}
                </button>
              </span>
            ))}
          </span>
          <a href={MANAGE_HREF} className="text-primary underline underline-offset-2">Add or change repositories</a>
        </div>
      )}

      {available && connections.map((c) => {
        const note = connectionNote(c);
        return note ? (
          <p key={`note-${c.installationId}`} role="status" className="flex items-start gap-2 text-xs text-amber-200 ml-1">
            <AlertTriangle className="w-4 h-4 shrink-0" /> <span>{note}</span>
          </p>
        ) : null;
      })}
    </div>
  );
}
