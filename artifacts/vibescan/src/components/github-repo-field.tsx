import { Github } from "lucide-react";

/** Same shape the server accepts: owner/repo, or a github.com URL. The server has the final say. */
export function looksLikeGithubRepo(value: string): boolean {
  const v = value.trim();
  if (v === "") return true;
  return /^[\w.-]+\/[\w.-]+$/.test(v) || /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/i.test(v);
}

export function GithubRepoField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const invalid = !looksLikeGithubRepo(value);
  return (
    <div className="flex flex-col gap-3">
      <label htmlFor="github-repo" className="text-sm font-semibold flex items-center gap-2">
        <Github className="w-4 h-4 text-primary" /> Source code check <span className="font-normal text-muted-foreground">(optional)</span>
      </label>
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
        className="w-full bg-background border-2 border-white/10 rounded-xl py-3 px-4 focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/10 transition-all placeholder:text-muted-foreground/50"
      />
      <p id="github-repo-help" className={invalid ? "text-xs text-red-400 ml-1" : "text-xs text-muted-foreground ml-1"}>
        {invalid
          ? "Use a public repository written as https://github.com/owner/repo."
          : "Also read a public GitHub repository for API keys and passwords committed to its files. Public repositories only, and only GitHub is contacted for it, never your site."}
      </p>
    </div>
  );
}
