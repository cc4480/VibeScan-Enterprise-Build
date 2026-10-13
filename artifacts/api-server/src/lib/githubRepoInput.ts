/**
 * Turns what a person typed into the GitHub repository field into the one form we store and scan,
 * or says why it cannot be used. Shared by the web form's API route and the MCP tool so both accept
 * and reject exactly the same things.
 */
import { parseGithubRepoRef } from "./githubSourceProbe";

export type GithubRepoInput =
  | { ok: true; url: string | null }
  | { ok: false; error: string };

// Kept short: the scan form shows at most 120 characters of a server error.
export const GITHUB_REPO_ERROR = "Not a GitHub repository. Use https://github.com/owner/repo, or leave it empty.";

/** Empty or missing means "no source scan"; anything else has to be a recognisable repository. */
export function normaliseGithubRepoInput(raw: string | null | undefined): GithubRepoInput {
  const trimmed = (raw ?? "").trim();
  if (trimmed === "") return { ok: true, url: null };
  // Bound the length before parsing: this is user text that ends up in a database column and a fetch URL.
  if (trimmed.length > 300) return { ok: false, error: GITHUB_REPO_ERROR };
  const ref = parseGithubRepoRef(trimmed);
  if (!ref) return { ok: false, error: GITHUB_REPO_ERROR };
  const base = `https://github.com/${ref.owner}/${ref.repo}`;
  return { ok: true, url: ref.branch ? `${base}/tree/${encodeURIComponent(ref.branch).replace(/%2F/g, "/")}` : base };
}
