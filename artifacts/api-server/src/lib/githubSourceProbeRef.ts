/** Parsing a user-supplied GitHub repository reference. */
export interface GithubRepoRef {
  owner: string;
  repo: string;
  /** A branch named in a pasted /tree/<branch> URL. The default branch is used when absent. */
  branch?: string;
}

export const NAME = /^[\w.-]+$/;

/** A name that is really a name: plain characters, and not empty, "." or ".." (which would be a path of its own). */
export function isPlainName(s: string): boolean {
  return NAME.test(s) && s !== "." && s !== "..";
}

/** Accepts a bare "owner/repo" or a full https://github.com/owner/repo(.git)(/tree/<branch>) URL. */
export function parseGithubRepoRef(input: string): GithubRepoRef | null {
  const trimmed = input.trim();
  const bare = /^([\w.-]+)\/([\w.-]+)$/.exec(trimmed);
  if (bare) {
    // The same checks as the URL form: "../.." and ".git/.git" are not repositories, and both end up in fetched URLs.
    const owner = bare[1]!;
    const repo = bare[2]!.replace(/\.git$/, "");
    return isPlainName(owner) && isPlainName(repo) ? { owner, repo } : null;
  }

  try {
    const url = new URL(trimmed);
    if (url.hostname !== "github.com" && url.hostname !== "www.github.com") return null;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const owner = parts[0]!;
    const repo = parts[1]!.replace(/\.git$/, "");
    // Both end up in URLs that are fetched: a name that is not plain would be a path of its own.
    if (!isPlainName(owner) || !isPlainName(repo)) return null;
    if (parts[2] === "tree" && parts.length > 3) {
      try {
        return { owner, repo, branch: decodeURIComponent(parts.slice(3).join("/")) };
      } catch {
        return { owner, repo };
      }
    }
    return { owner, repo };
  } catch {
    return null;
  }
}
