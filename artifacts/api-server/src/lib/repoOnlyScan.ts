/**
 * A scan of a GitHub repository alone, with no website.
 *
 * It is the ordinary scan with a repository address where the website address goes, so it spends the same credit,
 * counts against the same daily quota, queues the same way and is stored as the same kind of report, with nothing
 * added to the database. What marks it is that the scan's address and its repository are the same
 * https://github.com/owner/repo URL, which a real website scan never has (the address is a site, the repository is
 * an optional extra). The site checks are skipped for it, since there is no site.
 */
import { normaliseGithubRepoInput } from "./githubRepoInput";

/** The normalised repository URL when `address` is a GitHub repository, otherwise null (an ordinary website). */
export function repoOnlyAddress(address: string): string | null {
  if (!/^https?:\/\/(?:www\.)?github\.com\/[^/]+\/[^/?#]+/i.test(address.trim())) return null;
  const parsed = normaliseGithubRepoInput(address);
  return parsed.ok ? parsed.url : null;
}

/** True for a stored scan that was a repository alone. */
export function isRepoOnlyScan(targetUrl: string, githubRepoUrl: string | null | undefined): boolean {
  return Boolean(githubRepoUrl) && githubRepoUrl === targetUrl && repoOnlyAddress(targetUrl) === targetUrl;
}
