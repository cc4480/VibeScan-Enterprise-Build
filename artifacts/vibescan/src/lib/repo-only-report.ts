/**
 * A report from a scan of a GitHub repository alone (no website). Its address is the repository's own
 * https://github.com/owner/repo URL and its test record names the same repository, which a website scan never has.
 * Such a report has no pages, technologies, server, certificate or reconnaissance, and nothing to monitor, so the
 * parts of the report page that describe a website are left out for it.
 */
export function isRepoOnlyReport(targetUrl: string | null | undefined, tests: unknown): boolean {
  const m = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)(?:\/|$)/i.exec(targetUrl ?? "");
  if (!m || !Array.isArray(tests)) return false;
  const repository = `${m[1]}/${m[2]}`.toLowerCase();
  return tests.some((t) => {
    const source = (t as { source?: { repository?: unknown } } | null)?.source;
    return typeof source?.repository === "string" && source.repository.toLowerCase() === repository;
  });
}

/** "owner/repo" when a scan's address is a GitHub repository (a scan of a repository alone), otherwise null. */
export function repoNameFromAddress(address: string | null | undefined): string | null {
  const m = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)(?:\/|$)/i.exec(address ?? "");
  return m ? `${m[1]}/${m[2]}` : null;
}
