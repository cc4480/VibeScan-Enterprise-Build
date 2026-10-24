/**
 * What the "Create GitHub issue" control says. The server decides everything that matters (whether an issue already exists,
 * what is stored, what is redacted: server lib/githubIssues.ts); this only words the states and never claims more than the
 * server returned.
 */

export interface GithubIssueDestination {
  configured: boolean;
  repo: string | null;
  /** False when the server cannot store a token (no encryption key), so there is nothing to offer. */
  available: boolean;
  /** File issues by itself when monitoring finds a new problem. */
  autoFile: boolean;
  /** The lowest severity it files. */
  autoMinSeverity: AutoSeverity;
}

export type AutoSeverity = "critical" | "high" | "medium";

export const AUTO_SEVERITY_CHOICES: ReadonlyArray<{ value: AutoSeverity; label: string }> = [
  { value: "critical", label: "Critical only" },
  { value: "high", label: "High and critical" },
  { value: "medium", label: "Medium and above" },
];

/** What the switch promises, in the words of what the server does (api-server lib/githubIssuesAuto.ts). */
export function autoFileNote(repo: string, minSeverity: AutoSeverity): string {
  const level = AUTO_SEVERITY_CHOICES.find((c) => c.value === minSeverity)?.label.toLowerCase() ?? minSeverity;
  return `When a scheduled scan finds a new problem (${level}) that the last scan did not have, an issue is filed in ${repo}. One per problem, at most 10 a scan; secrets in the evidence are removed first.`;
}

export interface FiledIssue { issueNumber: number; issueUrl: string }

export type IssueView =
  | { kind: "hidden" }
  | { kind: "filed"; label: string; href: string }
  | { kind: "connect"; label: string; detail: string }
  | { kind: "create"; label: string; detail: string; busy: boolean };

/** Only ever a link to github.com's own issue pages: a value the server returned is still checked before it becomes an href. */
export function safeIssueHref(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && (u.hostname === "github.com" || u.hostname.endsWith(".github.com")) ? u.href : null;
  } catch {
    return null;
  }
}

export function issueView(input: { destination: Pick<GithubIssueDestination, "configured" | "repo" | "available"> | undefined; filed: FiledIssue | undefined; starting: boolean }): IssueView {
  const { destination, filed, starting } = input;
  if (!destination || !destination.available) return { kind: "hidden" };
  if (filed) {
    const href = safeIssueHref(filed.issueUrl);
    if (href) return { kind: "filed", label: `Issue #${filed.issueNumber} on GitHub`, href };
  }
  if (!destination.configured) {
    return { kind: "connect", label: "Track this in GitHub", detail: "Connect a repository in Settings to file findings as issues." };
  }
  return {
    kind: "create",
    label: starting ? "Creating the issue…" : "Create GitHub issue",
    detail: `Files this finding in ${destination.repo}. Secrets in the evidence are removed first.`,
    busy: starting,
  };
}

/** The server's own words for a refusal, with a fallback. */
export function issueRefusal(err: unknown): string {
  const data = (err as { data?: { error?: unknown } } | null)?.data;
  return typeof data?.error === "string" ? data.error : "That did not work. Please try again.";
}

/** What the Settings form checks before it sends anything; the server checks again. */
export function destinationFormError(repo: string, token: string): string | null {
  if (!/^\s*(?:https?:\/\/(?:www\.)?github\.com\/)?[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}(?:\.git)?\/?\s*$/.test(repo)) {
    return "Enter the repository as owner/name, for example acme/website.";
  }
  if (!/^[A-Za-z0-9_-]{20,255}$/.test(token.trim())) return "Paste the whole token. It starts with github_pat_ for a fine-grained token.";
  return null;
}
