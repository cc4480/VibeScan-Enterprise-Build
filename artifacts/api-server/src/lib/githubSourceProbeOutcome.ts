/** What a repository scan achieved, and why when it did not. */
import type { ProbeOutcome, SourceScanRecord } from "./testLedger";
import type { ScanVulnerability } from "./scanner";

/**
 * What a scan of one repository actually did. "Nothing found" only means something when
 * `status` is "scanned" (or "empty", a repo with no files at all); every other status is a
 * repository that was not looked at.
 */
export interface GithubScanOutcome {
  findings: ScanVulnerability[];
  status: "scanned" | "empty" | "unreachable" | "rate_limited" | "not_public_or_missing" | "blocked" | "unreadable";
  /** Files that matched the candidate list and were read. */
  filesRead: number;
  /** Candidate files left unread because of the file cap. */
  skipped?: number;
  /** GitHub cut the file list short, so files beyond it were never seen. */
  truncated?: boolean;
  /** How much of the repository was looked at (the repository scanner fills these in). */
  coverage?: {
    treeFiles: number; chosen: number; read: number; bytesRead: number; leftOutByCap: number;
    tooLarge: number; truncatedTree: boolean; failedReads: number; notRead?: { binary: number; vendored: number };
    /** Files read, by what they were read for. */
    byCheck?: Record<string, number>;
  };
  /** What each check looked at and found. */
  checks?: Array<{ name: string; files: number; findings: number; note?: string }>;
  /** How the repository was read. */
  via?: "public" | "github-app";
}

/** Why a repository was not looked at, or null when it was. */
export function githubNotScannedReason(status: GithubScanOutcome["status"]): string | null {
  switch (status) {
    case "unreachable": return "GitHub could not be reached, or answered with a server error";
    case "rate_limited": return "GitHub's public API rate limit was reached";
    case "not_public_or_missing": return "the repository is private or does not exist";
    case "blocked": return "GitHub refused to serve this repository (it may be blocked or restricted)";
    case "unreadable": return "GitHub answered, but the repository's files could not be read";
    default: return null;
  }
}

/**
 * How the ledger should record a GitHub scan. A repository GitHub says is private or does not exist is
 * an input this scan cannot use, not a fault in the scan: it is "not tested", with the reason and the
 * fact that only public repositories can be read, so the report does not count it as a failed test. A
 * GitHub outage, a rate limit, a block or unreadable files are failures (they throw), as before.
 */
export function githubProbeOutcome(outcome: GithubScanOutcome, ref?: { owner: string; repo: string }): ProbeOutcome {
  if (outcome.status === "not_public_or_missing") {
    return {
      findings: [],
      notTested: outcome.via === "github-app"
        ? "the repository could not be read through the connected GitHub account: it may no longer be shared with SecScan, or it does not exist. Connect GitHub again and choose it"
        : "the repository is private, or does not exist. To scan a private repository, connect GitHub on the scan page and choose it; a public one needs nothing",
      ...(ref ? { source: { repository: `${ref.owner}/${ref.repo}`, ...(outcome.via ? { via: outcome.via } : {}) } } : {}),
    };
  }
  const why = githubNotScannedReason(outcome.status);
  if (why) throw new Error(why);
  return { findings: outcome.findings, ...(ref ? { source: sourceRecord(outcome, ref) } : {}) };
}

/** What the report keeps of a repository scan: how it was read, how much, and what each check found. */
export function sourceRecord(outcome: GithubScanOutcome, ref: { owner: string; repo: string }): SourceScanRecord {
  const c = outcome.coverage;
  return {
    repository: `${ref.owner}/${ref.repo}`,
    ...(outcome.via ? { via: outcome.via } : {}),
    read: c?.read ?? outcome.filesRead,
    ...(c
      ? {
          treeFiles: c.treeFiles, chosen: c.chosen, bytesRead: c.bytesRead, leftOut: c.leftOutByCap,
          tooLarge: c.tooLarge, failedReads: c.failedReads, truncatedTree: c.truncatedTree, ...(c.notRead ? { notRead: c.notRead } : {}),
        }
      : {}),
    ...(outcome.checks ? { checks: outcome.checks } : {}),
  };
}

export const NOT_SCANNED = (status: GithubScanOutcome["status"]): GithubScanOutcome => ({ findings: [], status, filesRead: 0 });
