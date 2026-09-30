/** What a repository scan achieved, and why when it did not. */
import type { ProbeOutcome } from "./testLedger";
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
export function githubProbeOutcome(outcome: GithubScanOutcome): ProbeOutcome {
  if (outcome.status === "not_public_or_missing") {
    return {
      findings: [],
      notTested: "the repository is private or does not exist (only public repositories can be read)",
    };
  }
  const why = githubNotScannedReason(outcome.status);
  if (why) throw new Error(why);
  return { findings: outcome.findings };
}

export const NOT_SCANNED = (status: GithubScanOutcome["status"]): GithubScanOutcome => ({ findings: [], status, filesRead: 0 });
