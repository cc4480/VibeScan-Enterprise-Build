import type { Log } from "./workerTypes";
import { db, scansTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { decryptCredentials, toScanHttpCredentials } from "./scanCredentials";
import { GithubAppError, installationToken } from "./githubApp";
import { parseGithubRepoRef } from "./githubSourceProbe";

/** The sign-in a scan runs under: decrypted credentials, an optional second account, and how to renew a form login. */
export async function loadScanAuth(scanId: string, log: Log) {
  // Declared here so the re-probe later runs under the same credentials.
  let httpCredentials: Awaited<ReturnType<typeof toScanHttpCredentials>> = null;
  let reauthenticate: (() => Promise<Awaited<ReturnType<typeof toScanHttpCredentials>>>) | null = null;
  let secondaryCredentials: Awaited<ReturnType<typeof toScanHttpCredentials>> = null;
  // ── Credentials for an authenticated scan ────────────────────────────────
  // Loaded from the scan row rather than the job payload, decrypted here and
  // held only for this scan. A form login runs a real browser sign-in; if it
  // fails the scan continues unauthenticated rather than aborting, and says
  // so in the log.
  const [scanRow] = await db
    .select({
      blob: scansTable.credentialsEncrypted,
      secondBlob: scansTable.secondaryCredentialsEncrypted,
      githubRepoUrl: scansTable.githubRepoUrl,
      githubInstallationId: scansTable.githubInstallationId,
      autoSecondAccount: scansTable.autoSecondAccount,
    })
    .from(scansTable)
    .where(eq(scansTable.id, scanId));

  if (scanRow?.blob) {
    const stored = decryptCredentials(scanRow.blob);
    if (!stored) {
      log.warn("Stored credentials could not be decrypted — scanning unauthenticated");
    } else {
      httpCredentials = await toScanHttpCredentials(stored, log);
      log.info(
        { mode: stored.mode, authenticated: httpCredentials !== null },
        "Credentialed scan requested",
      );
      // Only a form login can be replayed. A pasted cookie or bearer token
      // has no renewal path, so its expiry is recorded but not recovered.
      // The second account only matters when the first one worked — access
      // control is a comparison, and there is nothing to compare against a
      // session that never authenticated.
      if (httpCredentials && scanRow.secondBlob) {
        const secondStored = decryptCredentials(scanRow.secondBlob);
        if (secondStored) {
          secondaryCredentials = await toScanHttpCredentials(secondStored, log);
          log.info(
            { enabled: secondaryCredentials !== null },
            "Access-control testing: second account session",
          );
        }
      }

      if (stored.mode === "form") {
        reauthenticate = async () => {
          log.warn("Session appears to have expired — signing in again");
          return toScanHttpCredentials(stored, log);
        };
      }
    }
  }

  // A private repository the owner shared through the GitHub App. The scan row carries only the installation id,
  // which scansCreate.ts set after checking the requester; the token is minted here for this one repository,
  // read-only, and held in memory for this scan. It is not stored and never logged. If it cannot be had, the
  // scan carries on reading what is public, and the report says the repository was not tested.
  let githubAccessToken: string | undefined;
  if (scanRow?.githubInstallationId && scanRow.githubRepoUrl) {
    const ref = parseGithubRepoRef(scanRow.githubRepoUrl);
    const installationId = Number(scanRow.githubInstallationId);
    if (ref && Number.isInteger(installationId)) {
      try {
        githubAccessToken = (await installationToken(installationId, ref.repo)).token;
        log.info({ via: "github-app" }, "Private repository access granted for this scan");
      } catch (err) {
        log.warn({ reason: err instanceof GithubAppError ? err.reason : "unknown" }, "No private repository access; reading public files only");
      }
    }
  }

  return { scanRow, httpCredentials, reauthenticate, secondaryCredentials, githubAccessToken };
}
