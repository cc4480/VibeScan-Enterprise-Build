/**
 * The job for a scan of a GitHub repository alone (lib/repoOnlyScan.ts): read the repository, record what was read, and
 * save a report. None of the site work runs, because there is no site: no page fetch, TLS handshake, reconnaissance,
 * probes or browser. A repository that could not be read fails the scan and gives the payment back, since a report that
 * says "nothing was read" is not something to charge for.
 */
import { db, scansTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { TestLedger, SOURCE_TEST_NAME } from "./testLedger";
import type { ScanResult } from "./scanner";
import { parseGithubRepoRef, githubProbeOutcome } from "./githubSourceProbe";
import { scanRepository } from "./repoScan";
import { githubInstallationSource, publicGithubSource } from "./repoSource";
import { buildReport } from "./workerReport";
import { buildFallbackAnalysis } from "./fixPromptFallback";
import { detectAgentEnvironment } from "./deepseek";
import { createLiveProgress } from "./liveProgress";
import { progressRecord } from "./repoProgress";
import { persistReport, refundIfPaid } from "./workerPersist";
import type { Log } from "./workerTypes";

export interface RepoJobInput {
  scanId: string;
  userId: string;
  /** The repository's https://github.com/owner/repo address, which is also the scan's address. */
  targetUrl: string;
  tier: string;
  githubAccessToken: string | undefined;
  log: Log;
}

export async function processRepoOnlyJob(input: RepoJobInput): Promise<void> {
  const { scanId, userId, targetUrl, tier, githubAccessToken, log } = input;
  const startedAt = Date.now();
  const ref = parseGithubRepoRef(targetUrl);

  const fail = async (message: string): Promise<void> => {
    await db
      .update(scansTable)
      .set({ status: "failed", error: message, completedAt: new Date(), credentialsEncrypted: null, secondaryCredentialsEncrypted: null })
      .where(eq(scansTable.id, scanId));
    await refundIfPaid(scanId, log);
  };

  if (!ref) {
    await fail("That is not a GitHub repository address.");
    return;
  }

  // The steps of the read are shown on the progress page as they happen (and saved with the scan row, not the report).
  const live = createLiveProgress(scanId);
  const ledger = new TestLedger(live.add);
  let findings: ScanResult["vulnerabilities"];
  try {
    const source = githubAccessToken ? githubInstallationSource(ref, githubAccessToken) : publicGithubSource(ref);
    findings = await ledger.trackOutcome("passive", SOURCE_TEST_NAME, scanRepository(source, ref, { onProgress: (e) => ledger.progress(progressRecord(e)) }).then((o) => githubProbeOutcome(o, ref)));
  } catch (err) {
    log.error({ err }, "Repository scan failed");
    await live.finish();
    await fail(`GitHub could not be read just now: ${err instanceof Error ? err.message.slice(0, 160) : "unknown error"}. You were not charged; try again in a few minutes.`);
    return;
  }

  // Not read at all (private and not shared, or no such repository): nothing to report, so nothing to charge for.
  await live.finish();
  const record = ledger.records.find((r) => r.name === SOURCE_TEST_NAME);
  if (!record || record.status !== "ran") {
    await fail(
      `${record?.reason ?? "The repository could not be read"}. You were not charged.`,
    );
    return;
  }

  const scanResult: ScanResult = {
    targetUrl,
    finalUrl: targetUrl,
    statusCode: 200,
    server: null,
    tlsGrade: null,
    technologies: [],
    vulnerabilities: findings,
    requestDurationMs: Date.now() - startedAt,
    rawHeaders: {},
    pagesScanned: [],
    probedNotFound: [],
    intercepted: false,
    tests: ledger.records,
  };

  // The fix prompt is built from the findings themselves, with no AI call: a repository scan spends nothing beyond its scan.
  const repository = `${ref.owner}/${ref.repo}`;
  const aiAnalysis = buildFallbackAnalysis({
    targetUrl, vulnerabilities: findings, agent: detectAgentEnvironment([], targetUrl), tests: ledger.records, repository,
  });

  const { reportData, riskScore, grade, intercepted, severityCounts, executiveSummary } = await buildReport({
    scanResult, targetUrl, tests: ledger.records, reconRunResult: null, aiAnalysis, autoSuppressedCount: 0, repository,
  });

  await persistReport({
    scanId, userId, targetUrl, tier, verificationId: null, monitorSubscriptionId: null, scanResult, tests: ledger.records,
    reportData, riskScore, grade, intercepted, severityCounts, executiveSummary, log,
  });
}
