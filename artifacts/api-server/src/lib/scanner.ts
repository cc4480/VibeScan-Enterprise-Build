/**
 * Black-box HTTP security scanner.
 *
 * Stage 1 (this file): fetches the target, checks headers, cookies, CORS and the
 * page, then runs the probe stage and the active API stage (scanner<Part>.ts).
 * Stage 2 (worker.ts): SSL Labs TLS assessment, in parallel.
 */

import { headerVal, type PageContext, type ScanVulnerability, type ScanResult, type RunScanAuth, type RunScanExtras } from "./scannerTypes";
import { runProbeStage } from "./scannerProbeStage";
import { loadStartPage } from "./scannerStartPage";
import { coverageNotes } from "./scannerCoverageNotes";
import { settleFindings } from "./scannerSettle";
import { runActiveApiStage } from "./scannerActiveStage";
import { transportFindings } from "./scannerTransportChecks";
import { cspFindings } from "./scannerCspChecks";
import { headerFindings } from "./scannerHeaderChecks";
import { pageFindings } from "./scannerPageChecks";
import { analyzeCookies } from "./scannerCookies";
import { technologiesWithVersions } from "./scannerTech";
import {
  sessionLostFinding, interceptedFinding, activeProbesSkippedFinding, capFindingsReadFromErrorPage,
  platformGateFinding, rootErrorFinding, landedElsewhereFinding,
} from "./scannerCoverage";
import { activeProbesStillAllowed } from "./activeScopeGuard";
import { detectChallengePage } from "./challengePage.js";
import { detectPlatformGate, landedElsewhere } from "./platformGate";
import { runWithScanHttp, sessionWasLost } from "./http";
import { TestLedger, foundNames, type TestRecord } from "./testLedger";
import { runCrossAccountStep } from "./crossAccountStep";
import { autoEnrichConfidence } from "./scoring";

export type { ScanVulnerability, ScanResult, RunScanAuth, RunScanExtras } from "./scannerTypes";
export { withholdInterceptedFindings } from "./scannerCoverage";
export { computeRiskScore, computeGrade, GRADE_INCOMPLETE, gradeForResult } from "./scannerGrade";

/**
 * Establishes the per-scan HTTP context (see lib/http.ts) and runs the scan
 * inside it, so every probe below this call shares one client, one User-Agent,
 * and one place where credentials are scoped to the target host.
 *
 * Split from the body only to avoid indenting the whole function.
 */
export async function runScan(
  targetUrl: string,
  tier: string,
  // Whether the caller established that this user may have offensive traffic
  // sent to this target. Required rather than defaulted: a scan entry point
  // that forgets to decide should fail to compile, not quietly attack someone.
  allowActiveProbes: boolean,
  auth?: RunScanAuth,
  // Correlates out-of-band callbacks back to this scan. Optional so a monitor
  // rescan or a test can call runScan without one; SSRF detection is simply
  // skipped when it and a callback host are both absent.
  scanId?: string | null,
  // Hears each test the moment it is recorded, for the live progress page.
  onTest?: (record: TestRecord) => void,
  extra?: RunScanExtras,
): Promise<ScanResult> {
  // Credentials go into the scan context, where lib/http.ts attaches them only
  // to in-scope requests and drops them on any redirect that leaves the target.
  return runWithScanHttp(
    {
      targetUrl,
      ...(extra?.signal ? { signal: extra.signal } : {}),
      ...(auth
        ? {
            credentials: auth.credentials,
            ...(auth.detectSignedOut ? { detectSignedOut: auth.detectSignedOut } : {}),
            ...(auth.onSessionLost ? { onSessionLost: auth.onSessionLost } : {}),
          }
        : {}),
    },
    () => runScanInner(targetUrl, tier, allowActiveProbes, auth, scanId ?? null, onTest, extra),
  );
}

async function runScanInner(
  targetUrl: string,
  tier: string,
  allowActiveProbes: boolean,
  auth?: RunScanAuth,
  scanId: string | null = null,
  onTest?: (record: TestRecord) => void,
  extra?: RunScanExtras,
): Promise<ScanResult> {
  const startedAt = Date.now();

  // The first request, and the headless render of it for a JavaScript app (scannerStartPage.ts).
  const { initial, finalUrl, html, rawHeaders, renderedWithBrowser, observedRequests, renderRejected } = await loadStartPage(targetUrl);

  // The ownership check was made on the host the requester typed. If the site sent us somewhere else,
  // the probes below would hit that other host, so active testing stops unless it is theirs too.
  let redirectedOffScope: string | undefined;
  if (allowActiveProbes) {
    const scope = await activeProbesStillAllowed(targetUrl, finalUrl, extra?.verifyHost);
    if (!scope.allowed) {
      allowActiveProbes = false;
      redirectedOffScope = scope.redirectedTo;
    }
  }

  const isHttps = finalUrl.startsWith("https://");
  // No grade here: nothing in this scan measures TLS quality. worker.ts sets it
  // only from a completed SSL Labs assessment; null means "not assessed".
  const tlsGrade: string | null = null;
  const server = headerVal(rawHeaders, "server") ?? null;

  const technologies = technologiesWithVersions(rawHeaders, html);

  const requestDurationMs = Date.now() - startedAt;
  const vulnerabilities: ScanVulnerability[] = [];

  const page: PageContext = { finalUrl, html, rawHeaders, isHttps };
  const setCookie = headerVal(rawHeaders, "set-cookie");
  // Everything the first response itself says: transport, CSP, headers, cookies, page content.
  const readFromStartPage = [
    ...(await transportFindings(page)),
    ...cspFindings(page),
    ...headerFindings(page),
    ...analyzeCookies(initial.setCookies ?? [], setCookie),
    ...pageFindings(page),
  ];
  // When that response was an error page (and not a refusal, which is withheld below as an
  // interception) it describes the error page, not the app: shown as information, not graded.
  vulnerabilities.push(...(initial.status >= 400 ? capFindingsReadFromErrorPage(readFromStartPage, initial.status) : readFromStartPage));

  // Pages the crawler will visit. Was 20 for deep scans and 0 (no crawl) for
  // basic ones; with one tier there is one budget.
  const CRAWL_PAGE_BUDGET = 20;

  // Did the edge answer instead of the site? Decided once, up front, because
  // several checks downstream are only meaningful if the document is the
  // target's own.
  const challengeVerdict = detectChallengePage(initial.status, html, rawHeaders);
  // Or a hosting platform or identity provider answered instead of the app: a sign-in wall in front
  // of the whole site, or the platform's "nothing running here" page. Same treatment as a challenge.
  const gateVerdict = challengeVerdict.isChallenge
    ? null
    : detectPlatformGate(targetUrl, finalUrl, initial.status, html, rawHeaders);
  const intercepted = challengeVerdict.isChallenge || gateVerdict?.isGate === true;

  // ── Run all parallel probes ───────────────────────────────────────────
  // All checks run concurrently — active HTTP probes, DNS checks, site crawl,
  // CVE lookup, JWT analysis, subdomain takeover, JS secret scanning and path
  // traversal.
  // Every test's outcome — ran, skipped (and why) or failed — for the per-test
  // log the worker writes and the coverage line in the report. See testLedger.ts.
  const ledger = new TestLedger(onTest);
  // The header, cookie and CSP checks above ran on the first response before the
  // ledger existed. Record them now, so they are counted like every other test, and
  // never as run when a bot-protection page answered instead of the site (their
  // findings are withheld below, so nothing was actually checked).
  ledger.records.push(
    intercepted
      ? {
          group: "passive", name: "response headers and cookies", status: "skipped", findings: 0, durationMs: 0,
          reason: challengeVerdict.isChallenge
            ? "a bot-protection page answered instead of the site"
            : gateVerdict?.kind === "sign-in wall"
              ? "a sign-in page answered instead of the app"
              : "the hosting platform answered instead of the app",
        }
      : (() => {
          const found = vulnerabilities.filter((v) => v.category !== "Scan Coverage");
          return {
            group: "passive", name: "response headers and cookies", status: "ran" as const, findings: found.length, durationMs: 0,
            ...(found.length > 0 ? { found: foundNames(found) } : {}),
          };
        })(),
  );

  const probes = await runProbeStage({
    finalUrl, html, rawHeaders, tier, allowActiveProbes, ledger,
    signedIn: Boolean(auth?.credentials),
    setCookies: initial.setCookies ?? [],
    status: initial.status,
    requestedUrl: targetUrl,
    // Not the rendered DOM: see ProbeStageInput.authoredHtml.
    authoredHtml: initial.body,
    crawlPageBudget: CRAWL_PAGE_BUDGET,
    ...(extra?.githubRepoUrl ? { githubRepoUrl: extra.githubRepoUrl } : {}),
    ...(extra?.githubAccessToken ? { githubAccessToken: extra.githubAccessToken } : {}),
  });
  const { crawlResult, unrunFamilies } = probes;
  vulnerabilities.push(...probes.vulnerabilities);

  vulnerabilities.push(...(await runActiveApiStage({
    finalUrl, html, observedRequests, allowActiveProbes, scanId, ledger, unrunFamilies,
    ...(auth ? { auth } : {}),
    ...(extra?.raceConditionTesting ? { raceConditionTesting: true } : {}),
  })));

  // ── A01: broken access control ─────────────────────────────────────────────
  // Runs last because it needs the crawl's output: the URLs the signed-in
  // account actually reached are the ones worth asking a second account for.
  // Requires both accounts — one identity cannot demonstrate an authorisation
  // boundary between users.
  //
  // When a primary account is signed in but no second one was supplied, the
  // step tries once to create a disposable one through the target's own public
  // signup form (autoSecondAccount.ts) — but only after checking that the probe
  // would have a record to use it on, and it says in the report when it created
  // one. The whole decision sequence lives in crossAccountStep.ts, where it is
  // tested; a probe that compared nothing is recorded as skipped, not as run.
  vulnerabilities.push(
    ...(await runCrossAccountStep({
      allowActiveProbes,
      allowAutoAccount: extra?.autoSecondAccount === true,
      primary: auth?.credentials,
      secondary: auth?.secondary,
      finalUrl,
      pagesVisited: crawlResult.pagesVisited,
      ledger,
      unrunFamilies,
    })),
  );

  vulnerabilities.push(...coverageNotes(renderRejected, unrunFamilies));

  const { deduped, withheld } = settleFindings({ vulnerabilities, intercepted, challengeVerdict, gateVerdict, ledger });

  // Not intercepted, but the reader still needs to know what the findings were read from.
  const contextNotes: ScanVulnerability[] = [];
  if (!intercepted) {
    if (initial.status >= 400) contextNotes.push(rootErrorFinding(initial.status, finalUrl));
    if (landedElsewhere(targetUrl, finalUrl)) contextNotes.push(landedElsewhereFinding(targetUrl, finalUrl));
  }

  return {
    targetUrl,
    finalUrl,
    statusCode: initial.status,
    server,
    tlsGrade,
    technologies,
    vulnerabilities: autoEnrichConfidence(
      [
        ...deduped,
        ...(sessionWasLost() ? [sessionLostFinding()] : []),
        ...(allowActiveProbes ? [] : [activeProbesSkippedFinding(redirectedOffScope)]),
        ...(challengeVerdict.isChallenge
          ? [interceptedFinding(challengeVerdict.vendor, challengeVerdict.signal ?? "")]
          : []),
        ...(gateVerdict?.isGate && gateVerdict.kind
          ? [platformGateFinding(gateVerdict.kind, gateVerdict.vendor, gateVerdict.signal ?? "")]
          : []),
        ...contextNotes,
      ],
      technologies,
    ),
    requestDurationMs,
    rawHeaders,
    pagesScanned: crawlResult.pagesVisited,
    probedNotFound: crawlResult.probedNotFound,
    renderedWithBrowser,
    intercepted,
    ...(challengeVerdict.isChallenge
      ? { interception: { kind: "bot challenge" as const, vendor: challengeVerdict.vendor, signal: challengeVerdict.signal ?? "" } }
      : gateVerdict?.isGate && gateVerdict.kind
        ? { interception: { kind: gateVerdict.kind, vendor: gateVerdict.vendor, signal: gateVerdict.signal ?? "" } }
        : {}),
    withheld,
    tests: ledger.records,
  };
}
