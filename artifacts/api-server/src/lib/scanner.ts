/**
 * Black-box HTTP security scanner.
 *
 * Stage 1 (this file): Fetches the target URL, analyses response headers,
 * cookies, TLS, CORS, and page content — produces an initial vulnerability list.
 *
 * Stage 2 (parallel, via worker.ts): SSL Labs TLS assessment.
 *
 * Stage 3 (parallel probes): Active HTTP probes via probes.ts,
 * DNS security checks via dnsChecks.ts, and JavaScript secret scanning
 * via jsScanner.ts — all run concurrently with stage 2.
 */

import { vuln, headerVal, type PageContext, type ScanVulnerability, type ScanResult, type RunScanAuth, type RunScanExtras } from "./scannerTypes";
import { runProbeStage } from "./scannerProbeStage";
import { runActiveApiStage } from "./scannerActiveStage";
import { transportFindings } from "./scannerTransportChecks";
import { cspFindings } from "./scannerCspChecks";
import { headerFindings } from "./scannerHeaderChecks";
import { pageFindings } from "./scannerPageChecks";
import { analyzeCookies } from "./scannerCookies";
import { technologiesWithVersions } from "./scannerTech";
import { sessionLostFinding, interceptedFinding, activeProbesSkippedFinding, withholdInterceptedFindings } from "./scannerCoverage";
import { activeProbesStillAllowed } from "./activeScopeGuard";
import { detectChallengePage } from "./challengePage.js";
import { runWithScanHttp, scanFetch, scanFetchOrThrow, sessionWasLost } from "./http";
import { TestLedger, type TestRecord } from "./testLedger";
import { runCrossAccountStep } from "./crossAccountStep";
import { autoEnrichConfidence } from "./scoring";
import { isSpa, renderPage } from "./browser";
import type { ObservedRequest } from "./apiRuntime";

export type { ScanVulnerability, ScanResult, RunScanAuth, RunScanExtras } from "./scannerTypes";
export { withholdInterceptedFindings } from "./scannerCoverage";
export { computeRiskScore, computeGrade, GRADE_INCOMPLETE, gradeForResult } from "./scannerGrade";

const FETCH_TIMEOUT_MS = 20_000;

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

  // The only request whose failure ends the scan, so it is the only one that
  // throws rather than returning null — the underlying reason is what the user
  // needs to see when a target is unreachable.
  let initial;
  try {
    initial = await scanFetchOrThrow(targetUrl, {
      timeoutMs: FETCH_TIMEOUT_MS,
      headers: {
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to reach target URL: ${msg}`);
  }

  let finalUrl = initial.finalUrl || targetUrl;
  let html = initial.body;

  // Keys arrive lowercased from the shared client. Every lookup already goes
  // through the case-insensitive helper above, so this is a no-op for callers.
  const rawHeaders: Record<string, string> = { ...initial.headers };

  // ── SPA detection + headless rendering ────────────────────────────────────
  // If the server returned a JS-shell SPA (empty <div id="root"> etc.), re-fetch
  // via headless browser so content analysis operates on the fully-rendered DOM.
  // HTTP security headers stay from the raw fetch above — they're identical.
  let renderedWithBrowser = false;
  let observedRequests: ObservedRequest[] = [];
  if (isSpa(html)) {
    const rendered = await renderPage(finalUrl).catch(() => null);
    if (rendered) {
      html = rendered.html;
      finalUrl = rendered.finalUrl || finalUrl;
      renderedWithBrowser = true;
      observedRequests = rendered.observed;
    }
  }

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
  // No grade is assigned here: nothing in this scan measures TLS quality, and a
  // hard-coded "A" would be shown as fact if SSL Labs times out. worker.ts sets
  // it only from a completed SSL Labs assessment; null means "not assessed".
  const tlsGrade: string | null = null;
  const server = headerVal(rawHeaders, "server") ?? null;

  const technologies = technologiesWithVersions(rawHeaders, html);

  const requestDurationMs = Date.now() - startedAt;
  const vulnerabilities: ScanVulnerability[] = [];

  const page: PageContext = { finalUrl, html, rawHeaders, isHttps };
  vulnerabilities.push(...(await transportFindings(page)));
  vulnerabilities.push(...cspFindings(page));
  vulnerabilities.push(...headerFindings(page));

  // ── Cookie analysis ───────────────────────────────────────────────────
  const setCookie = headerVal(rawHeaders, "set-cookie");
  vulnerabilities.push(...analyzeCookies(initial.setCookies ?? [], setCookie));

  vulnerabilities.push(...pageFindings(page));

  // Pages the crawler will visit. Was 20 for deep scans and 0 (no crawl) for
  // basic ones; with one tier there is one budget.
  const CRAWL_PAGE_BUDGET = 20;

  // Did the edge answer instead of the site? Decided once, up front, because
  // several checks downstream are only meaningful if the document is the
  // target's own.
  const challengeVerdict = detectChallengePage(initial.status, html, rawHeaders);

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
    challengeVerdict.isChallenge
      ? { group: "passive", name: "response headers and cookies", status: "skipped", findings: 0, durationMs: 0, reason: "a bot-protection page answered instead of the site" }
      : { group: "passive", name: "response headers and cookies", status: "ran", findings: vulnerabilities.filter((v) => v.category !== "Scan Coverage").length, durationMs: 0 },
  );

  const probes = await runProbeStage({
    finalUrl, html, rawHeaders, tier, allowActiveProbes, ledger,
    setCookies: initial.setCookies ?? [],
    status: initial.status,
    crawlPageBudget: CRAWL_PAGE_BUDGET,
    ...(extra?.githubRepoUrl ? { githubRepoUrl: extra.githubRepoUrl } : {}),
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

  if (unrunFamilies.length > 0) {
    vulnerabilities.push(vuln({
      name: `${unrunFamilies.length} check group${unrunFamilies.length > 1 ? "s" : ""} could not be completed`,
      severity: "info",
      category: "Scan Coverage",
      description:
        `${unrunFamilies.length} group${unrunFamilies.length > 1 ? "s" : ""} of checks failed to run on this scan — a network error, a timeout, or an internal fault. ` +
        `This is not a finding about your site, and it does not mean anything is wrong with it. It is here because the alternative is worse: ` +
        `a check group that dies silently returns nothing, which looks exactly like a check group that ran and found nothing. ` +
        `Anything those groups would have caught is simply unknown for this scan, so re-run it before treating a clean result in these areas as meaningful.`,
      evidence: `Not completed:\n${unrunFamilies.map((f) => `  • ${f}`).join("\n")}`,
      solution:
        "Re-run the scan. If the same group fails repeatedly, the target may be rate-limiting or blocking the scanner, or the check has a genuine fault worth reporting to us.",
      confidence: 100,
    }));
  }

  // Two rate-limit checks can fire on one scan: a header heuristic in
  // probes.ts, and the behavioural burst in apiProbe.ts. When both appear they
  // describe the same problem, and the behavioural one has actually
  // demonstrated it — the header check itself says infrastructure often
  // throttles without advertising it. Keep the evidence, drop the inference.
  const hasBehaviouralRateLimitFinding = vulnerabilities.some(
    (v) => v.name === "No Rate Limiting Observed on Sensitive API Endpoints",
  );
  const rateLimitDeduped = hasBehaviouralRateLimitFinding
    ? vulnerabilities.filter((v) => v.name !== "Rate Limiting Not Advertised in Response Headers")
    : vulnerabilities;

  // When an edge answered instead of the origin, every check that read the
  // response body or its headers describes the challenge page. Naming those
  // findings as untrusted in a Scan Coverage note was not enough: the report
  // still said "etsy.com is missing Content-Security-Policy and serves a
  // wildcard CORS policy", which is a statement about Cloudflare's
  // interstitial and false about Etsy. Twelve of eighteen findings on that
  // scan came from a page Etsy did not serve.
  //
  // This is an allowlist rather than a denylist on purpose. The question is
  // not "which findings look content-derived" but "which sources did not read
  // the intercepted response at all" — DNS, mail transport and the scan's own
  // coverage notes. Anything else is dropped, because over-suppressing behind
  // an aggressive WAF costs a finding, while under-suppressing attributes
  // another company's error page to the customer.
  const deduped = withholdInterceptedFindings(rateLimitDeduped, challengeVerdict.isChallenge);

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
      ],
      technologies,
    ),
    requestDurationMs,
    rawHeaders,
    pagesScanned: crawlResult.pagesVisited,
    probedNotFound: crawlResult.probedNotFound,
    renderedWithBrowser,
    intercepted: challengeVerdict.isChallenge,
    tests: ledger.records,
  };
}
