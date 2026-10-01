/**
 * Black-box HTTP security scanner.
 *
 * Stage 1 (this file): fetches the target, checks headers, cookies, CORS and the
 * page, then runs the probe stage and the active API stage (scanner<Part>.ts).
 * Stage 2 (worker.ts): SSL Labs TLS assessment, in parallel.
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
import {
  sessionLostFinding, interceptedFinding, activeProbesSkippedFinding, splitInterceptedFindings, withheldEntry,
  markInterceptedTestsNotRun,
  platformGateFinding, rootErrorFinding, landedElsewhereFinding, type WithheldFinding,
} from "./scannerCoverage";
import { activeProbesStillAllowed } from "./activeScopeGuard";
import { detectChallengePage } from "./challengePage.js";
import { detectPlatformGate, landedElsewhere } from "./platformGate";
import { runWithScanHttp, scanFetch, scanFetchOrThrow, sessionWasLost } from "./http";
import { TestLedger, foundNames, type TestRecord } from "./testLedger";
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
  let renderRejected: string | undefined;
  if (isSpa(html)) {
    const rendered = await renderPage(finalUrl).catch(() => null);
    // The browser can be answered differently from the plain fetch: a proxy error page, or a bot
    // challenge served only to headless Chrome. Analysing that page would replace the site's own
    // content, silently dropping every finding that reads it, so a render that failed where the
    // plain fetch did not is set aside and said so.
    // A challenge can also come back as HTTP 200 (Cloudflare's managed challenge to some clients,
    // Vercel's checkpoint), so the rendered page is checked for one as well as for its status.
    const renderedChallenge = rendered ? detectChallengePage(rendered.status, rendered.html, rendered.headers) : null;
    const initialChallenge = detectChallengePage(initial.status, html, rawHeaders);
    if (rendered && rendered.status >= 400 && rendered.status !== initial.status) {
      renderRejected = `the headless browser was answered with HTTP ${rendered.status} where the plain request got HTTP ${initial.status}`;
    } else if (rendered && renderedChallenge?.isChallenge && !initialChallenge.isChallenge) {
      renderRejected = `the headless browser was shown a bot-protection challenge (${renderedChallenge.signal}) that the plain request was not`;
    } else if (rendered) {
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
  // No grade here: nothing in this scan measures TLS quality. worker.ts sets it
  // only from a completed SSL Labs assessment; null means "not assessed".
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
    setCookies: initial.setCookies ?? [],
    status: initial.status,
    requestedUrl: targetUrl,
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

  if (renderRejected) {
    vulnerabilities.push(vuln({
      name: "Browser Rendering Was Not Used",
      severity: "info",
      category: "Scan Coverage",
      description:
        "This page looks like a JavaScript app, so the scan tried to load it in a headless browser, but " +
        `${renderRejected}. The scan used the page as the plain request received it instead. This is not a finding about your site. ` +
        "Anything that only appears after the page's scripts run (bundled secrets, calls the page makes at runtime) may not have been seen, so re-run before treating a clean result there as meaningful.",
      evidence: renderRejected,
      solution: "If a bot-protection rule treats headless browsers differently, allow the scanner's User-Agent, then re-run the scan.",
      confidence: 100,
    }));
  }

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
  const withheld: WithheldFinding[] = [];
  const rateLimitDeduped = hasBehaviouralRateLimitFinding
    ? vulnerabilities.filter((v) => {
        if (v.name !== "Rate Limiting Not Advertised in Response Headers") return true;
        withheld.push(withheldEntry(v, "covered by the rate-limit test that sent real requests, which is reported instead"));
        return false;
      })
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
  const { kept: deduped, dropped } = splitInterceptedFindings(rateLimitDeduped, intercepted);
  const droppedReason = challengeVerdict.isChallenge
    ? `read from ${challengeVerdict.vendor ? `${challengeVerdict.vendor}'s` : "a"} bot-protection page, not from this site`
    : gateVerdict?.kind === "sign-in wall"
      ? `read from ${gateVerdict.vendor ?? "a"} sign-in page, not from the app`
      : `read from ${gateVerdict?.vendor ?? "the hosting platform"}'s own page, not from the app`;
  for (const v of dropped) withheld.push(withheldEntry(v, droppedReason));
  if (intercepted) {
    markInterceptedTestsNotRun(
      ledger.records,
      challengeVerdict.isChallenge
        ? "a bot-protection page answered instead of the site"
        : gateVerdict?.kind === "sign-in wall"
          ? "a sign-in page answered instead of the app"
          : "the hosting platform answered instead of the app",
    );
  }

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
