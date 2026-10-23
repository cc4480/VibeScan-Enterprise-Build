/**
 * The last pass over a scan's findings: drop the rate-limit inference when a real burst test covers it, and, when an
 * edge or platform page answered instead of the app, withhold everything that was read from that page.
 */
import type { ScanVulnerability } from "./scannerTypes";
import type { TestLedger } from "./testLedger";
import { splitInterceptedFindings, withheldEntry, markInterceptedTestsNotRun, type WithheldFinding } from "./scannerCoverage";
import type { detectChallengePage } from "./challengePage.js";
import type { detectPlatformGate } from "./platformGate";

export function settleFindings(input: {
  vulnerabilities: ScanVulnerability[];
  intercepted: boolean;
  challengeVerdict: ReturnType<typeof detectChallengePage>;
  gateVerdict: ReturnType<typeof detectPlatformGate> | null;
  ledger: TestLedger;
}): { deduped: ScanVulnerability[]; withheld: WithheldFinding[] } {
  const { vulnerabilities, intercepted, challengeVerdict, gateVerdict, ledger } = input;
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

  return { deduped, withheld };
}
