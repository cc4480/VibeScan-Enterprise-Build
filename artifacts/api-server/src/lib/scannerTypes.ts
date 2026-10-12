/**
 * Shared shapes of the black-box scanner: a finding, a scan result, and the
 * optional inputs to runScan. Kept apart from scanner.ts so the check modules
 * can import them without importing the scan driver.
 */

import { randomUUID } from "node:crypto";
import type { VerifyHost } from "./activeScopeGuard";
import type { ScanCredentials as ScanHttpCredentials } from "./http";
import type { TestRecord } from "./testLedger";
import type { WithheldFinding } from "./scannerCoverage";

export interface ScanVulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  evidence?: string | null;
  solution: string;
  cweId?: string | null;
  cvssScore?: number | null;
  wstgId?: string | null;
  /** Confidence score 0–100: how certain we are this is a real finding, not a false positive */
  confidence?: number | null;
}

export interface ScanResult {
  targetUrl: string;
  finalUrl: string;
  statusCode: number;
  server: string | null;
  tlsGrade: string | null;
  technologies: string[];
  vulnerabilities: ScanVulnerability[];
  requestDurationMs: number;
  rawHeaders: Record<string, string>;
  /** URLs of inner pages actually fetched during the deep crawl (excludes the root URL) */
  pagesScanned: string[];
  /** High-value probe paths that returned HTTP 404 during the crawl (see CrawlResult.probedNotFound) */
  probedNotFound: string[];
  /** True when the root page was rendered via headless browser (SPA detected) */
  renderedWithBrowser?: boolean;
  /**
   * True when a bot-protection layer answered instead of the origin, so every
   * content-derived check described the challenge page and was withheld. The
   * consumer must NOT grade such a scan: the surviving findings (DNS, email,
   * mail transport) are real, but the absence of everything else is an artefact
   * of not being let in, not evidence the site is clean. See interceptedFinding.
   */
  intercepted: boolean;
  /**
   * What answered instead of the app, when intercepted: a bot challenge, a sign-in wall in front of
   * the whole site, or a platform page saying no app is running. Absent on scans that reached the app.
   */
  interception?: { kind: "bot challenge" | "sign-in wall" | "app not running"; vendor: string | null; signal: string };
  /**
   * Findings the scan produced and chose not to report, each with the reason. Listed in the report
   * so nothing is dropped silently (see scannerCoverage.ts).
   */
  withheld?: WithheldFinding[];
  /**
   * Every test the scan was meant to run and its outcome — ran, skipped (with
   * the reason) or failed — with its time and finding count. See testLedger.ts.
   * Optional because early-exit paths (unreachable target) run no tests.
   */
  tests?: TestRecord[];
}

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export function headerVal(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  const key = Object.keys(headers).find((k) => k.toLowerCase() === lower);
  return key ? headers[key] : undefined;
}

export interface RunScanAuth {
  credentials: ScanHttpCredentials;
  /**
   * A second account the user supplied. The comparison needs two identities
   * that own different data, and a user-supplied one is a statement that they do.
   * When there is none, an active scan of a verified domain may create a
   * disposable one through the target's own signup form (crossAccountStep.ts),
   * and reports that it did.
   */
  secondary?: ScanHttpCredentials;
  /** Recognises a signed-out response. */
  detectSignedOut?: (body: string, finalUrl: string, requestedUrl: string) => boolean;
  /** Signs back in when the session expires mid-scan. */
  onSessionLost?: () => Promise<ScanHttpCredentials | null>;
}

/**
 * Optional, independent extras that do not belong on `RunScanAuth` — that
 * object only exists at all when the scan is authenticated against the
 * target, and both of these are meaningful on an unauthenticated scan too.
 * A new trailing optional parameter, so every existing call site (which
 * passes none of this) is entirely unaffected.
 */
export interface RunScanExtras {
  /** Aborted when the worker gives up on the scan; every scanFetch then fails at once. */
  signal?: AbortSignal;
  /**
   * A public GitHub repository ("owner/repo" or a full URL) to additionally
   * scan for hardcoded secrets in source, alongside the live-URL scan. See
   * githubSourceProbe.ts. Omitted entirely for most scans; this is opt-in
   * per scan, supplied by the user.
   */
  githubRepoUrl?: string;
  /** GitHub App installation token for a private repository the owner connected. In memory only; never stored. */
  githubAccessToken?: string;
  /**
   * Explicit, scan-by-scan opt-in for the active race-condition probe (see
   * raceConditionProbe.ts for why this is not on by default). Defaults to
   * false/omitted, meaning the probe never runs unless a caller sets this.
   */
  raceConditionTesting?: boolean;
  /**
   * Explicit, scan-by-scan opt-in for creating a disposable second account through the target's public
   * signup form, so the cross-account (IDOR) test can run with only one login supplied. Off unless a
   * caller sets it, because it submits a form on the customer's system (see autoSecondAccount.ts).
   */
  autoSecondAccount?: boolean;
  /**
   * Says whether the requester has verified the host of a URL. Used when the target redirects to a
   * different host: active probing goes on only if that host is one they verified (see
   * activeScopeGuard.ts). Without it, any redirect to another host makes the scan passive.
   */
  verifyHost?: VerifyHost;
}

/** What the first-response checks read: the page as fetched, after any browser rendering. */
export interface PageContext {
  finalUrl: string;
  html: string;
  rawHeaders: Record<string, string>;
  isHttps: boolean;
}
