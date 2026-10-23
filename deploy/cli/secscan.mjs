#!/usr/bin/env node
/**
 * SecScan command line: scan a URL from a terminal or CI job and decide whether
 * the build passes.
 *
 *   SECSCAN_TOKEN=ssk_... secscan scan https://staging.example.com --fail-on high --sarif secscan.sarif
 *
 * Needs Node 18 or later and nothing else. Talks to the REST API (secscan.us/api/v1)
 * with a token whose scope is "api" (Settings → API).
 *
 * Exit codes, so a pipeline can tell a finding from a fault:
 *   0  the scan finished and the build passes
 *   1  the scan finished and the policy failed (a finding at or above --fail-on, or a grade worse than --min-grade)
 *   2  bad usage, or the scan failed or timed out
 *   3  the token was refused, or the API could not be reached
 *
 * It always prints how many tests were skipped. A grade with skipped tests says nothing
 * about the skipped areas; a build that passes on a passive-only scan should say so.
 */

export const EXIT = { ok: 0, policy: 1, scan: 2, api: 3 };
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const GRADES = ["A", "B", "C", "D", "F"];
const DEFAULT_API = "https://secscan.us/api/v1";

/** Parse argv (without node and script). Returns { error } instead of throwing, so tests can read it. */
export function parseArgs(argv) {
  const opts = { command: null, url: null, api: process.env.SECSCAN_API || DEFAULT_API, token: process.env.SECSCAN_TOKEN || null, failOn: "high", minGrade: null, sarif: null, json: null, timeout: 300, help: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value`);
      return v;
    };
    try {
      if (a === "--help" || a === "-h") opts.help = true;
      else if (a === "--token") opts.token = need();
      else if (a === "--api") opts.api = need().replace(/\/+$/, "");
      else if (a === "--fail-on") opts.failOn = need().toLowerCase();
      else if (a === "--min-grade") opts.minGrade = need().toUpperCase();
      else if (a === "--sarif") opts.sarif = need();
      else if (a === "--json") opts.json = need();
      else if (a === "--timeout") opts.timeout = Number(need());
      else if (a.startsWith("--")) return { error: `Unknown option ${a}` };
      else rest.push(a);
    } catch (e) {
      return { error: e.message };
    }
  }
  [opts.command, opts.url] = rest;
  if (opts.help) return { opts };
  if (opts.command !== "scan") return { error: "Usage: secscan scan <url> [options]. Try --help." };
  if (!opts.url) return { error: "Give the URL to scan: secscan scan https://example.com" };
  if (opts.failOn !== "none" && !SEVERITIES.includes(opts.failOn)) return { error: `--fail-on must be one of ${SEVERITIES.join(", ")}, none` };
  if (opts.minGrade && !GRADES.includes(opts.minGrade)) return { error: `--min-grade must be one of ${GRADES.join(", ")}` };
  if (!Number.isFinite(opts.timeout) || opts.timeout < 10) return { error: "--timeout is in seconds, at least 10" };
  if (!opts.token) return { error: "No token. Pass --token or set SECSCAN_TOKEN (create one at Settings → API)." };
  return { opts };
}

/** Findings at or above a severity, from the summary's counts. */
export function countAtOrAbove(findings, severity) {
  if (!findings || severity === "none") return 0;
  const cut = SEVERITIES.indexOf(severity);
  return SEVERITIES.slice(0, cut + 1).reduce((n, s) => n + (findings[s] ?? 0), 0);
}

/** Why the policy failed, or null if it passed. A missing grade never fails a --min-grade: it is reported, not guessed. */
export function policyFailure(summary, { failOn, minGrade }) {
  const reasons = [];
  const n = countAtOrAbove(summary.findings, failOn);
  if (n > 0) reasons.push(`${n} finding${n === 1 ? "" : "s"} at ${failOn} or worse`);
  if (minGrade && summary.grade && GRADES.includes(summary.grade) && GRADES.indexOf(summary.grade) > GRADES.indexOf(minGrade)) {
    reasons.push(`grade ${summary.grade} is worse than ${minGrade}`);
  }
  return reasons.length ? reasons.join("; ") : null;
}

export function formatSummary(scan) {
  const f = scan.findings;
  const lines = [`SecScan: ${scan.url}`, `  Grade ${scan.grade ?? "n/a"}${scan.riskScore != null ? `, risk ${scan.riskScore}/100` : ""}`];
  if (f) lines.push(`  Findings: ${f.total} (${SEVERITIES.map((s) => `${f[s] ?? 0} ${s}`).join(", ")})`);
  const c = scan.coverage;
  if (c) {
    lines.push(`  Tests: ${c.ran} ran, ${c.skipped} skipped, ${c.failed} failed`);
    if (c.skipped > 0) lines.push("  Note: skipped tests were NOT checked. Verify your domain (Settings → Domains) to run the active ones.");
  }
  if (scan.links?.web) lines.push(`  Report: ${scan.links.web}`);
  return lines.join("\n");
}

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call(opts, path, init = {}) {
  let res;
  try {
    res = await fetch(opts.api + path, { ...init, headers: { authorization: `Bearer ${opts.token}`, "content-type": "application/json", ...(init.headers ?? {}) } });
  } catch (e) {
    throw new ApiError(0, "unreachable", `Could not reach ${opts.api}: ${e.message}`);
  }
  const text = await res.text();
  if (!res.ok) {
    let err = {};
    try { err = JSON.parse(text).error ?? {}; } catch { /* not JSON */ }
    throw new ApiError(res.status, err.code ?? "error", err.message ?? `HTTP ${res.status}`);
  }
  return { text, json: () => JSON.parse(text) };
}

export async function run(argv, { log = console.log, err = console.error, write = null } = {}) {
  const parsed = parseArgs(argv);
  if (parsed.error) { err(parsed.error); return EXIT.scan; }
  const { opts } = parsed;
  if (opts.help) { log(HELP); return EXIT.ok; }
  const save = write ?? (await import("node:fs")).writeFileSync;

  try {
    const started = (await call(opts, "/scans", { method: "POST", body: JSON.stringify({ url: opts.url }) })).json();
    log(`Scan ${started.id} queued for ${opts.url}`);

    const deadline = Date.now() + opts.timeout * 1000;
    let scan;
    do {
      scan = (await call(opts, `/scans/${started.id}?wait=60`)).json();
    } while (scan.status !== "complete" && scan.status !== "failed" && Date.now() < deadline);

    if (scan.status === "failed") { err(`The scan failed: ${scan.error ?? "unknown error"}`); return EXIT.scan; }
    if (scan.status !== "complete") { err(`Timed out after ${opts.timeout}s; the scan is still ${scan.status}. It keeps running: ${opts.api}/scans/${started.id}`); return EXIT.scan; }

    log(formatSummary(scan));
    if (opts.json) save(opts.json, (await call(opts, `/scans/${started.id}/report`)).text);
    if (opts.sarif) {
      save(opts.sarif, (await call(opts, `/scans/${started.id}/sarif`)).text);
      log(`  SARIF written to ${opts.sarif}`);
    }

    const failure = policyFailure(scan, opts);
    if (failure) { err(`FAIL: ${failure}`); return EXIT.policy; }
    log("PASS");
    return EXIT.ok;
  } catch (e) {
    if (e instanceof ApiError) {
      err(e.status === 401 ? `Token refused: ${e.message}` : e.message);
      return e.status === 401 || e.code === "unreachable" ? EXIT.api : EXIT.scan;
    }
    err(`Unexpected error: ${e.message}`);
    return EXIT.scan;
  }
}

const HELP = `secscan scan <url> [options]

  --token <t>       API token (or SECSCAN_TOKEN). Scope: API.
  --fail-on <s>     Fail at this severity or worse: critical, high (default), medium, low, info, none
  --min-grade <g>   Also fail if the grade is worse than this: A, B, C, D, F
  --sarif <file>    Write SARIF 2.1.0 (for GitHub code scanning)
  --json <file>     Write the full report as JSON
  --timeout <s>     Give up waiting after this many seconds (default 300). The scan keeps running.
  --api <url>       API base (default ${DEFAULT_API})

Exit codes: 0 pass, 1 policy failed, 2 usage error or scan failed/timed out, 3 token refused or API unreachable.`;

// Run only when executed directly, so tests can import the functions above.
import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await run(process.argv.slice(2));
}
