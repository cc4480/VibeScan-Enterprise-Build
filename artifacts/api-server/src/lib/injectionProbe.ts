/**
 * A03: Injection — active reflected-XSS and error-based SQL injection probing.
 *
 * Strategy:
 *  1. Collect candidate (path, param) pairs from the target URL's own query
 *     string, in-page <form> input names, in-page link query params, and a
 *     small set of common injectable param names against the base path.
 *  2. Reflected XSS: inject a random canary wrapped in HTML metacharacters and
 *     confirm ONLY when the metacharacters reflect back UNENCODED — i.e. the
 *     literal "<canary>" appears in the response. If the app HTML-encodes them
 *     (&lt;canary&gt;) there is no finding.
 *  3. Error-based SQLi: fetch a benign baseline, then the same param with a
 *     trailing quote, and confirm ONLY when a distinctive SQL error signature
 *     appears in the injected response that was NOT already in the baseline.
 *
 * Both techniques observe behaviour rather than pattern-matching, so confirmed
 * findings are high-confidence. Detection only — no payload attempts to execute
 * script or extract data; the SQLi probe just trips a syntax error.
 *
 * Only runs on deep-tier scans (active requests). Non-fatal — all errors → [].
 */

import { randomUUID, randomBytes } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";
import { isDestructiveUrl } from "./destructive";

const TIMEOUT_MS = 7_000;
const MAX_CASES = 20;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// Common param names worth testing when the target exposes no query string of
// its own — search/lookup endpoints are the classic reflected-XSS / SQLi surface.
const COMMON_PARAMS = ["q", "s", "search", "query", "keyword", "term", "id", "name", "category"];

// Distinctive SQL error signatures. Each is specific enough to a database engine
// that its appearance in a response — absent from the benign baseline — is strong
// evidence the injected quote reached a SQL parser. Kept deliberately narrow to
// avoid matching the words "sql"/"database" in ordinary page copy.
export const SQL_ERROR_SIGNATURES: RegExp[] = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysqli?_/i,
  /mysql_fetch_(?:array|assoc|row|object)/i,
  /supplied argument is not a valid mysql/i,
  /check the manual that corresponds to your (?:mysql|mariadb) server version/i,
  /unterminated quoted string at or near/i,
  /syntax error at or near/i,
  /pg_query\(\)/i,
  /PSQLException/,
  /unclosed quotation mark after the character string/i,
  /microsoft ole db provider for sql server/i,
  /system\.data\.sqlclient\.sqlexception/i,
  /odbc sql server driver/i,
  /ORA-\d{5}/,
  /quoted string not properly terminated/i,
  /SQLite3?::|sqlite3\.operationalerror|SQLITE_ERROR/i,
  /unrecognized token:/i,
  /SQLSTATE\[/,
  /org\.hibernate\.exception/i,
];

interface Probed {
  status: number;
  body: string;
}

async function safeGet(url: string): Promise<Probed | null> {
  const res = await scanFetch(url, { timeoutMs: TIMEOUT_MS });
  return res ? { status: res.status, body: res.body } : null;
}

interface Case { path: string; param: string }

/** Collect (path, param) candidates from the URL, in-page forms/links, and common names. */
function collectCases(targetUrl: string, origin: string, targetPath: string, html: string): Case[] {
  const seen = new Set<string>();
  const cases: Case[] = [];
  const add = (path: string, param: string) => {
    if (!param) return;
    const key = `${path}::${param.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    cases.push({ path, param });
  };

  // 1. Params already on the target URL.
  try {
    for (const [k] of new URL(targetUrl).searchParams.entries()) add(targetPath, k);
  } catch { /* ignore */ }

  const sample = html.slice(0, 80_000);

  // 2. <form> input/select/textarea names (GET forms are the reflected surface).
  const formRx = /<(?:input|textarea|select)\b[^>]*\bname=["']([^"']+)["']/gi;
  let fm: RegExpExecArray | null;
  while ((fm = formRx.exec(sample)) !== null && cases.length < MAX_CASES) {
    add(targetPath, fm[1]!);
  }

  // 3. Query params from in-page links.
  const linkRx = /(?:href|src)=["']([^"'#]+\?[^"']+)["']/gi;
  let lm: RegExpExecArray | null;
  while ((lm = linkRx.exec(sample)) !== null && cases.length < MAX_CASES) {
    try {
      const u = new URL(lm[1]!, origin);
      for (const [k] of u.searchParams.entries()) add(u.pathname, k);
    } catch { /* invalid */ }
  }

  // 4. Common param names against the base path, to cover search endpoints that
  //    expose no parameter in the initial HTML.
  for (const p of COMMON_PARAMS) {
    if (cases.length >= MAX_CASES) break;
    add(targetPath, p);
  }

  return cases.slice(0, MAX_CASES);
}

export async function runInjectionProbes(
  targetUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  let origin: string;
  let targetPath: string;
  try {
    const parsed = new URL(targetUrl);
    origin = parsed.origin;
    targetPath = parsed.pathname;
  } catch {
    return [];
  }

  const cases = collectCases(targetUrl, origin, targetPath, html);
  if (cases.length === 0) return [];

  const xssParams: string[] = [];
  const sqliFindings: Array<{ param: string; path: string; signature: string }> = [];

  for (const { path, param } of cases) {
    // Never fire payloads at an endpoint whose name says it performs an action.
    // Unauthenticated this mostly bounced; with a session attached, injecting
    // into /account/delete does the deleting.
    if (isDestructiveUrl(`${origin}${path}`)) continue;

    // ── Reflected XSS: unique canary wrapped in HTML metacharacters ───────────
    // A random token means an accidental match is astronomically unlikely, and
    // requiring the literal "<token>" (angle brackets intact) confirms the input
    // is reflected into the HTML body WITHOUT output encoding.
    const token = "sq" + randomBytes(5).toString("hex");
    const xssPayload = `"'><${token}>`;
    const xssUrl = new URL(`${origin}${path}`);
    xssUrl.searchParams.set(param, xssPayload);
    const xssRes = await safeGet(xssUrl.toString());
    if (xssRes && xssRes.body.includes(`<${token}>`)) {
      if (!xssParams.includes(param)) xssParams.push(param);
    }

    // ── Error-based SQLi: baseline vs. quote-injected, signature diff ─────────
    const marker = "sq" + randomBytes(4).toString("hex");
    const baseUrl = new URL(`${origin}${path}`);
    baseUrl.searchParams.set(param, marker);
    const injUrl = new URL(`${origin}${path}`);
    injUrl.searchParams.set(param, `${marker}'`);

    const [baseRes, injRes] = await Promise.all([
      safeGet(baseUrl.toString()),
      safeGet(injUrl.toString()),
    ]);
    if (baseRes && injRes) {
      for (const sig of SQL_ERROR_SIGNATURES) {
        if (sig.test(injRes.body) && !sig.test(baseRes.body)) {
          sqliFindings.push({ param, path, signature: sig.source.slice(0, 60) });
          break;
        }
      }
    }
  }

  const findings: ScanVulnerability[] = [];

  if (xssParams.length > 0) {
    const list = xssParams.join(", ");
    const plural = xssParams.length > 1;
    findings.push(vuln({
      name: "Reflected Cross-Site Scripting (XSS)",
      severity: "high",
      category: "Injection",
      description: `${xssParams.length} parameter${plural ? "s" : ""} (${list}) reflect${plural ? "" : "s"} input into the HTML response without output encoding — the injected '<...>' markers came back with their angle brackets intact. An attacker can craft a link that runs arbitrary JavaScript in a victim's browser, stealing session tokens or performing actions as the victim.`,
      evidence: `Endpoint: ${targetPath}?${xssParams[0]}=<payload>\nInjected: "'><random-token>\nResponse reflected the token unencoded (angle brackets preserved), confirming an HTML-injection sink.`,
      solution:
        "Context-aware output encoding is the fix: HTML-encode user input before rendering it into the page (<, >, \", ', & → entities). Use your framework's auto-escaping (React/Vue/Angular escape by default — avoid dangerouslySetInnerHTML / v-html / bypassSecurityTrust). Add a strict Content-Security-Policy (script-src 'self') as defence in depth.",
      cweId: "CWE-79",
      cvssScore: 6.1,
      wstgId: "WSTG-INPV-01",
      confidence: 90,
    }));
  }

  if (sqliFindings.length > 0) {
    const params = [...new Set(sqliFindings.map((f) => f.param))];
    const list = params.join(", ");
    const plural = params.length > 1;
    findings.push(vuln({
      name: "SQL Injection (Error-Based)",
      severity: "critical",
      category: "Injection",
      description: `${params.length} parameter${plural ? "s" : ""} (${list}) triggered a database error when a single quote was appended to the value, while the un-quoted baseline did not. This means user input is concatenated into a SQL query unsafely — an attacker can read, modify, or destroy database contents.`,
      evidence: `Endpoint: ${sqliFindings[0]!.path}?${sqliFindings[0]!.param}=<value>'\nA SQL error signature appeared only when the quote was injected, matching: /${sqliFindings[0]!.signature}/`,
      solution:
        "Use parameterised queries / prepared statements (bound parameters) for every database call — never build SQL by string concatenation. Use your ORM's parameter binding. As defence in depth, validate/allowlist input types and run the database account with least privilege. Also disable verbose SQL error messages in production.",
      cweId: "CWE-89",
      cvssScore: 9.8,
      wstgId: "WSTG-INPV-05",
      confidence: 90,
    }));
  }

  return findings;
}
