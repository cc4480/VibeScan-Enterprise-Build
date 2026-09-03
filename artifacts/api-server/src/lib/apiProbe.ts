/**
 * Security testing against a discovered API surface.
 *
 * lib/apiSurface.ts recovers the endpoints; this decides what is safe to ask
 * them. Two checks, both aimed at the failures that dominate the OWASP API
 * Security Top 10:
 *
 *   1. Missing authentication — an endpoint that answers a caller with no
 *      session at all. On an API-first app this is where data actually leaks,
 *      and it is invisible to an HTML-shaped scan.
 *   2. SQL injection in API parameters — query, path, and JSON body fields the
 *      spec declares, which no HTML form ever exposes.
 *
 * ── Safety ──────────────────────────────────────────────────────────────────
 *
 * This runs against a live application belonging to a paying customer, so the
 * rule is: never send a request whose *success* would change their data.
 *
 *   - Only GET and HEAD are ever issued for auth coverage. A POST sent without
 *     a session to check whether it is rejected would perform the write if the
 *     answer is "no", which is exactly the case worth reporting — the test
 *     would cause the damage it is meant to warn about.
 *   - Body injection is restricted to read-shaped endpoints (search, query,
 *     filter, report, graphql). A POST /orders carrying a quote is an order.
 *   - The destructive-URL guard applies throughout.
 *
 * The cost is real and worth stating: write-endpoint authorisation is not
 * covered here. That needs a target the customer has told us is disposable,
 * which is a product decision rather than a scanner one.
 */

import { randomUUID, randomBytes } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch, type ScanCredentials } from "./http";
import { isDestructiveUrl } from "./destructive";
import { SQL_ERROR_SIGNATURES } from "./injectionProbe";
import {
  endpointsFromSpec,
  endpointsFromBundle,
  mergeEndpoints,
  type ApiEndpoint,
} from "./apiSurface";
import { collectJavaScript } from "./jsScanner";

const TIMEOUT_MS = 8_000;
const MAX_ENDPOINTS_TESTED = 25;
const MAX_PARAMS_PER_ENDPOINT = 4;

/** Paths whose POST is a query rather than a write. */
const READ_SHAPED = /\b(search|query|filter|lookup|find|list|report|graphql|validate|preview|check)\b/i;

/** A stand-in for a path parameter. Reading record 1 is a read. */
const PATH_PARAM_VALUE = "1";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/** Substitute {placeholders} so the URL can actually be requested. */
export function concreteUrl(endpoint: ApiEndpoint): string {
  return endpoint.url.replace(/\{[^}]+\}/g, PATH_PARAM_VALUE);
}

/** Is a POST to this endpoint a question rather than a change? */
export function isReadShaped(endpoint: ApiEndpoint): boolean {
  if (endpoint.method === "GET" || endpoint.method === "HEAD") return true;
  if (endpoint.method !== "POST") return false;
  try {
    return READ_SHAPED.test(new URL(endpoint.url).pathname);
  } catch {
    return false;
  }
}

/** Does this response carry data, as opposed to a refusal or an empty shell? */
function looksLikeData(status: number, body: string): boolean {
  if (status < 200 || status >= 300) return false;
  const trimmed = body.trim();
  if (trimmed.length < 20) return false;
  // An empty collection is a successful answer, not an exposure.
  if (/^\[\s*\]$/.test(trimmed)) return false;
  if (/^\{\s*("?(data|items|results|rows)"?\s*:\s*\[\s*\]\s*)\}$/.test(trimmed)) return false;
  return true;
}

/** A refusal, whatever status code it arrives with. */
function isRefusal(status: number, body: string): boolean {
  if (status === 401 || status === 403) return true;
  return /\b(unauthori[sz]ed|forbidden|access denied|not authenticated|login required|permission denied|invalid token|missing token)\b/i.test(
    body.slice(0, 1_000),
  );
}

export interface ApiProbeInput {
  endpoints: ApiEndpoint[];
  /** The scan's session. Without one, missing-auth cannot be distinguished. */
  credentials?: ScanCredentials;
}

export async function runApiProbes(input: ApiProbeInput): Promise<ScanVulnerability[]> {
  const testable = input.endpoints
    .filter((e) => !isDestructiveUrl(concreteUrl(e)))
    .filter(isReadShaped)
    .slice(0, MAX_ENDPOINTS_TESTED);

  if (testable.length === 0) return [];

  const unauthenticated: string[] = [];
  const injectable: Array<{ endpoint: string; param: string; where: string }> = [];

  for (const endpoint of testable) {
    const url = concreteUrl(endpoint);

    // ── 1. Missing authentication ───────────────────────────────────────────
    // Only meaningful with a session to contrast against: without one there is
    // no way to tell a public endpoint from an unprotected one.
    if (input.credentials && (endpoint.method === "GET" || endpoint.method === "HEAD")) {
      const [authed, anon] = await Promise.all([
        scanFetch(url, { as: input.credentials, timeoutMs: TIMEOUT_MS }),
        scanFetch(url, { as: null, timeoutMs: TIMEOUT_MS }),
      ]);

      if (
        authed &&
        anon &&
        looksLikeData(authed.status, authed.body) &&
        looksLikeData(anon.status, anon.body) &&
        !isRefusal(anon.status, anon.body)
      ) {
        unauthenticated.push(`${endpoint.method} ${new URL(url).pathname}`);
      }
    }

    // ── 2. SQL injection ────────────────────────────────────────────────────
    const params = endpoint.params.slice(0, MAX_PARAMS_PER_ENDPOINT);
    for (const param of params) {
      if (param.location === "header") continue;
      // A body field can only be tested by sending a body, so it is limited to
      // endpoints where doing so is a question rather than a change.
      if (param.location === "body" && endpoint.method !== "POST") continue;

      const marker = "sq" + randomBytes(4).toString("hex");
      const [baseline, injected] = await Promise.all([
        requestWith(endpoint, url, param, marker, input.credentials),
        requestWith(endpoint, url, param, `${marker}'`, input.credentials),
      ]);
      if (!baseline || !injected) continue;

      for (const signature of SQL_ERROR_SIGNATURES) {
        // Same discipline as injectionProbe: the signature must be absent from
        // the benign baseline, so a page that always mentions SQL is not a hit.
        if (signature.test(injected.body) && !signature.test(baseline.body)) {
          injectable.push({
            endpoint: `${endpoint.method} ${new URL(url).pathname}`,
            param: param.name,
            where: param.location,
          });
          break;
        }
      }
    }
  }

  const findings: ScanVulnerability[] = [];

  if (unauthenticated.length > 0) {
    findings.push(
      vuln({
        name: "API Endpoints Served Without Authentication",
        severity: "high",
        category: "Broken Access Control",
        description:
          `${unauthenticated.length} API endpoint${unauthenticated.length > 1 ? "s" : ""} returned data to a ` +
          `request carrying no session at all, matching what the signed-in session received. On a ` +
          `single-page app this is where data actually leaks: the endpoints are invisible in the HTML, so ` +
          `they are easy to ship without the authentication check the pages around them have. Anyone who ` +
          `reads your JavaScript bundle can find and call them.`,
        evidence:
          `Requested with the scan's session and with none, and compared:\n\n` +
          unauthenticated.map((e) => `  ${e}`).join("\n") +
          `\n\nIf any of these are meant to be public, no change is needed — but confirm that deliberately.`,
        solution:
          "Apply the authentication check at the router or middleware level so every endpoint is protected " +
          "by default and public ones are the explicit exception. Checking inside each handler means a new " +
          "handler is unprotected until somebody remembers, which is how these appear.",
        cweId: "CWE-306",
        cvssScore: 7.5,
        wstgId: "WSTG-ATHZ-01",
        confidence: 85,
      }),
    );
  }

  if (injectable.length > 0) {
    findings.push(
      vuln({
        name: "SQL Injection in API Parameters",
        severity: "critical",
        category: "Injection",
        description:
          `A single quote sent to ${injectable.length} API parameter${injectable.length > 1 ? "s" : ""} produced a ` +
          `database error that the same request without the quote did not. The value is reaching the SQL ` +
          `parser, which means an attacker can alter the query — reading any table, and often writing to ` +
          `them. These parameters are declared by the API rather than exposed in a form, so no amount of ` +
          `testing through the user interface would have found them.`,
        evidence:
          `Baseline and injected requests compared per parameter; the error signature was absent from the baseline.\n\n` +
          injectable.map((i) => `  ${i.endpoint}   ${i.param} (${i.where})`).join("\n"),
        solution:
          "Use parameterised queries or a query builder that binds values — never string concatenation, and " +
          "never an allowlist of 'dangerous characters', which is repeatedly defeated. If an ORM is already " +
          "in use, find the raw query that bypassed it. Fix every listed parameter: they are likely the same " +
          "handler pattern repeated.",
        cweId: "CWE-89",
        cvssScore: 9.8,
        wstgId: "WSTG-INPV-05",
        confidence: 90,
      }),
    );
  }

  return findings;
}

/** Issue one request with `value` placed wherever the parameter lives. */
async function requestWith(
  endpoint: ApiEndpoint,
  url: string,
  param: { name: string; location: string },
  value: string,
  credentials: ScanCredentials | undefined,
) {
  const as = credentials ?? undefined;

  if (param.location === "query") {
    const target = new URL(url);
    target.searchParams.set(param.name, value);
    return scanFetch(target.toString(), { as, timeoutMs: TIMEOUT_MS });
  }

  if (param.location === "path") {
    // Replace the substituted placeholder value rather than the brace, which
    // concreteUrl has already resolved.
    const target = url.replace(
      new RegExp(`/${PATH_PARAM_VALUE}(?=/|$)`),
      `/${encodeURIComponent(value)}`,
    );
    return scanFetch(target, { as, timeoutMs: TIMEOUT_MS });
  }

  // Body — read-shaped POST only, enforced by the caller.
  return scanFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ [param.name]: value }),
    as,
    timeoutMs: TIMEOUT_MS,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery orchestration
// ─────────────────────────────────────────────────────────────────────────────

/** Canonical spec locations, in the order they are worth trying. */
const SPEC_PATHS = [
  "/openapi.json",
  "/swagger.json",
  "/api/openapi.json",
  "/api/swagger.json",
  "/v1/openapi.json",
  "/api-docs/swagger.json",
];

/**
 * Assemble the API surface from whatever the target exposes.
 *
 * The spec is tried first and wins where both agree — it declares parameters
 * the front end may never send, which is exactly where forgotten handlers sit.
 * The bundle is the fallback, and on most vibe-coded apps it is the only source
 * there is.
 */
export async function collectApiSurface(
  origin: string,
  html: string,
): Promise<ApiEndpoint[]> {
  const [specEndpoints, bundleEndpoints] = await Promise.all([
    (async () => {
      for (const path of SPEC_PATHS) {
        const res = await scanFetch(`${origin}${path}`, { timeoutMs: TIMEOUT_MS });
        if (!res || res.status < 200 || res.status >= 300) continue;
        // Cheap structural check before parsing — a SPA catch-all returns 200
        // with HTML for any path, and parsing that wastes the budget.
        if (!/"(openapi|swagger)"\s*:|^\s*(openapi|swagger):/m.test(res.body)) continue;
        const found = endpointsFromSpec(res.body, origin);
        if (found.length > 0) return found;
      }
      return [] as ApiEndpoint[];
    })().catch(() => [] as ApiEndpoint[]),

    (async () => {
      const js = await collectJavaScript(html, origin);
      return js ? endpointsFromBundle(js, origin) : [];
    })().catch(() => [] as ApiEndpoint[]),
  ]);

  return mergeEndpoints(bundleEndpoints, specEndpoints);
}
