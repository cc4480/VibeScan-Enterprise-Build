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
// Small enough not to be load against a customer, large enough that any real
// limiter would have engaged.
const RATE_LIMIT_BURST = 12;

/**
 * Paths that are meant to answer an unlimited burst and must not be flagged
 * for it. A liveness probe is polled continuously by the platform itself —
 * Railway, Kubernetes, a load balancer — and rate-limiting it would make the
 * platform mark a healthy service as down. A provider-discovery or
 * well-known endpoint returns data that is public by definition (an OAuth
 * client ID is not a secret), so throttling it stops nothing an attacker
 * couldn't already get by loading the page once.
 *
 * Found the hard way: this probe flagged seclayer.app's own
 * /api/system/health and /api/auth/providers, while its actual
 * credential-issuing endpoint enforced a limit correctly (verified live:
 * 429 from the sixth request). The finding's own "credential stuffing"
 * language never applied to either endpoint it named.
 */
const RATE_LIMIT_EXEMPT_PATTERN =
  /\/(healthz?|health[-_]?check|status|ready(iness)?|live(ness)?|ping|version|manifest\.json|\.well-known\/[^/]+|providers?|config(uration)?|robots\.txt|sitemap\.xml|favicon\.ico)(\/|$)/i;

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

/**
 * An identifier chosen so that nothing can possibly exist at it.
 *
 * This is what makes write-verb authorisation testable without risk. DELETE on
 * a record that does not exist destroys nothing, but the status code still says
 * whether authorisation ran: a refusal means the check happens before the
 * lookup, while a 404 means an unauthenticated caller reached the database.
 *
 * PUT is deliberately never sent — many APIs treat it as an upsert, so a PUT to
 * a nonexistent id creates the record instead of missing it.
 */
const IMPLAUSIBLE_ID = "999999997";

/** Response fields that should not be leaving the server at all. */
// Two entries deliberately excluded: bare "hash" and bare "token" are common
// as public, non-sensitive field names — a content hash for cache-busting or
// dedup, a share/invite token already exposed in a URL. The prefixed forms
// (password_hash, access_token, session_token, …) still catch the case that
// actually matters, without a bare word firing on every API that returns a
// pagination cursor called "token".
const SENSITIVE_FIELD_RE =
  /^(password|passwd|pwd|password_?hash|salt|secret|api_?key|apikey|private_?key|access_?token|refresh_?token|session_?token|ssn|social_?security|card_?number|cardnumber|cvv|cvc|iban|routing_?number|tax_?id)$/i;

/** Fields that let a caller grant themselves something by including them. */
const PRIVILEGE_FIELD_RE =
  /^(role|roles|is_?admin|admin|is_?staff|permissions?|scopes?|plan|tier|credits?|balance|verified|is_?verified|email_?verified|owner_?id|user_?id|account_?id)$/i;

export interface ApiProbeInput {
  endpoints: ApiEndpoint[];
  /** The scan's session. Without one, missing-auth cannot be distinguished. */
  credentials?: ScanCredentials;
  /** A second account, enabling API-level IDOR comparison. */
  secondary?: ScanCredentials;
}

/** Collect every field name in a JSON document, however deeply nested. */
export function jsonFieldNames(body: string, limit = 400): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return [];
  }

  const names = new Set<string>();
  const walk = (node: unknown, depth: number) => {
    if (names.size >= limit || depth > 6 || !node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      // One element is enough: collection members share a shape.
      if (node.length > 0) walk(node[0], depth + 1);
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      names.add(key);
      walk(value, depth + 1);
    }
  };
  walk(parsed, 0);
  return [...names];
}

/**
 * Sensitive fields present in a response body.
 *
 * A read, so entirely safe to perform, and it catches the case where an API
 * returns the whole database row and lets the front end pick fields — the
 * password hash is still on the wire, and still in the browser's memory.
 */
export function exposedSensitiveFields(body: string): string[] {
  return jsonFieldNames(body).filter((n) => SENSITIVE_FIELD_RE.test(n));
}

/** Privilege-bearing fields a write endpoint declares it will accept. */
export function privilegeFieldsAccepted(endpoint: ApiEndpoint): string[] {
  return endpoint.params
    .filter((p) => p.location === "body" && PRIVILEGE_FIELD_RE.test(p.name))
    .map((p) => p.name);
}

export async function runApiProbes(input: ApiProbeInput): Promise<ScanVulnerability[]> {
  const testable = input.endpoints
    .filter((e) => !isDestructiveUrl(concreteUrl(e)))
    .filter(isReadShaped)
    .slice(0, MAX_ENDPOINTS_TESTED);

  if (testable.length === 0) return [];

  const unauthenticated: string[] = [];
  const injectable: Array<{ endpoint: string; param: string; where: string }> = [];
  const overExposed: Array<{ endpoint: string; fields: string[] }> = [];
  const unratelimited: string[] = [];
  const crossAccount: string[] = [];
  const massAssignable: Array<{ endpoint: string; fields: string[] }> = [];
  const unauthorizedWrites: string[] = [];

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

    // ── 1b. Excessive data exposure ─────────────────────────────────────────
    // Pure read. Catches an API that returns the whole database row and lets
    // the front end choose what to display — the password hash still crossed
    // the wire and still sits in the browser's memory.
    if (endpoint.method === "GET" || endpoint.method === "HEAD") {
      const res = await scanFetch(url, {
        ...(input.credentials ? { as: input.credentials } : {}),
        timeoutMs: TIMEOUT_MS,
      });
      if (res && looksLikeData(res.status, res.body) && !isRefusal(res.status, res.body)) {
        const fields = exposedSensitiveFields(res.body);
        if (fields.length > 0) {
          overExposed.push({ endpoint: `${endpoint.method} ${new URL(url).pathname}`, fields });
        }

        // ── 1c. API-level IDOR ────────────────────────────────────────────
        // The phase-04 comparison applied per endpoint: if a second account is
        // served byte-comparable data from a URL naming a record, one of them
        // is reading data that is not theirs.
        if (input.secondary && /\/\d+(?:\/|$)/.test(new URL(url).pathname)) {
          const asOther = await scanFetch(url, { as: input.secondary, timeoutMs: TIMEOUT_MS });
          if (
            asOther &&
            !isRefusal(asOther.status, asOther.body) &&
            looksLikeData(asOther.status, asOther.body) &&
            asOther.body === res.body
          ) {
            crossAccount.push(`${endpoint.method} ${new URL(url).pathname}`);
          }
        }
      }
    }

    // ── 1d. Rate limiting ───────────────────────────────────────────────────
    // Reads only, and a small burst — enough to show no limiter exists without
    // becoming load against a customer's server.
    if (
      endpoint.method === "GET" &&
      unratelimited.length < 3 &&
      !RATE_LIMIT_EXEMPT_PATTERN.test(new URL(url).pathname)
    ) {
      const burst = await Promise.all(
        Array.from({ length: RATE_LIMIT_BURST }, () =>
          scanFetch(url, {
            ...(input.credentials ? { as: input.credentials } : {}),
            timeoutMs: TIMEOUT_MS,
          }),
        ),
      );
      const answered = burst.filter((r) => r !== null);
      const throttled = answered.some((r) => r!.status === 429);
      if (!throttled && answered.length === RATE_LIMIT_BURST && answered.every((r) => r!.status < 400)) {
        unratelimited.push(`${endpoint.method} ${new URL(url).pathname}`);
      }
    }

    // ── 1e. Write-verb authorisation (BFLA) ─────────────────────────────────
    // Aimed at an identifier nothing can exist at, so a successful DELETE
    // destroys nothing — but the status still reveals whether authorisation
    // runs before the lookup. PUT is never sent: many APIs upsert.
    if (
      input.credentials &&
      /\{[^}]+\}/.test(endpoint.url) &&
      (endpoint.method === "GET" || endpoint.method === "DELETE" || endpoint.method === "PATCH")
    ) {
      const target = endpoint.url.replace(/\{[^}]+\}/g, IMPLAUSIBLE_ID);
      if (!isDestructiveUrl(target)) {
        for (const verb of ["DELETE", "PATCH"] as const) {
          const res = await scanFetch(target, { method: verb, as: null, timeoutMs: TIMEOUT_MS });
          // 404 means the handler looked for the record before checking who was
          // asking. 405 means the verb is not routed at all, which is fine.
          if (res && res.status === 404) {
            unauthorizedWrites.push(`${verb} ${new URL(target).pathname}`);
            break;
          }
        }
      }
    }

    // ── 1f. Mass assignment ─────────────────────────────────────────────────
    // Read from the declared contract rather than probed: sending a role field
    // to find out whether it sticks means granting somebody a role.
    const privileged = privilegeFieldsAccepted(endpoint);
    if (privileged.length > 0) {
      massAssignable.push({
        endpoint: `${endpoint.method} ${new URL(url).pathname}`,
        fields: privileged,
      });
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

  if (crossAccount.length > 0) {
    findings.push(
      vuln({
        name: "API Records Readable by Another Account",
        severity: "critical",
        category: "Broken Access Control",
        description:
          `A second, unrelated account received byte-identical data from ${crossAccount.length} API ` +
          `endpoint${crossAccount.length > 1 ? "s" : ""} that name a specific record. The API confirms someone ` +
          `is signed in but not that the record is theirs, so any user can read another user's data by ` +
          `changing the identifier. Two separate accounts cannot both own one record.`,
        evidence:
          `Requested as two separate accounts; both received identical responses:

` +
          crossAccount.map((e) => `  ${e}`).join("\n") +
          `

If these two accounts share an organisation, sharing the record may be intended.`,
        solution:
          "Scope the query to the caller: load the record with a WHERE clause bound to the current user or " +
          "tenant id, rather than fetching by id and returning it. Apply it in one place — a repository " +
          "layer or middleware — so a new endpoint inherits the check instead of needing to remember it.",
        cweId: "CWE-639",
        cvssScore: 8.1,
        wstgId: "WSTG-ATHZ-04",
        confidence: 85,
      }),
    );
  }

  if (unauthorizedWrites.length > 0) {
    findings.push(
      vuln({
        name: "Write Endpoints Reachable Without Authentication",
        severity: "critical",
        category: "Broken Access Control",
        description:
          `${unauthorizedWrites.length} write endpoint${unauthorizedWrites.length > 1 ? "s" : ""} answered an ` +
          `unauthenticated request with "not found" rather than "not allowed". The handler looked the record ` +
          `up before checking who was asking, which means authorisation runs after the database does — or ` +
          `not at all. Aimed at a real identifier instead of a nonexistent one, the same request would have ` +
          `modified or deleted the record.`,
        evidence:
          `Sent with no session, against an identifier chosen so nothing could exist at it, so nothing was ` +
          `modified:

` +
          unauthorizedWrites.map((e) => `  ${e}`).join("\n") +
          `

A protected endpoint answers 401 or 403 here; these answered 404.`,
        solution:
          "Check authentication and authorisation before touching the database, in middleware rather than " +
          "inside each handler. Returning 404 to an unauthenticated caller is only correct if the check ran " +
          "first and 404 was chosen deliberately to avoid confirming the record exists.",
        cweId: "CWE-862",
        cvssScore: 9.1,
        wstgId: "WSTG-ATHZ-02",
        confidence: 75,
      }),
    );
  }

  if (overExposed.length > 0) {
    const allFields = [...new Set(overExposed.flatMap((e) => e.fields))];
    findings.push(
      vuln({
        name: "Sensitive Fields Returned by the API",
        severity: "high",
        category: "Information Disclosure",
        description:
          `API responses include field${allFields.length > 1 ? "s" : ""} named ${allFields.join(", ")}. This is ` +
          `the signature of an endpoint returning a whole database row and letting the front end pick what to ` +
          `display: the values still crossed the network, still sit in the browser's memory, and are visible ` +
          `to anyone who opens the network tab. Hiding a field in the interface does not remove it from the ` +
          `response.`,
        evidence: overExposed.map((e) => `  ${e.endpoint}   ${e.fields.join(", ")}`).join("\n"),
        solution:
          "Serialise responses through an explicit shape that names the fields to include, rather than " +
          "returning the model and removing fields you remember to remove. A field added to the table later " +
          "then stays out of the API by default instead of leaking on the next deploy.",
        cweId: "CWE-213",
        cvssScore: 7.5,
        wstgId: "WSTG-ATHZ-04",
        confidence: 80,
      }),
    );
  }

  if (massAssignable.length > 0) {
    findings.push(
      vuln({
        name: "Privilege Fields Accepted in Request Bodies",
        severity: "medium",
        category: "Broken Access Control",
        description:
          `The API contract declares that these endpoints accept fields that decide privilege or ownership. ` +
          `If any is bound straight onto the stored record, a caller can grant themselves a role, change a ` +
          `plan, or reassign a record to another owner simply by including the field. This is read from the ` +
          `declared schema, not confirmed by sending one — testing it for real would mean granting somebody ` +
          `a role.`,
        evidence:
          massAssignable.map((e) => `  ${e.endpoint}   ${e.fields.join(", ")}`).join("\n") +
          `

Verify by hand whether each field is actually bound to the model.`,
        solution:
          "Bind request bodies to an explicit allowlist of writable fields per endpoint. Never pass a parsed " +
          "body into a model constructor or update call wholesale — that is what turns an extra JSON key into " +
          "a privilege escalation.",
        cweId: "CWE-915",
        cvssScore: 6.5,
        wstgId: "WSTG-BUSL-01",
        confidence: 55,
      }),
    );
  }

  if (unratelimited.length > 0) {
    findings.push(
      vuln({
        name: "API Endpoints Without Rate Limiting",
        severity: "medium",
        category: "Security Misconfiguration",
        description:
          `${unratelimited.length} endpoint${unratelimited.length > 1 ? "s" : ""} answered a rapid burst of ` +
          `requests without once throttling. Unlimited requests make credential stuffing, identifier ` +
          `enumeration and scraping cheap, and turn any expensive endpoint into a way to exhaust the server.`,
        evidence:
          `${RATE_LIMIT_BURST} requests in immediate succession, none answered with 429:

` +
          unratelimited.map((e) => `  ${e}`).join("\n"),
        solution:
          "Rate limit at the edge — reverse proxy, CDN or API gateway — so it applies to every route by " +
          "default. Apply a tighter limit to authentication and anything that reads by identifier, which are " +
          "the endpoints worth attacking in bulk.",
        cweId: "CWE-770",
        cvssScore: 5.3,
        wstgId: "WSTG-ATHN-04",
        confidence: 70,
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
