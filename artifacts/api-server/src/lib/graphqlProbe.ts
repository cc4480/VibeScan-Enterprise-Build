/**
 * GraphQL security probe.
 *
 * Discovers GraphQL endpoints (from inline JS + specific paths), checks whether
 * introspection is enabled in production, and tests for field-suggestion leaks.
 *
 * False-positive prevention:
 * - Endpoint confirmation requires data.__typename to be a string — the only
 *   response shape unique to GraphQL (REST APIs returning {"data":{…}} won't have
 *   this nested key). Content-Type must be application/json or application/graphql+json.
 * - Introspection is confirmed only when __schema.types is a non-empty array.
 * - Field-suggestion is only flagged when the error object has the GraphQL-specific
 *   "locations" array + a suggestion phrase in errors[].message.
 * - Generic paths (/api, /query) are excluded — only paths with "graphql" in the
 *   segment or explicitly extracted from JS are probed.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";
import { probeBatching, probeIde } from "./graphqlExtra";

const TIMEOUT_MS = 8_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safePost(
  url: string,
  body: unknown,
): Promise<{ status: number; body: string; ct: string } | null> {
  const res = await scanFetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, application/graphql+json",
    },
    body: JSON.stringify(body),
    timeoutMs: TIMEOUT_MS,
  });
  if (!res) return null;
  return { status: res.status, body: res.body, ct: res.headers["content-type"] ?? "" };
}

// ─────────────────────────────────────────────────────────────────────────────
// ENDPOINT DISCOVERY
// ─────────────────────────────────────────────────────────────────────────────

// Only paths that are specifically GraphQL — no /api or /query (too generic).
// /api/query is included because it requires both segments.
const GRAPHQL_SPECIFIC_PATHS = [
  "/graphql",
  "/api/graphql",
  "/v1/graphql",       // Hasura
  "/graphql/v1",
  "/graphql/v2",
];

/** Hosts many unrelated customers share; a sibling subdomain there is NOT the same site. */
const SHARED_SUFFIXES = [
  "vercel.app", "netlify.app", "herokuapp.com", "github.io", "pages.dev", "workers.dev",
  "web.app", "firebaseapp.com", "onrender.com", "fly.dev", "azurewebsites.net", "appspot.com",
  "amazonaws.com", "cloudfront.net", "railway.app", "supabase.co", "glitch.me", "repl.co",
];

/** Registrable-domain guess: last two labels, three under a two-letter ccTLD's second level (co.uk). */
function siteOf(host: string): string {
  const labels = host.toLowerCase().replace(/^www\./, "").split(".");
  const cc = labels.length >= 3 && labels[labels.length - 1]!.length === 2 &&
    ["co", "com", "org", "net", "gov", "ac", "edu"].includes(labels[labels.length - 2]!);
  return labels.slice(cc ? -3 : -2).join(".");
}

/**
 * Whether a JS-referenced endpoint belongs to the scanned site: the same host, or a
 * subdomain of the same registrable domain (api.example.com for www.example.com).
 * A vendor's endpoint (a headless CMS, a public data API) is never probed or reported
 * against the customer; the introspection POST would also be traffic to a third party.
 */
export function isOwnHost(candidateHost: string, targetHost: string): boolean {
  const a = candidateHost.toLowerCase().replace(/^www\./, "");
  const b = targetHost.toLowerCase().replace(/^www\./, "");
  if (a === b) return true;
  if (SHARED_SUFFIXES.some((x) => a === x || a.endsWith("." + x) || b === x || b.endsWith("." + x))) return false;
  return siteOf(a) === siteOf(b);
}

function extractGraphqlUrlsFromJs(html: string, origin: string): string[] {
  const inlineRx = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const js: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = inlineRx.exec(html)) !== null) {
    if (!/\bsrc\s*=/i.test(m[0])) js.push(m[1] ?? "");
  }
  const content = js.join("\n");

  const candidates: string[] = [];
  const patterns = [
    /(?:graphqlUrl|graphql_url|GRAPHQL_URL|GRAPHQL_ENDPOINT|graphqlEndpoint|hasuraUrl|HASURA_URL|NEXT_PUBLIC_GRAPHQL)\s*[:=,]\s*["'`]([^"'`\s]{5,})["'`]/gi,
    /uri\s*:\s*["'`](https?:\/\/[^"'`\s]+graphql[^"'`\s]*)["'`]/gi,
  ];
  for (const rx of patterns) {
    let pm: RegExpExecArray | null;
    while ((pm = rx.exec(content)) !== null) {
      try {
        const parsed = new URL(pm[1], origin);
        // Own host (or a subdomain of the same site) only. A third-party endpoint
        // inlined in the page is neither ours to probe nor the customer's to own.
        if (isOwnHost(parsed.hostname, new URL(origin).hostname) &&
            (parsed.pathname.toLowerCase().includes("graphql") || parsed.hostname === new URL(origin).hostname)) {
          candidates.push(parsed.href);
        }
      } catch { /* skip invalid */ }
    }
  }

  return [...new Set(candidates)].slice(0, 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// GRAPHQL RESPONSE VALIDATORS — strict to eliminate REST API false positives
// ─────────────────────────────────────────────────────────────────────────────

const TYPENAME_QUERY = { query: "{ __typename }" };

/**
 * Confirms a GraphQL endpoint with very high specificity.
 *
 * A true GraphQL server responding to `{ __typename }` returns:
 *   {"data":{"__typename":"Query"}} (or Mutation/Subscription)
 *
 * A REST API returning {"data":{…}} will NOT have data.__typename as a string,
 * because __typename is a GraphQL meta-field — not a common REST field name.
 *
 * If __typename check is ambiguous (some servers return it differently under
 * auth requirements), also accept a response with errors[] where each error
 * object has the GraphQL-specific "locations" array field.
 */
function isConfirmedGraphqlEndpoint(text: string, ct: string): boolean {
  // Must be JSON content (or graphql+json)
  if (!ct.includes("application/json") && !ct.includes("graphql")) return false;

  let j: Record<string, unknown>;
  try { j = JSON.parse(text) as Record<string, unknown>; } catch { return false; }

  // Signal 1: data.__typename is a string (the canonical GraphQL confirmation)
  const data = j["data"];
  if (data && typeof data === "object" && data !== null) {
    const tn = (data as Record<string, unknown>)["__typename"];
    if (typeof tn === "string" && tn.length > 0) return true;
  }

  // Signal 2: errors[] array where each error has a "locations" array
  // (GraphQL spec mandates this shape — REST APIs don't typically use it)
  const errors = j["errors"];
  if (Array.isArray(errors) && errors.length > 0) {
    const firstErr = errors[0] as Record<string, unknown>;
    if (
      typeof firstErr["message"] === "string" &&
      Array.isArray(firstErr["locations"])
    ) return true;
  }

  return false;
}

function hasIntrospectionData(text: string): boolean {
  try {
    const j = JSON.parse(text) as { data?: { __schema?: { types?: unknown[] } } };
    const types = j.data?.__schema?.types;
    // Real introspection returns 15+ built-in types minimum
    return Array.isArray(types) && types.length >= 10;
  } catch {
    return false;
  }
}

/**
 * Field suggestion check — only flag when:
 * 1. The response is a GraphQL errors array (with "locations" field — GraphQL spec)
 * 2. A suggestion phrase appears inside errors[].message
 *
 * This avoids flagging REST APIs or HTML error pages that say "Did you mean X?"
 * in unrelated contexts.
 */
function hasGraphqlFieldSuggestion(text: string, ct: string): boolean {
  if (!ct.includes("application/json") && !ct.includes("graphql")) return false;
  let j: Record<string, unknown>;
  try { j = JSON.parse(text) as Record<string, unknown>; } catch { return false; }

  const errors = j["errors"];
  if (!Array.isArray(errors) || errors.length === 0) return false;

  return errors.some((e) => {
    const err = e as Record<string, unknown>;
    // Must have GraphQL-specific "locations" array to confirm this is a GQL error
    if (!Array.isArray(err["locations"])) return false;
    const msg = typeof err["message"] === "string" ? err["message"] : "";
    return /did you mean|cannot query field/i.test(msg);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-ENDPOINT CHECK
// ─────────────────────────────────────────────────────────────────────────────

const INTROSPECTION_QUERY = {
  query: `{
    __schema {
      queryType { name }
      types { name kind }
    }
  }`,
};

const BOGUS_FIELD_QUERY = { query: "{ nonExistentFieldSecScanProbe }" };

async function checkEndpoint(url: string): Promise<ScanVulnerability[]> {
  // Step 1: confirm it's actually GraphQL (strict validation)
  const probe = await safePost(url, TYPENAME_QUERY);
  if (!probe) return [];
  if (!isConfirmedGraphqlEndpoint(probe.body, probe.ct)) return [];

  const findings: ScanVulnerability[] = [];
  const path = (() => { try { return new URL(url).pathname; } catch { return url; } })();

  // Step 2: test full introspection
  const introRes = await safePost(url, INTROSPECTION_QUERY);
  if (introRes && hasIntrospectionData(introRes.body)) {
    let typeCount = 0;
    try {
      const j = JSON.parse(introRes.body) as { data?: { __schema?: { types?: unknown[] } } };
      typeCount = j.data?.__schema?.types?.length ?? 0;
    } catch { /* skip */ }

    findings.push(vuln({
      name: "GraphQL Introspection Enabled in Production",
      severity: "medium",
      category: "API Security",
      description:
        `GraphQL introspection is enabled at ${path}. This lets any external party retrieve ` +
        `the API schema — type, query, mutation and field names — in a single request` +
        `${typeCount > 0 ? ` (${typeCount} types returned)` : ""}. ` +
        `It exposes structure, not data, and many public or developer-facing APIs leave it on ` +
        `deliberately; it becomes a real weakness when the API is private or relies on ` +
        `obscurity of its fields for access control. Verify whether this schema is meant to be public.`,
      evidence: `POST ${url}\n{"query":"{ __schema { types { name } } }"}\nHTTP ${introRes.status} — full schema returned (${typeCount} types)\nConfirmed via __typename endpoint verification`,
      solution:
        "Disable introspection in production. Apollo Server: pass `introspection: false` (default when NODE_ENV=production). " +
        "Hasura: set env var `HASURA_GRAPHQL_ENABLE_INTROSPECTION=false`. " +
        "GraphQL Yoga: pass `disableIntrospection: true`. " +
        "If you need introspection for internal tooling, restrict it by IP or API key.",
      cweId: "CWE-200",
      cvssScore: 5.3,
      wstgId: "WSTG-INFO-01",
      // The schema response is directly observed; whether it is intended is not.
      confidence: 90,
    }));
  }

  // Step 3: test field suggestions (only if we haven't already confirmed introspection
  //         — introspection is the bigger issue; suggestions are a lower-level signal)
  const suggestRes = await safePost(url, BOGUS_FIELD_QUERY);
  if (suggestRes && hasGraphqlFieldSuggestion(suggestRes.body, suggestRes.ct)) {
    findings.push(vuln({
      name: 'GraphQL Field Suggestions Enabled ("Did you mean…" Leaks)',
      severity: "low",
      category: "API Security",
      description:
        `The GraphQL server returns field name suggestions when a query references a field ` +
        `that doesn't exist (e.g. "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?"). ` +
        `This leaks valid field names even when introspection is disabled, letting attackers ` +
        `enumerate the API schema incrementally using a dictionary of common names.`,
      evidence: `POST ${url}\n{"query":"{ nonExistentFieldSecScanProbe }"}\nResponse: errors[].message contains field suggestion\nError has GraphQL "locations" array (confirmed GQL endpoint)`,
      solution:
        "Disable field suggestions in your GraphQL server. graphql-js: add a custom validation rule that removes suggestions. " +
        "Apollo Server v4+: this is configurable via `formatError`. " +
        "The simplest fix is to replace all GraphQL error messages with a generic 'Invalid query' string in production.",
      cweId: "CWE-209",
      cvssScore: 3.7,
      confidence: 90,
    }));
  }

  const batching = await probeBatching(url).catch(() => null);
  if (batching) findings.push(batching);

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function runGraphqlProbe(
  targetUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  let origin: string;
  try { origin = new URL(targetUrl).origin; } catch { return []; }

  // JS-extracted URLs first (high confidence they're real GQL endpoints)
  // then the standard path list — but NOT generic paths like /api or /query
  const jsUrls = extractGraphqlUrlsFromJs(html, origin);
  const pathUrls = GRAPHQL_SPECIFIC_PATHS.map((p) => origin + p);
  const candidates = [...new Set([...jsUrls, ...pathUrls])];

  const [settled, ide] = await Promise.all([
    Promise.allSettled(candidates.map((url) => checkEndpoint(url).catch(() => []))),
    probeIde(origin).catch(() => null),
  ]);

  // Deduplicate — report each finding name only once even if on multiple paths
  const seen = new Set<string>();
  const all: ScanVulnerability[] = [];
  for (const r of settled) {
    if (r.status !== "fulfilled") continue;
    for (const v of r.value) {
      if (!seen.has(v.name)) {
        seen.add(v.name);
        all.push(v);
      }
    }
  }

  if (ide) all.push(ide);
  return all;
}
