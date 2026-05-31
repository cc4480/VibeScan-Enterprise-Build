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

const TIMEOUT_MS = 8_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safePost(
  url: string,
  body: unknown,
): Promise<{ status: number; body: string; ct: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 Seclayer Security Scanner",
        Accept: "application/json, application/graphql+json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "follow",
    });
    const text = await res.text().catch(() => "");
    const ct = res.headers.get("content-type") ?? "";
    return { status: res.status, body: text, ct };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
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
        // Only same-origin or explicit graphql mentions — skip if it's a CDN or analytics URL
        if (parsed.pathname.toLowerCase().includes("graphql") ||
            parsed.hostname === new URL(origin).hostname) {
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

const BOGUS_FIELD_QUERY = { query: "{ nonExistentFieldSeclayerProbe }" };

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
      severity: "high",
      category: "API Security",
      description:
        `GraphQL introspection is enabled at ${path}. This lets any external party retrieve ` +
        `the full API schema — every type, query, mutation, and field name — in a single request. ` +
        `Introspection is a reconnaissance tool: it hands attackers the complete attack surface ` +
        `of your API${typeCount > 0 ? ` (${typeCount} types exposed)` : ""}. ` +
        `Tools like GraphQL Voyager can visualise the entire schema from one introspection call.`,
      evidence: `POST ${url}\n{"query":"{ __schema { types { name } } }"}\nHTTP ${introRes.status} — full schema returned (${typeCount} types)\nConfirmed via __typename endpoint verification`,
      solution:
        "Disable introspection in production. Apollo Server: pass `introspection: false` (default when NODE_ENV=production). " +
        "Hasura: set env var `HASURA_GRAPHQL_ENABLE_INTROSPECTION=false`. " +
        "GraphQL Yoga: pass `disableIntrospection: true`. " +
        "If you need introspection for internal tooling, restrict it by IP or API key.",
      cweId: "CWE-200",
      cvssScore: 7.5,
      wstgId: "WSTG-INFO-01",
      confidence: 97,
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
      evidence: `POST ${url}\n{"query":"{ nonExistentFieldSeclayerProbe }"}\nResponse: errors[].message contains field suggestion\nError has GraphQL "locations" array (confirmed GQL endpoint)`,
      solution:
        "Disable field suggestions in your GraphQL server. graphql-js: add a custom validation rule that removes suggestions. " +
        "Apollo Server v4+: this is configurable via `formatError`. " +
        "The simplest fix is to replace all GraphQL error messages with a generic 'Invalid query' string in production.",
      cweId: "CWE-209",
      cvssScore: 3.7,
      confidence: 90,
    }));
  }

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

  const settled = await Promise.allSettled(
    candidates.map((url) => checkEndpoint(url).catch(() => [])),
  );

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

  return all;
}
