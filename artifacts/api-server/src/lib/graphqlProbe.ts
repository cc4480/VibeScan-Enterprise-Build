/**
 * GraphQL security probe.
 *
 * Discovers GraphQL endpoints (from inline JS + common paths), checks whether
 * introspection is enabled in production, and tests for field suggestion leaks.
 *
 * Design: read-only POSTs (introspection + bogus-field queries). No mutations.
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
  headers?: Record<string, string>,
): Promise<{ status: number; body: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 VibeScan Security Scanner",
        ...headers,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "follow",
    });
    const text = await res.text().catch(() => "");
    return { status: res.status, body: text };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ENDPOINT DISCOVERY
// ─────────────────────────────────────────────────────────────────────────────

const COMMON_GRAPHQL_PATHS = [
  "/graphql",
  "/api/graphql",
  "/v1/graphql",       // Hasura
  "/graphql/v1",
  "/graphql/v2",
  "/query",
  "/api/query",
  "/api",
];

function extractGraphqlUrlsFromJs(html: string, baseUrl: string): string[] {
  const inlineRx = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const js: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = inlineRx.exec(html)) !== null) {
    if (!/\bsrc\s*=/i.test(m[0])) js.push(m[1] ?? "");
  }
  const content = js.join("\n");

  const candidates: string[] = [];
  const patterns = [
    /(?:graphqlUrl|graphql_url|GRAPHQL_URL|GRAPHQL_ENDPOINT|graphqlEndpoint|hasuraUrl|HASURA_URL|NEXT_PUBLIC_GRAPHQL)\s*[:=,]\s*["'`]([^"'`\s]+)["'`]/gi,
    /uri\s*:\s*["'`](https?:\/\/[^"'`\s]+graphql[^"'`\s]*)["'`]/gi,
  ];
  for (const rx of patterns) {
    let pm: RegExpExecArray | null;
    while ((pm = rx.exec(content)) !== null) {
      try { candidates.push(new URL(pm[1]).href); } catch { /* skip */ }
    }
  }

  return [...new Set(candidates)].slice(0, 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// GRAPHQL CHECKS
// ─────────────────────────────────────────────────────────────────────────────

const INTROSPECTION_QUERY = {
  query: `{
    __schema {
      queryType { name }
      types { name kind description }
    }
  }`,
};

const TYPENAME_QUERY = { query: "{ __typename }" };

const BOGUS_FIELD_QUERY = { query: "{ nonExistentFieldVibeScan }" };

function isGraphqlResponse(text: string): boolean {
  try {
    const j = JSON.parse(text) as Record<string, unknown>;
    return "data" in j || "errors" in j;
  } catch {
    return false;
  }
}

function hasIntrospectionData(text: string): boolean {
  try {
    const j = JSON.parse(text) as { data?: { __schema?: { types?: unknown[] } } };
    return Array.isArray(j.data?.__schema?.types) && (j.data.__schema.types.length ?? 0) > 0;
  } catch {
    return false;
  }
}

function hasFieldSuggestion(text: string): boolean {
  return /did you mean|suggestions?:/i.test(text);
}

async function checkEndpoint(url: string): Promise<ScanVulnerability[]> {
  // First confirm it's a GraphQL endpoint with a cheap __typename query
  const probe = await safePost(url, TYPENAME_QUERY);
  if (!probe || !isGraphqlResponse(probe.body)) return [];

  const findings: ScanVulnerability[] = [];

  // Test full introspection
  const introRes = await safePost(url, INTROSPECTION_QUERY);
  if (introRes && hasIntrospectionData(introRes.body)) {
    let typeCount = 0;
    try {
      const j = JSON.parse(introRes.body) as { data?: { __schema?: { types?: unknown[] } } };
      typeCount = j.data?.__schema?.types?.length ?? 0;
    } catch { /* skip */ }

    const path = (() => { try { return new URL(url).pathname; } catch { return url; } })();

    findings.push(vuln({
      name: "GraphQL Introspection Enabled in Production",
      severity: "high",
      category: "API Security",
      description:
        `GraphQL introspection is enabled at ${path}. This lets any external party query the ` +
        `full API schema — every type, query, mutation, and field name — in a single request. ` +
        `Introspection is a reconnaissance tool that hands attackers the complete attack surface ` +
        `of your API${typeCount > 0 ? ` (${typeCount} types exposed)` : ""}.`,
      evidence: `POST ${url}\n{"query":"{ __schema { types { name } } }"}\nHTTP ${introRes.status} — schema returned with ${typeCount} types`,
      solution:
        "Disable introspection in production. Apollo Server: set `introspection: false` in " +
        "ApolloServer options (it is disabled by default when NODE_ENV=production). " +
        "Hasura: set the `HASURA_GRAPHQL_ENABLE_CONSOLE=false` env var and disable introspection " +
        "in the Hasura metadata. GraphQL Yoga / Pothos: pass `maskedErrors: true` and " +
        "`disableIntrospection: true` to the server factory.",
      cweId: "CWE-200",
      cvssScore: 7.5,
      wstgId: "WSTG-INFO-01",
      confidence: 95,
    }));
  }

  // Test field suggestions
  const suggestRes = await safePost(url, BOGUS_FIELD_QUERY);
  if (suggestRes && hasFieldSuggestion(suggestRes.body)) {
    findings.push(vuln({
      name: 'GraphQL Field Suggestions Enabled ("Did you mean…" Leaks)',
      severity: "low",
      category: "API Security",
      description:
        `The GraphQL server returns field name suggestions when a query contains a typo ` +
        `(e.g. "Did you mean 'password'?"). This leaks valid field names even when introspection ` +
        `is disabled, allowing attackers to enumerate your API schema incrementally.`,
      evidence: `POST ${url}\n{"query":"{ nonExistentFieldVibeScan }"}\nResponse contains suggestion hints`,
      solution:
        "Disable field suggestions. Apollo Server: wrap with `ApolloServerPluginDisabledSchema` " +
        "or use the `persistedQueries` plugin. graphql-js: patch with a custom " +
        "`noSuggestionsValidationRule`. Masking all errors with a generic message is the simplest fix.",
      cweId: "CWE-209",
      cvssScore: 3.7,
      confidence: 85,
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

  // Build candidate URL list: JS-extracted + common paths
  const jsUrls = extractGraphqlUrlsFromJs(html, origin);
  const pathUrls = COMMON_GRAPHQL_PATHS.map((p) => origin + p);
  const candidates = [...new Set([...jsUrls, ...pathUrls])];

  const settled = await Promise.allSettled(
    candidates.map((url) => checkEndpoint(url).catch(() => [])),
  );

  // Deduplicate by finding name — report introspection once even if on multiple paths
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
