import { MAX_ENDPOINTS } from "./apiSurfaceSpec";
export { endpointsFromSpec } from "./apiSurfaceSpec";
/**
 * API endpoint discovery.
 *
 * Every existing parameter source in this scanner is HTML-shaped: query strings
 * on the target URL, `<form>` input names, and `<a href>` query params. That
 * works on a server-rendered site and finds almost nothing on the stack this
 * product exists to scan.
 *
 * A React or Vue SPA ships an empty shell — no forms, no named inputs, no links
 * carrying parameters — and talks to a JSON API discovered only at runtime. The
 * injection and traversal probes therefore fall back to guessing common
 * parameter names against "/", which is close to testing nothing.
 *
 * This module recovers the real surface from the two places it actually exists:
 *
 *   1. An OpenAPI/Swagger document, when the app exposes one. Authoritative:
 *      paths, methods, parameters and request-body fields, all declared.
 *   2. The JavaScript bundle, when it does not. Every endpoint the front end
 *      calls appears there as a string literal, because it has to.
 *
 * Discovery only. Deciding what to *do* with an endpoint belongs to the probes.
 */

export type ParamLocation = "query" | "path" | "body" | "header";

export interface ApiParam {
  name: string;
  location: ParamLocation;
}

export interface ApiEndpoint {
  /** Absolute URL. Path parameters keep their declared braces: /users/{id} */
  url: string;
  method: string;
  params: ApiParam[];
  source: "spec" | "bundle" | "runtime";
}

// ─────────────────────────────────────────────────────────────────────────────
// JavaScript bundles
// ─────────────────────────────────────────────────────────────────────────────

// Paths that look like an API rather than a page or an asset.
// The class includes ? = & deliberately: without them a literal carrying a
// query string fails to reach the closing quote and the endpoint is dropped
// entirely rather than merely losing its parameters.
const API_PATH_RE = /["'`](\/(?:api|v\d+|rest|graphql)\/[A-Za-z0-9/_\-.${}:?=&]*)["'`]/g;
// Absolute URLs back to the target origin.
const ABSOLUTE_RE = /["'`](https?:\/\/[^"'`\s]+\/(?:api|v\d+|rest)\/[^"'`\s]*)["'`]/g;
// fetch("/x") and axios.post("/x") — catches API roots that lack an /api prefix.
const CALL_RE =
  /(?:fetch|axios(?:\.(get|post|put|patch|delete))?)\s*\(\s*["'`]([^"'`]+)["'`]/g;

const ASSET_RE = /\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|woff2?|ttf|ico|map|json)$/i;

/**
 * Recover endpoints from a JS bundle.
 *
 * Every endpoint the front end calls is a string literal in the bundle, because
 * it has to be. This is less complete than a spec — it sees only what the UI
 * uses, and misses handlers nothing calls — but on an app with no spec it is
 * the difference between testing the API and testing nothing.
 *
 * Template placeholders are normalised: `/api/scans/${id}` becomes
 * `/api/scans/{id}` so it reads the same as a declared path parameter.
 */
export function endpointsFromBundle(js: string, origin: string): ApiEndpoint[] {
  const paths = new Set<string>();

  const collect = (raw: string | undefined) => {
    if (!raw) return;
    let path = raw.trim();
    if (!path) return;

    if (/^https?:\/\//i.test(path)) {
      try {
        const parsed = new URL(path);
        if (parsed.origin !== origin) return; // never test someone else's API
        path = parsed.pathname;
      } catch {
        return;
      }
    }

    if (!path.startsWith("/")) return;
    if (path.startsWith("//")) return;
    // Test the path alone: "/api/data.json?v=2" is still an asset.
    if (ASSET_RE.test(path.split("?")[0]!)) return;

    // `${id}` and `:id` both mean "a value goes here". Placeholders are
    // numbered from the second onward so /a/{id}/b/{id} cannot end up with two
    // parameters of the same name, which would be ambiguous to substitute into.
    let placeholder = 0;
    path = path
      .replace(/\$\{[^}]*\}/g, () => {
        placeholder += 1;
        return placeholder === 1 ? "{id}" : `{id${placeholder}}`;
      })
      .replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{$1}");
    // Trailing concatenation artefacts from minified template literals.
    path = path.replace(/[?&]$/, "");

    if (path.length > 1) paths.add(path);
  };

  for (const m of js.matchAll(API_PATH_RE)) collect(m[1]);
  for (const m of js.matchAll(ABSOLUTE_RE)) collect(m[1]);
  for (const m of js.matchAll(CALL_RE)) collect(m[2]);

  // Keyed by URL so "/x" and "/x?a=" collapse into one endpoint carrying the
  // union of their parameters, rather than two entries for the same handler.
  const byUrl = new Map<string, ApiEndpoint>();

  for (const path of paths) {
    if (byUrl.size >= MAX_ENDPOINTS) break;

    const [pathname, query] = path.split("?");
    const url = `${origin}${pathname}`;

    const params: ApiParam[] = [];
    for (const m of (pathname ?? "").matchAll(/\{([^}]+)\}/g)) {
      params.push({ name: m[1]!, location: "path" });
    }
    if (query) {
      for (const pair of query.split("&")) {
        const name = pair.split("=")[0];
        if (name) params.push({ name, location: "query" });
      }
    }

    const existing = byUrl.get(url);
    if (existing) {
      for (const p of params) {
        if (!existing.params.some((q) => q.name === p.name && q.location === p.location)) {
          existing.params.push(p);
        }
      }
      continue;
    }

    byUrl.set(url, {
      url,
      // The method is unknown from a bare string, so GET is the safe assumption:
      // reading is the only verb worth guessing at on someone's live API.
      method: "GET",
      params,
      source: "bundle",
    });
  }

  return [...byUrl.values()];
}

/**
 * Merge discovery results, preferring the spec.
 *
 * A spec entry is authoritative — it carries declared parameters and the real
 * method — so a bundle entry for the same path and method adds nothing.
 */
export function mergeEndpoints(...groups: ApiEndpoint[][]): ApiEndpoint[] {
  const byKey = new Map<string, ApiEndpoint>();
  for (const group of groups) {
    for (const endpoint of group) {
      const key = `${endpoint.method} ${endpoint.url}`;
      const existing = byKey.get(key);
      if (!existing || (existing.source === "bundle" && endpoint.source === "spec")) {
        byKey.set(key, endpoint);
      }
    }
  }
  return [...byKey.values()].slice(0, MAX_ENDPOINTS);
}