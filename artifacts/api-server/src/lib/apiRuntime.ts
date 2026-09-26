/**
 * API endpoints seen at runtime.
 *
 * The bundle scan (apiSurface.ts) finds an endpoint only if its URL is a string literal
 * in the shipped JavaScript. Apps that build URLs from parts, read them from a config
 * fetched at startup, or load a lazy chunk after render leave nothing to match. The
 * browser that renders a single-page app sees every request the page actually makes, so
 * the requests it observes are the authoritative list of what the front end calls.
 *
 * Only the shape is kept: method, URL, and the names of a JSON body's keys. Values (a
 * token in a query string, a field in a body) are never stored. Only requests to the
 * site's own hosts, of the fetch or XHR kind, are considered, and anything that looks
 * like an action (delete, logout, checkout) is dropped before it can reach a probe.
 */
import type { ApiEndpoint, ApiParam } from "./apiSurface";
import { isDestructiveUrl } from "./destructive";
import { isFirstParty } from "./sriPolicy";

export interface ObservedRequest {
  method: string;
  url: string;
  /** Names of the keys of a JSON request body, if it had one. Never the values. */
  bodyKeys?: string[];
}

const MAX_OBSERVED = 80;
const NUMERIC_OR_UUID = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

/** /api/users/42 and /api/users/97 are one endpoint. */
const template = (pathname: string) => pathname.split("/").map((s) => (NUMERIC_OR_UUID.test(s) ? "{id}" : s)).join("/");

export function endpointsFromRuntime(observed: ObservedRequest[], origin: string): ApiEndpoint[] {
  let host: string;
  try {
    host = new URL(origin).hostname;
  } catch {
    return [];
  }
  const byKey = new Map<string, ApiEndpoint>();
  for (const req of observed.slice(0, MAX_OBSERVED)) {
    let u: URL;
    try {
      u = new URL(req.url);
    } catch {
      continue;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") continue;
    if (!isFirstParty(host, u.hostname)) continue;
    if (isDestructiveUrl(u.toString())) continue;

    const method = req.method.toUpperCase();
    const key = `${method} ${u.origin}${template(u.pathname)}`;
    const params: ApiParam[] = [
      ...[...new Set(u.searchParams.keys())].map((name): ApiParam => ({ name, location: "query" })),
      ...(req.bodyKeys ?? []).map((name): ApiParam => ({ name, location: "body" })),
    ];
    const existing = byKey.get(key);
    if (existing) {
      // The same endpoint seen twice with different parameters: keep them all.
      const have = new Set(existing.params.map((p) => `${p.location}:${p.name}`));
      for (const p of params) if (!have.has(`${p.location}:${p.name}`)) existing.params.push(p);
      continue;
    }
    // The URL is kept without its query string: parameters are listed separately, and a
    // value in the query (a session id, a token) must not travel into a probe.
    byKey.set(key, { url: `${u.origin}${u.pathname}`, method, params, source: "runtime" });
  }
  return [...byKey.values()];
}

/** The top-level key names of a JSON request body, or none if it is not a JSON object. */
export function jsonBodyKeys(postData: string | null | undefined): string[] {
  if (!postData) return [];
  try {
    const parsed: unknown = JSON.parse(postData);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? Object.keys(parsed).slice(0, 30) : [];
  } catch {
    return [];
  }
}
