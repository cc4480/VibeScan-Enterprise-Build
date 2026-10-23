/** API surface discovery from bundles and published specs. */
import { scanFetch, getScanHttpContext, ScanScope, type ScanCredentials } from "./http";
import { endpointsFromSpec, endpointsFromBundle, mergeEndpoints, type ApiEndpoint } from "./apiSurface";
import { endpointsFromRuntime, type ObservedRequest } from "./apiRuntime";
import { collectJavaScript } from "./jsScanner";
import { TIMEOUT_MS, PATH_PARAM_VALUE } from "./apiProbeHelpers";

/** Issue one request with `value` placed wherever the parameter lives. */
export async function requestWith(
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
export const SPEC_PATHS = [
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
  observed: ObservedRequest[] = [],
): Promise<ApiEndpoint[]> {
  const [specEndpoints, bundleEndpoints] = await Promise.all([
    (async () => {
      for (const path of SPEC_PATHS) {
        const res = await scanFetch(`${origin}${path}`, { timeoutMs: TIMEOUT_MS });
        if (!res || res.status < 200 || res.status >= 300) continue;
        // Cheap structural check before parsing — a SPA catch-all returns 200
        // with HTML for any path, and parsing that wastes the budget.
        if (!/"(openapi|swagger)"\s*:|^\s*(openapi|swagger):/m.test(res.body)) continue;
        // A spec's servers[0].url is used verbatim, so a target's own /openapi.json can name any host. Bundle
        // endpoints were already limited to the target (endpointsFromBundle); spec endpoints get the same rule,
        // the scan's own scope, or a probe would send real requests to a third party on the target's say-so.
        const scope = getScanHttpContext()?.scope ?? new ScanScope(origin);
        const found = endpointsFromSpec(res.body, origin).filter((e) => scope.includes(e.url));
        if (found.length > 0) return found;
      }
      return [] as ApiEndpoint[];
    })().catch(() => [] as ApiEndpoint[]),

    (async () => {
      const js = await collectJavaScript(html, origin);
      return js ? endpointsFromBundle(js, origin) : [];
    })().catch(() => [] as ApiEndpoint[]),
  ]);

  // Runtime last: a bundle or spec entry for the same endpoint carries better parameters.
  return mergeEndpoints(bundleEndpoints, specEndpoints, endpointsFromRuntime(observed, origin));
}
