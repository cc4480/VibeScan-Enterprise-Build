/**
 * Which discovered endpoints an ACTIVE probe may send a POST to.
 *
 * promptInjectionProbe.ts and raceConditionProbe.ts send real, state-changing requests with the
 * scan's signed-in session. Reviewers found they picked their targets carelessly:
 *
 *   - The route regex ran over the WHOLE url, host included, so any endpoint on promo.acme.com,
 *     claim.acme.com or chat.acme.com matched, and the first three discovered endpoints, whatever
 *     they were (/api/account/delete, /api/logout), received five concurrent POSTs.
 *   - Neither probe applied the destructive-URL guard every other signed-in probe applies, so
 *     /api/chat/clear and /api/coupon/remove were fair game.
 *   - Endpoints from a target's OpenAPI document are used verbatim, servers[0].url included, so a
 *     spec that declares https://api.openai.com/v1 put a third party's chat endpoint in the list.
 *   - Placeholder URLs from a spec or bundle (/api/coupons/{id}/redeem) were POSTed literally.
 *   - The method a spec declared was ignored.
 *
 * This is the one place those rules live. A probe passes what discovery found and a matcher for
 * the routes it wants; what comes back is safe to POST to.
 */
import { isDestructiveUrl } from "./destructive";
import { getScanHttpContext } from "./http";

/** The parts of an ApiEndpoint the probes care about. Plain strings are accepted for callers with only a URL. */
export interface EndpointRef {
  url: string;
  method?: string;
  source?: "spec" | "bundle" | "runtime";
  params?: Array<{ name: string; location: string }>;
}
export type EndpointInput = string | EndpointRef;

const asRef = (e: EndpointInput): EndpointRef => (typeof e === "string" ? { url: e } : e);

/** Lower-cased, with "-" and "_" removed, so chat_stream, chat-stream and chatStream agree. */
const norm = (segment: string): string => segment.toLowerCase().replace(/[-_]/g, "");

/**
 * The last two path segments, normalised, of a URL. The host is never consulted: a route is what
 * its path says, not what its subdomain is called.
 */
export function pathLeaf(url: string): { leaf: string; parent: string } {
  let pathname: string;
  try {
    pathname = new URL(url).pathname;
  } catch {
    return { leaf: "", parent: "" };
  }
  const segments = pathname.split("/").filter(Boolean).map((s) => {
    try { return decodeURIComponent(s); } catch { return s; }
  });
  return { leaf: norm(segments.at(-1) ?? ""), parent: norm(segments.at(-2) ?? "") };
}

/**
 * Endpoints that pass every gate, each URL once. Fails closed outside a scan: with no context
 * there is no target to be in scope of, and an active probe must not guess one.
 */
export function actableEndpoints(
  endpoints: EndpointInput[],
  matchesRoute: (url: string) => boolean,
): EndpointRef[] {
  const scope = getScanHttpContext()?.scope;
  if (!scope) return [];

  const seen = new Set<string>();
  const out: EndpointRef[] = [];
  for (const raw of endpoints) {
    const ref = asRef(raw);
    if (!ref.url || seen.has(ref.url)) continue;
    let parsed: URL;
    try {
      parsed = new URL(ref.url);
    } catch {
      continue;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") continue;
    // A placeholder means the real id is unknown; POSTing "{id}" tests nothing and may create junk.
    if (/[{}]|\$\{/.test(decodeURIComponentSafe(ref.url))) continue;
    if (!scope.includes(ref.url)) continue;
    if (isDestructiveUrl(ref.url)) continue;
    // A spec or a runtime observation states the method; a bare string in a bundle is only a guess.
    const declared = ref.source === "spec" || ref.source === "runtime";
    if (declared && (ref.method ?? "POST").toUpperCase() !== "POST") continue;
    if (!matchesRoute(ref.url)) continue;
    seen.add(ref.url);
    out.push(ref);
  }
  return out;
}

function decodeURIComponentSafe(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}
