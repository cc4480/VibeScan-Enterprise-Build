/** Finding a site's own GraphQL endpoints in its JavaScript. */
// ─────────────────────────────────────────────────────────────────────────────
// ENDPOINT DISCOVERY
// ─────────────────────────────────────────────────────────────────────────────

// Only paths that are specifically GraphQL — no /api or /query (too generic).
// /api/query is included because it requires both segments.
export const GRAPHQL_SPECIFIC_PATHS = [
  "/graphql",
  "/api/graphql",
  "/v1/graphql",       // Hasura
  "/graphql/v1",
  "/graphql/v2",
];

/** Hosts many unrelated customers share; a sibling subdomain there is NOT the same site. */
export const SHARED_SUFFIXES = [
  "vercel.app", "netlify.app", "herokuapp.com", "github.io", "pages.dev", "workers.dev",
  "web.app", "firebaseapp.com", "onrender.com", "fly.dev", "azurewebsites.net", "appspot.com",
  "amazonaws.com", "cloudfront.net", "railway.app", "supabase.co", "glitch.me", "repl.co",
];

/** Registrable-domain guess: last two labels, three under a two-letter ccTLD's second level (co.uk). */
export function siteOf(host: string): string {
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

export function extractGraphqlUrlsFromJs(html: string, origin: string): string[] {
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
