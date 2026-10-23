/**
 * Two more GraphQL checks, each confirmed by what the server literally returns:
 *
 *  QUERY BATCHING. Some servers accept a JSON array of operations in one HTTP request.
 *  Rate limits and lockouts that count requests then see one request carrying hundreds
 *  of operations, so a login mutation can be tried many times per request. Confirmed
 *  only when three harmless { __typename } operations sent as an array come back as an
 *  array of three results, each holding __typename. A server that refuses arrays
 *  answers with an error object, which is "not enabled".
 *
 *  EXPOSED IDE. GraphiQL, GraphQL Playground, Apollo Sandbox and Altair served from a
 *  public path give every visitor a ready-made client for the API and, when
 *  introspection is on, its documentation. Confirmed by the IDE's own page: an HTML
 *  response carrying its unmistakable name or embed host. A single-page app's catch-all
 *  page does not carry those, so it is not mistaken for one.
 *
 * Detection only: __typename is a meta-field that names a type and reads no data.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";

const TIMEOUT_MS = 8_000;
const vuln = (partial: Omit<ScanVulnerability, "id">): ScanVulnerability => ({ id: randomUUID(), ...partial });

/** Three typename operations as an array. Exported for the tests. */
export const BATCH_BODY = [1, 2, 3].map(() => ({ query: "{ __typename }" }));

export function isBatchedResponse(text: string): boolean {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return false; }
  if (!Array.isArray(j) || j.length !== 3) return false;
  return j.every((r) => {
    const data = (r as { data?: { __typename?: unknown } } | null)?.data;
    return typeof data?.__typename === "string" && data.__typename.length > 0;
  });
}

export async function probeBatching(url: string): Promise<ScanVulnerability | null> {
  const res = await scanFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(BATCH_BODY),
    timeoutMs: TIMEOUT_MS,
  });
  if (!res || !isBatchedResponse(res.body)) return null;
  const path = (() => { try { return new URL(url).pathname; } catch { return url; } })();
  return vuln({
    name: "GraphQL Query Batching Enabled",
    severity: "low",
    category: "API Security",
    description:
      `The GraphQL endpoint at ${path} accepts an array of operations in a single request and runs all of them. ` +
      "Rate limits and lockouts that count HTTP requests then see one request however many operations it carries, so an " +
      "attacker can try many passwords or codes in one call. Batching is legitimate for some clients; if none of yours " +
      "needs it, turn it off, and either way limit the number of operations per request.",
    evidence: `POST ${url}\n[{"query":"{ __typename }"} × 3]\nHTTP ${res.status} — an array of 3 results, each with __typename`,
    solution:
      "Disable HTTP batching (Apollo Server: allowBatchedHttpRequests: false, the default in v4), or cap the batch size, " +
      "and rate-limit by operation and by account rather than by request.",
    cweId: "CWE-770",
    cvssScore: 3.7,
    wstgId: "WSTG-BUSL-05",
    confidence: 95,
  });
}

const IDE_PATHS = ["/graphiql", "/playground", "/altair", "/api/graphiql", "/graphql/playground", "/explorer", "/sandbox", "/graphql"];

/** The IDE a page is, judged only by its own name or embed host. */
export function ideName(body: string): string | null {
  if (/<title>\s*GraphiQL\s*<\/title>|graphiql\.(?:min\.)?(?:js|css)|GraphiQL\.createFetcher|id=["']graphiql["']/i.test(body)) return "GraphiQL";
  if (/<title>\s*GraphQL Playground\s*<\/title>|graphql-playground-react|GraphQLPlayground\.init/i.test(body)) return "GraphQL Playground";
  if (/sandbox\.embed\.apollographql\.com|<title>\s*Apollo Sandbox|ApolloSandbox\s*\(/i.test(body)) return "Apollo Sandbox";
  if (/<title>\s*Altair(?: GraphQL Client)?\s*<\/title>|altair-graphql-client|AltairGraphQL\.init/i.test(body)) return "Altair";
  return null;
}

export async function probeIde(origin: string): Promise<ScanVulnerability | null> {
  for (const path of IDE_PATHS) {
    const url = `${origin}${path}`;
    const res = await scanFetch(url, { headers: { Accept: "text/html" }, timeoutMs: TIMEOUT_MS });
    if (!res || res.status !== 200 || !(res.headers["content-type"] ?? "").includes("html")) continue;
    const ide = ideName(res.body);
    if (!ide) continue;
    return vuln({
      name: "GraphQL IDE Exposed",
      severity: "medium",
      category: "API Security",
      description:
        `${ide} is served publicly at ${path}. It is a ready-made client for your GraphQL API that any visitor can open, and with ` +
        "introspection enabled it also documents every type and field. Development tools belong in development.",
      evidence: `GET ${url}\nHTTP 200, text/html, the page is ${ide}`,
      solution:
        "Disable the IDE in production (Apollo Server: use the landing page plugin only in development; GraphQL Yoga: graphiql: false; " +
        "Hasura: HASURA_GRAPHQL_ENABLE_CONSOLE=false), or put it behind authentication.",
      cweId: "CWE-489",
      cvssScore: 5.3,
      wstgId: "WSTG-CONF-05",
      confidence: 95,
    });
  }
  return null;
}
