import { describe, it, expect } from "vitest";
import { runApiDocsProbe } from "./apiDocsProbe.js";
import { useRouteSite } from "./routeSite.testkit";

// The site is a real web server on loopback (lib/routeSite.testkit.ts); what it serves at each path is set per test.
const site = await useRouteSite();

/**
 * First tests for this module. Its only importer is scanner.ts, which has no
 * test file, so nothing reached it before now.
 *
 * The discriminators here are the interesting part: a page that merely says
 * "swagger" is not a Swagger UI, and JSON with a "paths" key is not an OpenAPI
 * spec. Those guards are what stop a Medium Information Disclosure finding
 * landing on a marketing page, and nothing was holding them in place.
 */

function serve(routes: Record<string, { body: string; status?: number; ct?: string }>) {
  site.routes(routes);
}

const pad = (s: string, n = 400) => s + " ".repeat(Math.max(0, n - s.length));

// Padded past MIN_BODY_BYTES (200), which a real spec comfortably exceeds —
// the check skips thin bodies so an error page cannot pass as a contract.
const realSpec = JSON.stringify({
  openapi: "3.0.0",
  info: { title: "Orders API", version: "1.0.0", description: "Internal order management API for the storefront and fulfilment services." },
  paths: {
    "/orders": { get: { summary: "List orders", parameters: [{ name: "limit", in: "query", schema: { type: "integer" } }] } },
    "/orders/{id}": { get: { summary: "Fetch one order", parameters: [{ name: "id", in: "path", required: true }] } },
    "/customers": { get: { summary: "List customers" }, post: { summary: "Create a customer" } },
  },
});

describe("runApiDocsProbe — confirms a real spec", () => {
  it("reports an OpenAPI 3 document", async () => {
    serve({ "/openapi.json": { body: realSpec } });

    const vulns = await runApiDocsProbe(`${site.origin}/`);
    expect(vulns).toHaveLength(1);
    // A reachable spec is INFO, not a vulnerability: publishing an OpenAPI spec
    // is mainstream intentional practice (Stripe, Vercel, Cloudflare all do it),
    // and the endpoints it documents still enforce their own auth. It is
    // surface disclosure to confirm is intended, not a MEDIUM "exploit your
    // backend" finding — which fired confidently against sites whose specs are
    // a deliberate developer resource.
    expect(vulns[0]!.severity).toBe("info");
    expect(vulns[0]!.cweId).toBe("CWE-200");
    expect(vulns[0]!.name).toMatch(/openapi\.json/);
    expect(vulns[0]!.evidence).toMatch(/spec structure validated/);
  });

  it("reports a Swagger UI page that actually loads the bundle", async () => {
    serve({
      "/swagger-ui.html": {
        body: pad('<html><head><title>API</title></head><body><div id="ui"></div><script src="/swagger-ui-bundle.js"></script></body></html>'),
        ct: "text/html",
      },
    });

    const vulns = await runApiDocsProbe(`${site.origin}/`);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.evidence).toMatch(/UI bundle script detected/);
  });
});

describe("runApiDocsProbe — does not invent one", () => {
  it("ignores a marketing page that merely mentions Swagger", async () => {
    // "We publish Swagger docs for our partners" on a product page is not an
    // exposed documentation UI.
    serve({
      "/swagger-ui.html": {
        body: pad("<html><body><h1>Our API</h1><p>We support Swagger and OpenAPI for integrators. Contact sales about swagger tooling.</p></body></html>"),
        ct: "text/html",
      },
    });

    expect(await runApiDocsProbe(`${site.origin}/`)).toEqual([]);
  });

  it("ignores JSON that happens to contain a paths key", async () => {
    // A build manifest or tsconfig has "paths" and is not an API contract.
    serve({
      "/openapi.json": {
        body: pad(JSON.stringify({ compilerOptions: { paths: { "@/*": ["src/*"] } }, info: { name: "app" } })),
      },
    });

    expect(await runApiDocsProbe(`${site.origin}/`)).toEqual([]);
  });

  it("ignores a spec-shaped document with no version field", async () => {
    serve({
      "/openapi.json": {
        body: pad(JSON.stringify({ info: { title: "x" }, paths: { "/a": {} } })),
      },
    });

    expect(await runApiDocsProbe(`${site.origin}/`)).toEqual([]);
  });

  it("ignores the SPA catch-all shell served at every path", async () => {
    // The app answers 200 with its shell for anything, including the random
    // nonce path detectCatchAll probes first.
    const shell = pad("<!doctype html><html><head><title>Dashboard</title></head><body><div id=root></div></body></html>", 800);
    site.otherwise(() => ({ body: shell, ct: "text/html" }));

    expect(await runApiDocsProbe(`${site.origin}/`)).toEqual([]);
  });

  it("ignores a thin response below the minimum body size", async () => {
    serve({ "/openapi.json": { body: '{"openapi":"3.0.0","info":{},"paths":{}}' } });

    expect(await runApiDocsProbe(`${site.origin}/`)).toEqual([]);
  });

  it("reports nothing when every documentation path 404s", async () => {
    serve({});
    expect(await runApiDocsProbe(`${site.origin}/`)).toEqual([]);
  });

  it("returns nothing for a URL it cannot parse", async () => {
    serve({});
    expect(await runApiDocsProbe("not a url")).toEqual([]);
  });
});
