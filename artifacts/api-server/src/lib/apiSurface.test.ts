import { describe, it, expect } from "vitest";
import { endpointsFromSpec, endpointsFromBundle, mergeEndpoints } from "./apiSurface.js";

const ORIGIN = "https://app.example";

describe("endpointsFromSpec", () => {
  const openapi = JSON.stringify({
    openapi: "3.0.0",
    servers: [{ url: "/api/v1" }],
    paths: {
      "/users/{userId}": {
        get: {
          parameters: [
            { name: "userId", in: "path" },
            { name: "expand", in: "query" },
          ],
        },
        delete: { parameters: [{ name: "userId", in: "path" }] },
      },
      "/orders": {
        post: {
          requestBody: {
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Order" },
              },
            },
          },
        },
      },
    },
    components: {
      schemas: {
        Order: { type: "object", properties: { itemId: {}, quantity: {}, couponCode: {} } },
      },
    },
  });

  it("finds every declared operation", () => {
    const found = endpointsFromSpec(openapi, ORIGIN);
    expect(found.map((e) => `${e.method} ${e.url}`).sort()).toEqual([
      "DELETE https://app.example/api/v1/users/{userId}",
      "GET https://app.example/api/v1/users/{userId}",
      "POST https://app.example/api/v1/orders",
    ]);
  });

  it("applies a relative server URL as the base path", () => {
    expect(endpointsFromSpec(openapi, ORIGIN)[0]!.url).toContain("/api/v1/");
  });

  it("reads query and path parameters", () => {
    const get = endpointsFromSpec(openapi, ORIGIN).find((e) => e.method === "GET")!;
    expect(get.params).toEqual(
      expect.arrayContaining([
        { name: "userId", location: "path" },
        { name: "expand", location: "query" },
      ]),
    );
  });

  it("follows a $ref to recover request body fields", () => {
    const post = endpointsFromSpec(openapi, ORIGIN).find((e) => e.method === "POST")!;
    expect(post.params).toEqual(
      expect.arrayContaining([
        { name: "itemId", location: "body" },
        { name: "quantity", location: "body" },
        { name: "couponCode", location: "body" },
      ]),
    );
  });

  it("handles Swagger 2 basePath", () => {
    const swagger = JSON.stringify({
      swagger: "2.0",
      basePath: "/v2",
      paths: { "/pets": { get: {} } },
    });
    expect(endpointsFromSpec(swagger, ORIGIN)[0]!.url).toBe("https://app.example/v2/pets");
  });

  it("recovers path parameters that were never declared", () => {
    const spec = JSON.stringify({ openapi: "3.0.0", paths: { "/a/{id}/b/{sub}": { get: {} } } });
    expect(endpointsFromSpec(spec, ORIGIN)[0]!.params).toEqual([
      { name: "id", location: "path" },
      { name: "sub", location: "path" },
    ]);
  });

  it("falls back to pattern extraction for a YAML spec", () => {
    const yaml = [
      "openapi: 3.0.0",
      "paths:",
      "  /invoices:",
      "    get:",
      "      summary: list",
      "    post:",
      "      summary: create",
      "  /invoices/{id}:",
      "    get:",
      "      summary: read",
      "components:",
      "  schemas: {}",
    ].join("\n");

    const found = endpointsFromSpec(yaml, ORIGIN);
    expect(found.map((e) => `${e.method} ${e.url}`).sort()).toEqual([
      "GET https://app.example/invoices",
      "GET https://app.example/invoices/{id}",
      "POST https://app.example/invoices",
    ]);
    expect(found.find((e) => e.url.endsWith("{id}"))!.params).toEqual([
      { name: "id", location: "path" },
    ]);
  });

  it("returns nothing for a document with no paths", () => {
    expect(endpointsFromSpec(JSON.stringify({ openapi: "3.0.0" }), ORIGIN)).toEqual([]);
    expect(endpointsFromSpec("not a spec at all", ORIGIN)).toEqual([]);
  });

  it("ignores keys under paths that are not HTTP methods", () => {
    const spec = JSON.stringify({
      openapi: "3.0.0",
      paths: { "/x": { get: {}, summary: "desc", parameters: [] } },
    });
    expect(endpointsFromSpec(spec, ORIGIN)).toHaveLength(1);
  });
});

describe("endpointsFromBundle", () => {
  it("finds API paths in string literals", () => {
    const js = `const a="/api/scans";const b='/api/auth/user';const c=\`/api/reports\`;`;
    const urls = endpointsFromBundle(js, ORIGIN).map((e) => e.url);
    expect(urls).toEqual(
      expect.arrayContaining([
        "https://app.example/api/scans",
        "https://app.example/api/auth/user",
        "https://app.example/api/reports",
      ]),
    );
  });

  it("normalises template placeholders into path parameters", () => {
    const js = 'fetch(`/api/scans/${scanId}/status`)';
    const found = endpointsFromBundle(js, ORIGIN);
    expect(found[0]!.url).toBe("https://app.example/api/scans/{id}/status");
    expect(found[0]!.params).toEqual([{ name: "id", location: "path" }]);
  });

  it("normalises express-style :params", () => {
    const js = 'const r="/api/users/:userId/orders"';
    expect(endpointsFromBundle(js, ORIGIN)[0]!.url).toBe(
      "https://app.example/api/users/{userId}/orders",
    );
  });

  it("picks up fetch and axios calls without an /api prefix", () => {
    const js = 'fetch("/graphql");axios.post("/v2/checkout");axios.get("/session")';
    const urls = endpointsFromBundle(js, ORIGIN).map((e) => e.url);
    expect(urls).toEqual(
      expect.arrayContaining([
        "https://app.example/graphql",
        "https://app.example/v2/checkout",
        "https://app.example/session",
      ]),
    );
  });

  it("never returns another origin's API", () => {
    const js = '"https://evil.example/api/steal";"https://app.example/api/mine"';
    const urls = endpointsFromBundle(js, ORIGIN).map((e) => e.url);
    expect(urls).toEqual(["https://app.example/api/mine"]);
  });

  it("ignores static assets that happen to match", () => {
    const js = '"/api/thing.js";"/api/data.json";"/api/logo.svg";"/api/real"';
    expect(endpointsFromBundle(js, ORIGIN).map((e) => e.url)).toEqual([
      "https://app.example/api/real",
    ]);
  });

  it("extracts query parameters written into the literal", () => {
    const js = '"/api/search?q=&page="';
    const found = endpointsFromBundle(js, ORIGIN)[0]!;
    expect(found.url).toBe("https://app.example/api/search");
    expect(found.params).toEqual(
      expect.arrayContaining([
        { name: "q", location: "query" },
        { name: "page", location: "query" },
      ]),
    );
  });

  it("assumes GET, the only verb safe to guess at on a live API", () => {
    expect(endpointsFromBundle('"/api/orders"', ORIGIN)[0]!.method).toBe("GET");
  });

  it("returns nothing for a bundle with no endpoints", () => {
    expect(endpointsFromBundle("const x=1;function y(){}", ORIGIN)).toEqual([]);
  });
});

describe("mergeEndpoints", () => {
  it("prefers the spec entry, which carries declared parameters", () => {
    const spec = endpointsFromSpec(
      JSON.stringify({
        openapi: "3.0.0",
        paths: { "/api/scans": { get: { parameters: [{ name: "limit", in: "query" }] } } },
      }),
      ORIGIN,
    );
    const bundle = endpointsFromBundle('"/api/scans"', ORIGIN);

    const merged = mergeEndpoints(bundle, spec);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.source).toBe("spec");
    expect(merged[0]!.params).toEqual([{ name: "limit", location: "query" }]);
  });

  it("keeps endpoints only one source knows about", () => {
    const spec = endpointsFromSpec(
      JSON.stringify({ openapi: "3.0.0", paths: { "/api/admin": { get: {} } } }),
      ORIGIN,
    );
    const bundle = endpointsFromBundle('"/api/public"', ORIGIN);
    expect(mergeEndpoints(spec, bundle)).toHaveLength(2);
  });

  it("treats different methods on one path as different endpoints", () => {
    const spec = endpointsFromSpec(
      JSON.stringify({ openapi: "3.0.0", paths: { "/api/x": { get: {}, post: {} } } }),
      ORIGIN,
    );
    expect(mergeEndpoints(spec)).toHaveLength(2);
  });
});

describe("endpointsFromBundle — deduplication", () => {
  it("collapses the same path seen with and without a query string", () => {
    // Minified bundles reference one handler several ways; two entries for one
    // endpoint would double the request budget spent on it.
    const js = '"/api/dismissals";"/api/dismissals?targetUrl="';
    const found = endpointsFromBundle(js, ORIGIN);
    expect(found).toHaveLength(1);
    expect(found[0]!.params).toEqual([{ name: "targetUrl", location: "query" }]);
  });

  it("gives repeated placeholders distinct names", () => {
    // /a/{id}/b/{id} would be ambiguous to substitute into.
    const js = "fetch(`/api/reports/${reportId}/shares/${shareId}`)";
    const found = endpointsFromBundle(js, ORIGIN)[0]!;
    expect(found.url).toBe("https://app.example/api/reports/{id}/shares/{id2}");
    expect(found.params.map((p) => p.name)).toEqual(["id", "id2"]);
  });
});
