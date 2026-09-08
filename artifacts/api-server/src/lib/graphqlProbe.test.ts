import { describe, it, expect, afterEach, vi } from "vitest";
import { runGraphqlProbe } from "./graphqlProbe.js";

/**
 * First tests for this module — nothing reached it before, because its only
 * importer is scanner.ts, which has no test file.
 *
 * Everything here turns on one question: is the thing that answered actually
 * GraphQL? A REST API that returns {"errors":[{"message":"..."}]} is not, and
 * an HTML page that says "did you mean" is not. Getting that wrong would post
 * a High introspection finding against an endpoint that has no schema at all.
 */

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

/** Answers every POST with one body; enough, since all probes are POSTs. */
function answerWith(body: unknown, ct = "application/json", status = 200) {
  globalThis.fetch = (async () =>
    new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": ct },
    })) as typeof fetch;
}

/** A schema big enough to clear the 10-type floor for real introspection. */
const schemaTypes = Array.from({ length: 14 }, (_, i) => ({ name: `Type${i}`, kind: "OBJECT" }));

const EMPTY_PAGE = "<html><body></body></html>";

describe("runGraphqlProbe — confirms a real endpoint", () => {
  it("reports introspection when the schema comes back", async () => {
    answerWith({ data: { __typename: "Query", __schema: { queryType: { name: "Query" }, types: schemaTypes } } });

    const vulns = await runGraphqlProbe("https://example.com/", EMPTY_PAGE);
    expect(vulns.length).toBeGreaterThan(0);
    expect(vulns.some((v) => /introspection/i.test(v.name))).toBe(true);
  });
});

describe("runGraphqlProbe — does not invent one", () => {
  it("ignores a REST API whose errors have no locations array", async () => {
    // The GraphQL spec mandates locations on errors. A REST API returning an
    // errors array is the single most likely thing to be mistaken for GraphQL.
    answerWith({ errors: [{ message: "Invalid request", code: 400 }] });

    expect(await runGraphqlProbe("https://example.com/", EMPTY_PAGE)).toEqual([]);
  });

  it("ignores an HTML error page, whatever it says", async () => {
    answerWith("<html><body><h1>404</h1><p>Did you mean /search?</p></body></html>", "text/html");

    expect(await runGraphqlProbe("https://example.com/", EMPTY_PAGE)).toEqual([]);
  });

  it("ignores JSON that is not a GraphQL response at all", async () => {
    answerWith({ status: "ok", data: { items: [] } });

    expect(await runGraphqlProbe("https://example.com/", EMPTY_PAGE)).toEqual([]);
  });

  it("does not call a short type list real introspection", async () => {
    // A stub or a partial response is not a live schema; the floor is 10 types.
    answerWith({ data: { __typename: "Query", __schema: { types: [{ name: "Query" }, { name: "String" }] } } });

    const vulns = await runGraphqlProbe("https://example.com/", EMPTY_PAGE);
    expect(vulns.some((v) => /introspection/i.test(v.name))).toBe(false);
  });

  it("reports nothing when every candidate path 404s", async () => {
    globalThis.fetch = (async () => new Response("Not Found", { status: 404 })) as typeof fetch;

    expect(await runGraphqlProbe("https://example.com/", EMPTY_PAGE)).toEqual([]);
  });

  it("returns nothing for a URL it cannot parse", async () => {
    answerWith({ data: { __typename: "Query" } });
    expect(await runGraphqlProbe("not a url", EMPTY_PAGE)).toEqual([]);
  });
});

describe("runGraphqlProbe — field suggestions", () => {
  it("needs a GraphQL error shape, not just the words", async () => {
    // "Did you mean" inside a plain JSON error is not evidence of a schema.
    answerWith({ errors: [{ message: 'Cannot query field "x". Did you mean "y"?' }] });

    expect(await runGraphqlProbe("https://example.com/", EMPTY_PAGE)).toEqual([]);
  });
});
