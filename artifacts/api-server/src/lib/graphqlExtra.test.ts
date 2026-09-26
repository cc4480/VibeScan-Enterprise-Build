import { describe, it, expect, vi, afterEach } from "vitest";

const fetchMock = vi.fn();
vi.mock("./http", () => ({ scanFetch: (...a: unknown[]) => fetchMock(...a) }));
import { probeBatching, probeIde, isBatchedResponse, ideName } from "./graphqlExtra";

afterEach(() => fetchMock.mockReset());
const ok = (body: string, ct = "application/json") => ({ status: 200, body, headers: { "content-type": ct } });

describe("query batching", () => {
  it("flags a server that answers an array of three with an array of three results", async () => {
    fetchMock.mockResolvedValue(ok(JSON.stringify([1, 2, 3].map(() => ({ data: { __typename: "Query" } })))));
    expect((await probeBatching("https://x.com/graphql"))?.name).toBe("GraphQL Query Batching Enabled");
  });
  it("clean twin: a server that refuses arrays", async () => {
    fetchMock.mockResolvedValue({ status: 400, body: JSON.stringify({ errors: [{ message: "Batching is not enabled" }] }), headers: { "content-type": "application/json" } });
    expect(await probeBatching("https://x.com/graphql")).toBeNull();
  });
  it("only accepts a full, well-formed batch", () => {
    const one = { data: { __typename: "Query" } };
    expect(isBatchedResponse(JSON.stringify([one, one, one]))).toBe(true);
    expect(isBatchedResponse(JSON.stringify([one, one]))).toBe(false);
    expect(isBatchedResponse(JSON.stringify([one, one, { errors: [] }]))).toBe(false);
    expect(isBatchedResponse(JSON.stringify(one))).toBe(false);
    expect(isBatchedResponse("nope")).toBe(false);
  });
  it("treats a network failure as nothing found", async () => {
    fetchMock.mockResolvedValue(null);
    expect(await probeBatching("https://x.com/graphql")).toBeNull();
  });
});

describe("exposed IDE", () => {
  const graphiql = '<html><head><title>GraphiQL</title><script src="/static/graphiql.min.js"></script></head></html>';
  it("flags a public GraphiQL and names it", async () => {
    fetchMock.mockImplementation(async (url: string) => (url.endsWith("/graphiql") ? ok(graphiql, "text/html") : { status: 404, body: "", headers: {} }));
    const f = await probeIde("https://x.com");
    expect(f?.name).toBe("GraphQL IDE Exposed");
    expect(f?.evidence).toContain("GraphiQL");
  });
  it("clean twin: a single-page app that answers every path with its own shell", async () => {
    fetchMock.mockResolvedValue(ok('<html><title>My App</title><div id="root"></div></html>', "text/html"));
    expect(await probeIde("https://x.com")).toBeNull();
  });
  it("ignores a 200 that is not HTML, and a 404 page", async () => {
    fetchMock.mockResolvedValue(ok(graphiql, "application/json"));
    expect(await probeIde("https://x.com")).toBeNull();
    fetchMock.mockResolvedValue({ status: 404, body: graphiql, headers: { "content-type": "text/html" } });
    expect(await probeIde("https://x.com")).toBeNull();
  });
  it("recognises each IDE by its own name and nothing else", () => {
    expect(ideName("<title>GraphQL Playground</title>")).toBe("GraphQL Playground");
    expect(ideName('<script src="https://sandbox.embed.apollographql.com/embed.js">')).toBe("Apollo Sandbox");
    expect(ideName("<title>Altair GraphQL Client</title>")).toBe("Altair");
    expect(ideName("A blog post about GraphiQL and Playground")).toBeNull();
  });
});
