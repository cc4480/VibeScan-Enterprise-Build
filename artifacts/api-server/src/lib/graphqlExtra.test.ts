import { describe, it, expect, afterEach } from "vitest";
import type http from "node:http";
import { probeBatching, probeIde, isBatchedResponse, ideName } from "./graphqlExtra";
import { serve, closeServers, readBody } from "./testkit";

// Real servers on loopback: the probe goes through the real scan HTTP layer to a real peer.
afterEach(closeServers);

const json = (res: http.ServerResponse, status: number, body: string, ct = "application/json") => {
  res.writeHead(status, { "content-type": ct });
  res.end(body);
};

describe("query batching", () => {
  it("flags a server that answers an array of three with an array of three results", async () => {
    const port = await serve(async (req, res) => {
      const sent = JSON.parse((await readBody(req)) || "null");
      json(res, 200, JSON.stringify(Array.isArray(sent) ? sent.map(() => ({ data: { __typename: "Query" } })) : { data: { __typename: "Query" } }));
    });
    expect((await probeBatching(`http://127.0.0.1:${port}/graphql`))?.name).toBe("GraphQL Query Batching Enabled");
  });

  it("clean twin: a server that refuses arrays", async () => {
    const port = await serve((_req, res) => json(res, 400, JSON.stringify({ errors: [{ message: "Batching is not enabled" }] })));
    expect(await probeBatching(`http://127.0.0.1:${port}/graphql`)).toBeNull();
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
    // A port that was open and is now closed: the connection is genuinely refused.
    const port = await serve((_req, res) => res.end());
    await closeServers();
    expect(await probeBatching(`http://127.0.0.1:${port}/graphql`)).toBeNull();
  });
});

describe("exposed IDE", () => {
  const graphiql = '<html><head><title>GraphiQL</title><script src="/static/graphiql.min.js"></script></head></html>';

  it("flags a public GraphiQL and names it", async () => {
    const port = await serve((req, res) => (req.url?.split("?")[0] === "/graphiql" ? json(res, 200, graphiql, "text/html") : json(res, 404, "", "text/html")));
    const f = await probeIde(`http://127.0.0.1:${port}`);
    expect(f?.name).toBe("GraphQL IDE Exposed");
    expect(f?.evidence).toContain("GraphiQL");
  });

  it("clean twin: a single-page app that answers every path with its own shell", async () => {
    const port = await serve((_req, res) => json(res, 200, '<html><title>My App</title><div id="root"></div></html>', "text/html"));
    expect(await probeIde(`http://127.0.0.1:${port}`)).toBeNull();
  });

  it("ignores a 200 that is not HTML", async () => {
    const port = await serve((_req, res) => json(res, 200, graphiql, "application/json"));
    expect(await probeIde(`http://127.0.0.1:${port}`)).toBeNull();
  });

  it("ignores a 404 page, however much it looks like an IDE", async () => {
    const port = await serve((_req, res) => json(res, 404, graphiql, "text/html"));
    expect(await probeIde(`http://127.0.0.1:${port}`)).toBeNull();
  });

  it("recognises each IDE by its own name and nothing else", () => {
    expect(ideName("<title>GraphQL Playground</title>")).toBe("GraphQL Playground");
    expect(ideName('<script src="https://sandbox.embed.apollographql.com/embed.js">')).toBe("Apollo Sandbox");
    expect(ideName("<title>Altair GraphQL Client</title>")).toBe("Altair");
    expect(ideName("A blog post about GraphiQL and Playground")).toBeNull();
  });
});
