/**
 * Fixture routes for the GraphQL batching and IDE checks (graphqlExtra.ts).
 *
 *   POST /graphql       (server.ts) also runs an array of operations  VULNERABLE (batching)
 *   GET  /graphiql      serves the GraphiQL page                      VULNERABLE (exposed IDE)
 *   POST /api/graphql   a real GraphQL endpoint that refuses arrays   clean twin (no batching, no IDE)
 */
import type { Express } from "express";

export const GRAPHIQL_HTML = `<!doctype html><html><head><title>GraphiQL</title><script src="/static/graphiql.min.js"></script></head><body><div id="graphiql">Loading…</div></body></html>`;

export function mountGraphqlExtras(app: Express): void {
  app.get("/graphiql", (_req, res) => { res.type("text/html").send(GRAPHIQL_HTML); });
  app.post("/api/graphql", (req, res) => {
    if (Array.isArray(req.body)) {
      res.status(400).json({ errors: [{ message: "Batching is not enabled", locations: [{ line: 1, column: 1 }] }] });
      return;
    }
    const query = String(req.body?.query ?? "");
    if (/__schema/.test(query)) { res.json({ errors: [{ message: "Introspection is disabled", locations: [{ line: 1, column: 3 }] }] }); return; }
    res.json({ data: { __typename: "Query" } });
  });
}
