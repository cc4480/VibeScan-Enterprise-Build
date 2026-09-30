import { serve, SESSION, DATA, ep } from "./apiProbe.testkit";
import { describe, it, expect } from "vitest";
import http from "node:http";
import { runWithScanHttp } from "./http.js";
import { runApiProbes, exposedSensitiveFields, privilegeFieldsAccepted } from "./apiProbe.js";

describe("excessive data exposure", () => {
  it("names sensitive fields anywhere in the response", () => {
    const body = JSON.stringify({
      items: [{ id: 1, email: "a@b.c", password_hash: "x", profile: { ssn: "1" } }],
    });
    expect(exposedSensitiveFields(body).sort()).toEqual(["password_hash", "ssn"]);
  });

  it("says nothing about an ordinary response", () => {
    expect(exposedSensitiveFields(JSON.stringify({ id: 1, name: "Ada", total: 5040 }))).toEqual([]);
  });

  it("ignores a body that is not JSON", () => {
    expect(exposedSensitiveFields("<html><body>password</body></html>")).toEqual([]);
  });

  it("reports it end to end", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ user: { id: 1, email: "ada@example.com", passwordHash: "$2b$x" } }));
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/me` })],
        credentials: SESSION,
      }),
    );
    expect(findings.some((f) => /Sensitive Fields/i.test(f.name))).toBe(true);
  });
});

describe("mass assignment", () => {
  it("flags privilege-bearing body fields the contract declares", () => {
    const endpoint = ep({
      url: "https://a.example/api/users",
      method: "POST",
      params: [
        { name: "email", location: "body" },
        { name: "role", location: "body" },
        { name: "is_admin", location: "body" },
      ],
    });
    expect(privilegeFieldsAccepted(endpoint).sort()).toEqual(["is_admin", "role"]);
  });

  it("ignores ordinary fields and query parameters", () => {
    expect(
      privilegeFieldsAccepted(
        ep({
          url: "https://a.example/api/users",
          params: [
            { name: "email", location: "body" },
            { name: "role", location: "query" },
          ],
        }),
      ),
    ).toEqual([]);
  });
});

describe("write-verb authorisation", () => {
  it("reports a handler that looks the record up before checking the caller", async () => {
    const seen: string[] = [];
    const port = await serve((req, res) => {
      seen.push(`${req.method} ${req.url}`);
      // The bug: no auth check, and the delete is idempotent, so a missing record is accepted
      // rather than refused with 401.
      res.writeHead(req.method === "DELETE" ? 204 : 404, { "content-type": "application/json" });
      res.end();
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders/{id}` })],
        credentials: SESSION,
      }),
    );

    expect(findings.some((f) => /Write Endpoints Reachable/i.test(f.name))).toBe(true);
    // Aimed only at an identifier nothing can exist at.
    expect(seen.filter((s) => s.startsWith("DELETE"))).toEqual([
      "DELETE /api/orders/999999997",
    ]);
    expect(seen.some((s) => s.startsWith("PUT"))).toBe(false);
  });

  it.each([
    ["Express's default answer for a verb nobody routed", 404, "text/html", "<pre>Cannot DELETE /api/orders/999999997</pre>"],
    ["a JSON not-found from a router with no such handler", 404, "application/json", '{"error":"not found"}'],
    ["a 405", 405, "application/json", '{"error":"method not allowed"}'],
    ["a body-parser 400 before any handler", 400, "application/json", '{"error":"Unexpected token } in JSON"}'],
  ])("stays quiet for %s", async (_l, status, type, body) => {
    // Clean twin. Any unrouted verb answers like this, so it cannot show that a handler ran
    // without asking who was calling; it used to be reported as a CRITICAL.
    const port = await serve((req, res) => {
      if (req.method === "DELETE" || req.method === "PATCH") {
        res.writeHead(status, { "content-type": type });
        res.end(body);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders/{id}` })],
        credentials: SESSION,
      }),
    );
    expect(findings.some((f) => /Write Endpoints Reachable/i.test(f.name))).toBe(false);
  });

  it("reports a handler that got as far as validating an unauthenticated PATCH", async () => {
    const port = await serve((req, res) => {
      if (req.method === "PATCH") {
        res.writeHead(422, { "content-type": "application/json" });
        res.end('{"error":"Validation failed: name is required"}');
        return;
      }
      res.writeHead(req.method === "DELETE" ? 404 : 200, { "content-type": "application/json" });
      res.end(req.method === "DELETE" ? '{"error":"not found"}' : DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders/{id}` })],
        credentials: SESSION,
      }),
    );
    const f = findings.find((x) => /Write Endpoints Reachable/i.test(x.name));
    expect(f).toBeDefined();
    expect(f!.evidence).toContain("PATCH /api/orders/999999997 -> 422");
  });

  it("stays quiet when the write verb is properly refused", async () => {
    const port = await serve((req, res) => {
      if (req.method === "DELETE" || req.method === "PATCH") {
        res.writeHead(401);
        res.end('{"error":"unauthorized"}');
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders/{id}` })],
        credentials: SESSION,
      }),
    );
    expect(findings.some((f) => /Write Endpoints Reachable/i.test(f.name))).toBe(false);
  });
});

describe("rate limiting", () => {
  it("notes a sensitive endpoint that never throttles a burst, as an observation", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/auth/verify-code` })] }),
    );
    const f = findings.find((x) => /Rate Limiting/i.test(x.name));
    expect(f).toBeDefined();
    expect(f!.severity).toBe("info");
    expect(f!.name).toMatch(/Observed/);
    expect(f!.confidence).toBeLessThan(85);
  });

  it("says nothing about an ordinary data endpoint that answers twelve requests", async () => {
    // Clean twin: almost any API tolerates twelve requests, so this proves nothing.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/orders` }), ep({ url: `http://localhost:${port}/api/products` })] }),
    );
    expect(findings.some((f) => /Rate Limiting/i.test(f.name))).toBe(false);
  });

  it("stays quiet when the endpoint answers 429", async () => {
    let n = 0;
    const port = await serve((_req, res) => {
      n += 1;
      if (n > 3) {
        res.writeHead(429);
        res.end('{"error":"too many requests"}');
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/auth/otp` })] }),
    );
    expect(findings.some((f) => /Rate Limiting/i.test(f.name))).toBe(false);
  });
});
