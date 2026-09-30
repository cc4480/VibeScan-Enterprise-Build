import { serve, SESSION, DATA, ep } from "./apiProbe.testkit";
import { describe, it, expect } from "vitest";
import http from "node:http";
import { runWithScanHttp } from "./http.js";
import { runApiProbes } from "./apiProbe.js";

describe("SQL injection in API parameters", () => {
  const sqlError = '{"error":"unterminated quoted string at or near \\"\'\\""}';

  it("reports an injectable query parameter", async () => {
    const port = await serve((req, res) => {
      const value = new URL(req.url ?? "", "http://x").searchParams.get("q") ?? "";
      if (value.includes("'")) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(sqlError);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [
          ep({
            url: `http://localhost:${port}/api/search`,
            params: [{ name: "q", location: "query" }],
          }),
        ],
      }),
    );

    const f = findings.find((x) => /SQL Injection/i.test(x.name));
    expect(f).toBeDefined();
    expect(f!.severity).toBe("critical");
    expect(f!.evidence).toContain("q (query)");
  });

  it("reports an injectable path parameter", async () => {
    const port = await serve((req, res) => {
      // The quote may arrive percent-encoded or literal depending on how the
      // URL is normalised in transit; both mean it reached the handler.
      const raw = req.url ?? "";
      const decoded = (() => {
        try {
          return decodeURIComponent(raw);
        } catch {
          return raw;
        }
      })();
      if (decoded.includes("'")) {
        res.writeHead(500);
        res.end(sqlError);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [
          ep({
            url: `http://localhost:${port}/api/users/{id}`,
            params: [{ name: "id", location: "path" }],
          }),
        ],
      }),
    );
    expect(findings.some((f) => /SQL Injection/i.test(f.name))).toBe(true);
  });

  it("reports an injectable JSON body field on a read-shaped endpoint", async () => {
    const port = await serve((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (body.includes("'")) {
          res.writeHead(500);
          res.end(sqlError);
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(DATA);
      });
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [
          ep({
            url: `http://localhost:${port}/api/search`,
            method: "POST",
            params: [{ name: "filter", location: "body" }],
          }),
        ],
      }),
    );

    const f = findings.find((x) => /SQL Injection/i.test(x.name));
    expect(f).toBeDefined();
    expect(f!.evidence).toContain("filter (body)");
  });

  it("does not flag an endpoint that always mentions a SQL error", async () => {
    // The baseline diff is what prevents this; without it any error-log viewer
    // would be reported as injectable.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ log: "unterminated quoted string at or near x", items: [1, 2] }));
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [
          ep({
            url: `http://localhost:${port}/api/search`,
            params: [{ name: "q", location: "query" }],
          }),
        ],
      }),
    );
    expect(findings.some((f) => /SQL Injection/i.test(f.name))).toBe(false);
  });
});

describe("safety", () => {
  it("never sends a request to a write endpoint", async () => {
    const seen: string[] = [];
    const port = await serve((req, res) => {
      seen.push(`${req.method} ${req.url}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [
          ep({ url: `http://localhost:${port}/api/orders`, method: "POST" }),
          ep({ url: `http://localhost:${port}/api/users/{id}`, method: "DELETE" }),
          ep({ url: `http://localhost:${port}/api/users/{id}`, method: "PUT" }),
        ],
        credentials: SESSION,
      }),
    );

    // Placing an order or deleting a user is not an acceptable way to discover
    // that authentication is missing.
    expect(seen).toEqual([]);
  });

  it("never requests a destructive URL", async () => {
    const seen: string[] = [];
    const port = await serve((req, res) => {
      seen.push(req.url ?? "");
      res.writeHead(200);
      res.end(DATA);
    });

    await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/account/delete` })],
        credentials: SESSION,
      }),
    );
    expect(seen).toEqual([]);
  });
});
