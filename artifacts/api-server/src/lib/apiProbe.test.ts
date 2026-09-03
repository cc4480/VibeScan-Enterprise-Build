import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { runApiProbes, isReadShaped, concreteUrl } from "./apiProbe.js";
import type { ApiEndpoint } from "./apiSurface.js";

const servers: http.Server[] = [];

async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<number> {
  const srv = http.createServer(handler);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const SESSION = { cookie: "sid=valid" };
const signedIn = (req: http.IncomingMessage) => (req.headers.cookie ?? "").includes("sid=valid");

const DATA = JSON.stringify({
  items: [
    { id: 1, customer: "Ada Lovelace", email: "ada@example.com", total: 5040 },
    { id: 2, customer: "Grace Hopper", email: "grace@example.com", total: 1080 },
  ],
});

function ep(partial: Partial<ApiEndpoint> & { url: string }): ApiEndpoint {
  return { method: "GET", params: [], source: "spec", ...partial };
}

describe("isReadShaped", () => {
  it("treats GET and HEAD as always safe", () => {
    expect(isReadShaped(ep({ url: "https://a.example/api/orders", method: "GET" }))).toBe(true);
    expect(isReadShaped(ep({ url: "https://a.example/api/orders", method: "HEAD" }))).toBe(true);
  });

  it("allows POST only where it reads rather than writes", () => {
    expect(isReadShaped(ep({ url: "https://a.example/api/search", method: "POST" }))).toBe(true);
    expect(isReadShaped(ep({ url: "https://a.example/graphql", method: "POST" }))).toBe(true);
    expect(isReadShaped(ep({ url: "https://a.example/api/reports/query", method: "POST" }))).toBe(true);
  });

  it("refuses a POST that would create something", () => {
    // Sending a payload here is placing an order, not testing one.
    expect(isReadShaped(ep({ url: "https://a.example/api/orders", method: "POST" }))).toBe(false);
    expect(isReadShaped(ep({ url: "https://a.example/api/users", method: "POST" }))).toBe(false);
  });

  it("refuses every write verb outright", () => {
    for (const method of ["PUT", "PATCH", "DELETE"]) {
      expect(isReadShaped(ep({ url: "https://a.example/api/search", method }))).toBe(false);
    }
  });
});

describe("concreteUrl", () => {
  it("substitutes path placeholders so the URL can be requested", () => {
    expect(concreteUrl(ep({ url: "https://a.example/api/users/{id}/orders/{oid}" }))).toBe(
      "https://a.example/api/users/1/orders/1",
    );
  });
});

describe("missing authentication", () => {
  it("reports an endpoint that serves data with no session", async () => {
    const port = await serve((_req, res) => {
      // The bug: no auth check at all.
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders` })],
        credentials: SESSION,
      }),
    );

    const f = findings.find((x) => /Without Authentication/i.test(x.name));
    expect(f).toBeDefined();
    expect(f!.evidence).toContain("/api/orders");
  });

  it("stays quiet when the endpoint refuses an anonymous caller", async () => {
    const port = await serve((req, res) => {
      if (!signedIn(req)) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end('{"error":"unauthorized"}');
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders` })],
        credentials: SESSION,
      }),
    );
    expect(findings).toEqual([]);
  });

  it("stays quiet when a 200 actually carries a refusal", async () => {
    // Apps that answer 200 with {"error":"Unauthorized"} are common enough to
    // matter; taking the status at face value would report every one of them.
    const port = await serve((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(signedIn(req) ? DATA : '{"error":"Unauthorized - please sign in to continue"}');
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders` })],
        credentials: SESSION,
      }),
    );
    expect(findings).toEqual([]);
  });

  it("does not treat an empty collection as an exposure", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"items":[]}');
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders` })],
        credentials: SESSION,
      }),
    );
    expect(findings).toEqual([]);
  });

  it("skips the check entirely without a session to contrast against", async () => {
    // A public API returning data to nobody is not a finding on its own.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/orders` })] }),
    );
    expect(findings).toEqual([]);
  });
});

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
