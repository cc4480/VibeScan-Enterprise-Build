import { servers, serve, SESSION, signedIn, DATA, ep } from "./apiProbe.testkit";
import { describe, it, expect } from "vitest";
import http from "node:http";
import { runWithScanHttp } from "./http.js";
import { runApiProbes, isReadShaped, concreteUrl } from "./apiProbe.js";

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

  it("stays quiet for a public catalogue that answers signed-in and anonymous callers alike", async () => {
    // Clean twin. A product list is public by design: the same data for everyone is what it is.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ items: [{ id: 1, name: "Widget", price: 9 }, { id: 2, name: "Gadget", price: 12 }] }));
    });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/products` })], credentials: SESSION }),
    );
    expect(findings.some((x) => /Without Authentication/i.test(x.name))).toBe(false);
  });

  it("still reports a collection with a public-sounding name when it holds personal data", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/reviews` })], credentials: SESSION }),
    );
    expect(findings.some((x) => /Without Authentication/i.test(x.name))).toBe(true);
  });

  it.each([
    ["a redirect to the sign-in page", "redirect"],
    ["an HTML sign-in page served with 200", "html"],
    ["a JSON message asking for a login", "json"],
  ])("treats %s as a refusal", async (_l, kind) => {
    const port = await serve((req, res) => {
      if (!signedIn(req)) {
        if (kind === "redirect" && req.url !== "/login") { res.writeHead(302, { location: "/login" }); res.end(); return; }
        if (kind === "redirect" || kind === "html") {
          res.writeHead(200, { "content-type": "text/html" });
          res.end("<html><body><h1>Welcome back</h1><form><input type='password' name='p'></form></body></html>");
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"message":"Please log in to continue","code":"E_AUTH"}');
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/orders` })], credentials: SESSION }),
    );
    expect(findings.some((x) => /Without Authentication/i.test(x.name))).toBe(false);
  });

  it("stays quiet when the anonymous caller gets a different, generic payload", async () => {
    const port = await serve((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(signedIn(req) ? DATA : '{"notice":"Sign up to see your orders, guests see nothing here"}');
    });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({ endpoints: [ep({ url: `http://localhost:${port}/api/orders` })], credentials: SESSION }),
    );
    expect(findings.some((x) => /Without Authentication/i.test(x.name))).toBe(false);
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
    // Scoped to the check under test: these stub servers have no rate
    // limiter either, which the probe is right to notice.
    expect(findings.some((f) => /Without Authentication/i.test(f.name))).toBe(false);
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
    // Scoped to the check under test: these stub servers have no rate
    // limiter either, which the probe is right to notice.
    expect(findings.some((f) => /Without Authentication/i.test(f.name))).toBe(false);
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
    // Scoped to the check under test: these stub servers have no rate
    // limiter either, which the probe is right to notice.
    expect(findings.some((f) => /Without Authentication/i.test(f.name))).toBe(false);
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
    // Scoped to the check under test: these stub servers have no rate
    // limiter either, which the probe is right to notice.
    expect(findings.some((f) => /Without Authentication/i.test(f.name))).toBe(false);
  });
});
