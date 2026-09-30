import { servers, serve, SESSION, DATA, ep } from "./apiProbe.testkit";
import { collectApiSurface, runApiProbes } from "./apiProbe.js";
import { describe, it, expect } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";

describe("API-level IDOR", () => {
  it("reports a record endpoint serving identical data to a second account", async () => {
    const port = await serve((req, res) => {
      const c = req.headers.cookie ?? "";
      if (!c.includes("sid=")) {
        res.writeHead(401);
        res.end('{"error":"unauthorized"}');
        return;
      }
      // The bug: any signed-in caller gets the same record.
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders/{id}` })],
        credentials: SESSION,
        secondary: { cookie: "sid=other" },
      }),
    );
    expect(findings.some((f) => /Readable by Another Account/i.test(f.name))).toBe(true);
  });

  it("stays quiet when the same account is supplied as both", async () => {
    const port = await serve((req, res) => {
      const c = req.headers.cookie ?? "";
      if (!c.includes("sid=")) { res.writeHead(401); res.end('{"error":"unauthorized"}'); return; }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders/{id}` })],
        credentials: SESSION,
        secondary: { cookie: " sid=valid " },
      }),
    );
    expect(findings.some((f) => /Readable by Another Account/i.test(f.name))).toBe(false);
  });

  it("stays quiet when the record is public, so anonymous callers read it too", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: 1, title: "Launch notes", body: "Public release notes for everyone" }));
    });
    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/notes/{id}` })],
        credentials: SESSION,
        secondary: { cookie: "sid=other" },
      }),
    );
    expect(findings.some((f) => /Readable by Another Account/i.test(f.name))).toBe(false);
  });

  it("stays quiet when each account sees its own record", async () => {
    const port = await serve((req, res) => {
      const c = req.headers.cookie ?? "";
      if (!c.includes("sid=")) {
        res.writeHead(401);
        res.end('{"error":"unauthorized"}');
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ owner: c.includes("valid") ? "ada" : "grace", items: [1, 2, 3] }));
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/orders/{id}` })],
        credentials: SESSION,
        secondary: { cookie: "sid=other" },
      }),
    );
    expect(findings.some((f) => /Readable by Another Account/i.test(f.name))).toBe(false);
  });
});

describe("rate-limit finding", () => {
  it("flags a genuinely unlimited sensitive endpoint", async () => {
    // A credential endpoint with no throttling — the case this finding
    // exists to catch.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/auth/login-code` })],
      }),
    );

    const f = findings.find((x) => /Rate Limiting Observed/i.test(x.name));
    expect(f).toBeDefined();
    expect(f!.evidence).toContain("/api/auth/login-code");
  });

  it("does not flag a liveness or discovery endpoint for answering an unlimited burst", async () => {
    // Regression: this probe flagged seclayer.app's /api/system/health and
    // /api/auth/providers — a platform health check and a public
    // OAuth-provider-discovery route. Both are meant to answer every request;
    // throttling either is the wrong fix, not the missing one. The endpoint
    // shapes here mirror the ones actually found in production.
    const exemptPaths = [
      "/api/system/health",
      "/api/health",
      "/healthz",
      "/api/auth/providers",
      "/.well-known/security.txt",
      "/robots.txt",
      "/api/version",
    ];

    for (const path of exemptPaths) {
      const port = await serve((_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"ok":true}');
      });

      const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
        runApiProbes({
          endpoints: [ep({ url: `http://localhost:${port}${path}` })],
        }),
      );

      expect(
        findings.some((f) => /Rate Limiting Observed/i.test(f.name)),
        `expected no rate-limit finding for ${path}`,
      ).toBe(false);
    }
  });

  it("still flags a sensitive path that merely contains an exempt word as a substring", async () => {
    // The exemption matches whole path segments, not substrings — a route
    // like /api/health-records must not be swept up with /api/health.
    const port = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(DATA);
    });

    const findings = await runWithScanHttp({ targetUrl: `http://localhost:${port}/` }, () =>
      runApiProbes({
        endpoints: [ep({ url: `http://localhost:${port}/api/password/status-check` })],
      }),
    );

    expect(findings.some((f) => /Rate Limiting Observed/i.test(f.name))).toBe(true);
  });
});

// ─── A spec's servers[0].url is the target's own claim, not a licence to test a third party ───



describe("collectApiSurface: endpoints from the target's own OpenAPI document", () => {
  it("drops an endpoint whose server is a third party, so no probe is ever pointed at it", async () => {
    // The target's /openapi.json declares servers[0].url as another host. endpointsFromSpec uses it
    // verbatim (bundle endpoints were origin-filtered, spec endpoints were not), so an active probe
    // could POST to https://api.openai.com/v1/chat/completions on the strength of the target's say-so.
    const spec = (base: string) => JSON.stringify({
      openapi: "3.0.0",
      servers: [{ url: base }],
      paths: { "/chat/completions": { post: {} }, "/records": { get: {} } },
    });
    const port = await serve((req, res) => {
      if (req.url === "/openapi.json") {
        res.writeHead(200, { "content-type": "application/json" }).end(spec("http://127.0.0.2:9/v1"));
        return;
      }
      res.writeHead(404).end();
    });
    const origin = `http://127.0.0.1:${port}`;
    const endpoints = await runWithScanHttp({ targetUrl: origin }, () => collectApiSurface(origin, "<html></html>"));
    expect(endpoints.map((e) => e.url)).toEqual([]);
  });

  it("keeps a spec whose server is the target itself", async () => {
    const port = await serve((req, res) => {
      if (req.url === "/openapi.json") {
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
          openapi: "3.0.0",
          servers: [{ url: `http://127.0.0.1:${(servers[0]!.address() as AddressInfo).port}/v1` }],
          paths: { "/records": { get: {} } },
        }));
        return;
      }
      res.writeHead(404).end();
    });
    const origin = `http://127.0.0.1:${port}`;
    const endpoints = await runWithScanHttp({ targetUrl: origin }, () => collectApiSurface(origin, "<html></html>"));
    expect(endpoints.map((e) => e.url)).toEqual([`${origin}/v1/records`]);
  });
});
