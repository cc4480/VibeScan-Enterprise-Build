import { serve } from "./http.testkit";
import { describe, it, expect } from "vitest";
import http from "node:http";
import { ScanScope, scanFetch, runWithScanHttp } from "./http.js";

describe("ScanScope", () => {
  const scope = new ScanScope("https://example.com/some/path");

  it("includes the target host itself", () => {
    expect(scope.includes("https://example.com/anything")).toBe(true);
  });

  it("includes subdomains", () => {
    expect(scope.includes("https://api.example.com/v1")).toBe(true);
  });

  it("ignores protocol, so an http:// redirect check stays in scope", () => {
    expect(scope.includes("http://example.com/")).toBe(true);
  });

  it("does not treat a host merely ending in the target as a subdomain", () => {
    // The bug a bare endsWith() check would introduce.
    expect(scope.includes("https://notexample.com/")).toBe(false);
    expect(scope.includes("https://evil-example.com/")).toBe(false);
  });

  it("excludes unrelated hosts and unparseable URLs", () => {
    expect(scope.includes("https://evil.com/")).toBe(false);
    expect(scope.includes("not a url")).toBe(false);
  });
});

describe("scanFetch credentials", () => {
  it("sends credentials to the target", async () => {
    const { port, seen } = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=secret", headers: { Authorization: "Bearer tok" } },
      },
      () => scanFetch(`http://localhost:${port}/page`),
    );

    expect(seen[0].headers.cookie).toBe("sid=secret");
    expect(seen[0].headers.authorization).toBe("Bearer tok");
  });

  it("withholds credentials from a host outside the scan scope", async () => {
    const { port, seen } = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    // Scope is "localhost"; this request goes to 127.0.0.1 — a different host,
    // standing in for osv.dev or api.deepseek.com.
    await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=secret", headers: { Authorization: "Bearer tok" } },
      },
      () => scanFetch(`http://127.0.0.1:${port}/third-party`),
    );

    expect(seen[0].headers.cookie).toBeUndefined();
    expect(seen[0].headers.authorization).toBeUndefined();
  });

  it("drops credentials when a redirect leaves the scan scope", async () => {
    // The leak this module exists to prevent: target 302s to an attacker host,
    // and the session follows it.
    const external = await serve((_req, res) => {
      res.writeHead(200);
      res.end("external");
    });

    const target = await serve((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { Location: `http://127.0.0.1:${external.port}/landing` });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end("ok");
    });

    const result = await runWithScanHttp(
      {
        targetUrl: `http://localhost:${target.port}/`,
        credentials: { cookie: "sid=secret", headers: { Authorization: "Bearer tok" } },
      },
      () => scanFetch(`http://localhost:${target.port}/start`),
    );

    expect(result?.status).toBe(200);
    expect(result?.redirected).toBe(true);
    expect(external.seen[0].headers.cookie).toBeUndefined();
    expect(external.seen[0].headers.authorization).toBeUndefined();
    // The in-scope hop still received them.
    expect(target.seen[0].headers.cookie).toBe("sid=secret");
  });

  it("keeps credentials across an in-scope redirect", async () => {
    const { port, seen } = await serve((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { Location: "/dest" });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end("arrived");
    });

    const result = await runWithScanHttp(
      { targetUrl: `http://localhost:${port}/`, credentials: { cookie: "sid=secret" } },
      () => scanFetch(`http://localhost:${port}/start`),
    );

    expect(result?.body).toBe("arrived");
    expect(seen).toHaveLength(2);
    expect(seen[1].headers.cookie).toBe("sid=secret");
  });

  it("sends no credentials when no scan context is active", async () => {
    const { port, seen } = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    const result = await scanFetch(`http://localhost:${port}/`);

    expect(result?.status).toBe(200);
    expect(seen[0].headers.cookie).toBeUndefined();
  });
});
