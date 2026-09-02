import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { ScanScope, scanFetch, runWithScanHttp, SCANNER_USER_AGENT } from "./http.js";

// Real servers rather than a mocked fetch: the behaviour under test is redirect
// handling and what gets put on the wire, which a mock would only restate.
// "localhost" and "127.0.0.1" are distinct hostnames, so they stand in for
// in-scope and out-of-scope hosts without any network access.

interface Captured {
  url: string;
  headers: http.IncomingHttpHeaders;
}

const servers: http.Server[] = [];

async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse, seen: Captured[]) => void,
): Promise<{ port: number; seen: Captured[] }> {
  const seen: Captured[] = [];
  const srv = http.createServer((req, res) => {
    seen.push({ url: req.url ?? "", headers: req.headers });
    handler(req, res, seen);
  });
  servers.push(srv);
  await new Promise<void>((resolve) => srv.listen(0, "127.0.0.1", resolve));
  return { port: (srv.address() as AddressInfo).port, seen };
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

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

describe("scanFetch redirects", () => {
  it("exposes the 3xx and its Location in manual mode", async () => {
    // Open-redirect detection depends on reading Location rather than following.
    const { port } = await serve((_req, res) => {
      res.writeHead(302, { Location: "https://evil.example.com/landing" });
      res.end();
    });

    const result = await scanFetch(`http://localhost:${port}/?next=evil`, { redirect: "manual" });

    expect(result?.status).toBe(302);
    expect(result?.headers["location"]).toBe("https://evil.example.com/landing");
    expect(result?.redirected).toBe(false);
  });

  it("gives up on a redirect loop instead of hanging", async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(302, { Location: "/loop" });
      res.end();
    });

    expect(await scanFetch(`http://localhost:${port}/loop`)).toBeNull();
  });

  it("returns the 3xx when a redirect has no Location header", async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(302);
      res.end();
    });

    const result = await scanFetch(`http://localhost:${port}/`);
    expect(result?.status).toBe(302);
  });
});

describe("scanFetch transport", () => {
  it("returns null rather than throwing when the host is unreachable", async () => {
    // Port 1 on loopback: nothing listens there.
    expect(await scanFetch("http://127.0.0.1:1/")).toBeNull();
  });

  it("returns null on timeout", async () => {
    const { port } = await serve(() => {
      // Never respond.
    });

    expect(await scanFetch(`http://localhost:${port}/`, { timeoutMs: 150 })).toBeNull();
  });

  it("applies one consistent User-Agent", async () => {
    const { port, seen } = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    await scanFetch(`http://localhost:${port}/`);
    expect(seen[0].headers["user-agent"]).toBe(SCANNER_USER_AGENT);
  });

  it("lets a caller override headers", async () => {
    const { port, seen } = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    await scanFetch(`http://localhost:${port}/`, { headers: { Origin: "https://spoofed.example" } });
    expect(seen[0].headers.origin).toBe("https://spoofed.example");
  });

  it("normalises the response shape", async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(201, { "X-Custom": "Value" });
      res.end("body text");
    });

    const result = await scanFetch(`http://localhost:${port}/x`);
    expect(result).toMatchObject({ status: 201, body: "body text" });
    expect(result?.headers["x-custom"]).toBe("Value");
    expect(result?.finalUrl).toContain("/x");
  });
});
