import { serve } from "./http.testkit";
import { describe, it, expect } from "vitest";
import { scanFetch, SCANNER_USER_AGENT } from "./http.js";

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

describe("scan abort signal", () => {
  it("fails requests at once once the scan's signal is aborted", async () => {
    const { runWithScanHttp, scanFetch } = await import("./http");
    const { port, seen } = await serve((_req, res) => { res.writeHead(200); res.end("ok"); });
    const url = `http://127.0.0.1:${port}/`;
    const ac = new AbortController();
    const out = await runWithScanHttp({ targetUrl: url, signal: ac.signal }, async () => {
      const before = await scanFetch(url);
      ac.abort();
      const after = await scanFetch(url);
      return { before, after };
    });
    expect(out.before?.body).toBe("ok");
    expect(out.after).toBeNull();
    expect(seen).toHaveLength(1); // the aborted request never reached the server
  });
});
