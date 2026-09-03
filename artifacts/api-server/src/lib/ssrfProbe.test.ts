import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { isUrlParam } from "./ssrfProbe.js";
import type { ApiEndpoint } from "./apiSurface.js";

// The collector is mocked: these tests exercise the probe's logic — which
// parameters it plants, that it reports only on a real callback — without a
// database. A separate suite covers the collector's own token discipline.
const registered: Array<{ token: string; context: string }> = [];
let callbackTokens = new Set<string>();

vi.mock("./oobServer.js", () => ({
  isOobConfigured: () => true,
  registerOobToken: async (_scanId: string | null, context: string) => {
    const token = `oobtok${registered.length}`;
    registered.push({ token, context });
    return { token, url: `https://collector.example/api/oob/${token}` };
  },
  tokensWithInteractions: async (tokens: string[]) =>
    new Set(tokens.filter((t) => callbackTokens.has(t))),
}));

const { runSsrfProbes } = await import("./ssrfProbe.js");

const servers: http.Server[] = [];
async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<number> {
  const srv = http.createServer(handler);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}

beforeEach(() => {
  registered.length = 0;
  callbackTokens = new Set();
  vi.useFakeTimers();
});

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** Run the probe and let its post-injection wait elapse. */
async function runProbe(input: Parameters<typeof runSsrfProbes>[0]) {
  const promise = runSsrfProbes(input);
  await vi.runAllTimersAsync();
  return promise;
}

function ep(partial: Partial<ApiEndpoint> & { url: string }): ApiEndpoint {
  return { method: "GET", params: [], source: "spec", ...partial };
}

describe("isUrlParam", () => {
  it.each(["url", "uri", "callback", "webhook", "redirect", "image_url", "feed", "proxy", "dest"])(
    "recognises %s",
    (name) => expect(isUrlParam(name)).toBe(true),
  );

  it.each(["quantity", "email", "name", "total", "id", "password"])(
    "ignores %s",
    (name) => expect(isUrlParam(name)).toBe(false),
  );
});

describe("runSsrfProbes", () => {
  it("does nothing when no collector is configured", async () => {
    vi.resetModules();
    vi.doMock("./oobServer.js", () => ({
      isOobConfigured: () => false,
      registerOobToken: async () => ({ token: "x", url: "x" }),
      tokensWithInteractions: async () => new Set(),
    }));
    const { runSsrfProbes: probes } = await import("./ssrfProbe.js");
    const found = await probes({
      scanId: "s1",
      targetUrl: "https://a.example/?url=x",
      endpoints: [],
    });
    expect(found).toEqual([]);
    vi.doUnmock("./oobServer.js");
  });

  it("plants a callback URL in a url-shaped query parameter", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    await runProbe({
      scanId: "s1",
      targetUrl: `http://localhost:${port}/fetch?url=http://original`,
      endpoints: [],
    });

    expect(registered).toHaveLength(1);
    expect(registered[0]!.context).toContain('"url"');
  });

  it("leaves parameters that do not carry a URL alone", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    await runProbe({
      scanId: "s1",
      targetUrl: `http://localhost:${port}/search?q=hello&count=5`,
      endpoints: [],
    });

    // "q" is in the URL_PARAM set (a common SSRF alias); "count" is not.
    expect(registered.every((r) => !r.context.includes('"count"'))).toBe(true);
  });

  it("reports SSRF only when a callback actually arrived", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    // No callback yet.
    let found = await runProbe({
      scanId: "s1",
      targetUrl: `http://localhost:${port}/fetch?url=x`,
      endpoints: [],
    });
    expect(found).toEqual([]);

    // Now the collector has seen the planted token.
    callbackTokens = new Set(registered.map((r) => r.token));
    registered.length = 0;
    found = await runProbe({
      scanId: "s1",
      targetUrl: `http://localhost:${port}/fetch?url=x`,
      endpoints: [],
    });

    expect(found).toHaveLength(1);
    expect(found[0]!.name).toMatch(/SSRF/);
    expect(found[0]!.severity).toBe("critical");
    expect(found[0]!.cweId).toBe("CWE-918");
  });

  it("tests url-shaped parameters declared by API endpoints", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    await runProbe({
      scanId: "s1",
      targetUrl: `http://localhost:${port}/`,
      endpoints: [
        ep({
          url: `http://localhost:${port}/api/import`,
          params: [
            { name: "webhook", location: "query" },
            { name: "count", location: "query" },
          ],
        }),
      ],
    });

    expect(registered).toHaveLength(1);
    expect(registered[0]!.context).toContain('"webhook"');
  });

  it("never plants a payload in a destructive endpoint", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(200);
      res.end("ok");
    });

    await runProbe({
      scanId: "s1",
      targetUrl: `http://localhost:${port}/`,
      endpoints: [
        ep({
          url: `http://localhost:${port}/api/account/delete`,
          params: [{ name: "url", location: "query" }],
        }),
      ],
    });

    expect(registered).toEqual([]);
  });
});
