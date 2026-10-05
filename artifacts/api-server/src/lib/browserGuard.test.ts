/**
 * The browser request guard, against a real headless Chromium and local hosts. 127.0.0.1 plays the scan
 * target; 127.0.0.2 and 127.0.0.3 are other hosts the page or a redirect can reach.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import http from "node:http";
import { initBrowser, closeBrowser, renderPage } from "./browser";
import { runWithScanHttp } from "./http";
import { __setBrowserUrlRule, guardBrowser } from "./browserGuard";

interface Hit { url: string; cookie?: string }
const servers: http.Server[] = [];

function serve(host: string, handler: (req: http.IncomingMessage, res: http.ServerResponse, hits: Hit[]) => void) {
  const hits: Hit[] = [];
  return new Promise<{ port: number; hits: Hit[] }>((resolve) => {
    const srv = http.createServer((req, res) => {
      hits.push({ url: req.url ?? "", cookie: req.headers.cookie });
      handler(req, res, hits);
    }).listen(0, host, () => {
      servers.push(srv);
      resolve({ port: (srv.address() as { port: number }).port, hits });
    });
  });
}

const html = (body: string) => (_q: unknown, res: http.ServerResponse) => res.writeHead(200, { "content-type": "text/html" }).end(body);

beforeAll(async () => {
  delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  await initBrowser();
}, 60_000);
afterAll(async () => { await closeBrowser(); });
afterEach(async () => {
  __setBrowserUrlRule(null);
  delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** These tests play on 127.x hosts, which the vetted proxy refuses as private. Opt in so the rule under test is the guard's own. */
function useRule(fn: Parameters<typeof __setBrowserUrlRule>[0]) {
  process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
  __setBrowserUrlRule(fn);
}

const render = (url: string, credentials?: { cookie?: string }) =>
  runWithScanHttp({ targetUrl: url, ...(credentials ? { credentials } : {}) } as never, () => renderPage(url));

describe("browser request guard", () => {
  it("refuses a private target outright, with the real address rule", async () => {
    const t = await serve("127.0.0.1", html("<h1>internal</h1>"));
    const page = await render(`http://127.0.0.1:${t.port}/`);
    expect(page).toBeNull();
    expect(t.hits).toHaveLength(0);
  }, 60_000);

  it("does not follow a redirect onto a blocked host", async () => {
    const victim = await serve("127.0.0.2", html("secret"));
    const target = await serve("127.0.0.1", (_q, res) => res.writeHead(302, { Location: `http://127.0.0.2:${victim.port}/meta` }).end());
    useRule(async (u) => new URL(u).hostname === "127.0.0.1");
    await render(`http://127.0.0.1:${target.port}/`);
    expect(victim.hits).toHaveLength(0);
  }, 60_000);

  it("follows a redirect to an allowed host and does not carry the customer's cookie to it", async () => {
    const dest = await serve("127.0.0.3", html("<p>landed</p>"));
    const target = await serve("127.0.0.1", (_q, res) => res.writeHead(302, { Location: `http://127.0.0.3:${dest.port}/home` }).end());
    useRule(async () => true);
    const page = await render(`http://127.0.0.1:${target.port}/`, { cookie: "sid=customer-session" });
    expect(page?.html).toContain("landed");
    expect(target.hits[0]?.cookie).toBe("sid=customer-session");
    expect(dest.hits).toHaveLength(1);
    expect(dest.hits[0]?.cookie).toBeUndefined();
  }, 60_000);

  it("stops a redirect chain that ends on a blocked host even after an allowed hop", async () => {
    const victim = await serve("127.0.0.2", html("secret"));
    const mid = await serve("127.0.0.3", (_q, res) => res.writeHead(302, { Location: `http://127.0.0.2:${victim.port}/x` }).end());
    const target = await serve("127.0.0.1", (_q, res) => res.writeHead(302, { Location: `http://127.0.0.3:${mid.port}/hop` }).end());
    useRule(async (u) => new URL(u).hostname !== "127.0.0.2");
    await render(`http://127.0.0.1:${target.port}/`);
    // renderPage retries its navigation once, so the allowed middle host may be asked twice.
    expect(mid.hits.length).toBeGreaterThan(0);
    expect(mid.hits.every((h) => h.url === "/hop")).toBe(true);
    expect(victim.hits).toHaveLength(0);
  }, 60_000);

  it("blocks requests the page's own script makes to a blocked host", async () => {
    const victim = await serve("127.0.0.2", (_q, res) => res.writeHead(200, { "access-control-allow-origin": "*" }).end("secret"));
    const target = await serve("127.0.0.1", html(`<script>fetch("http://127.0.0.2:${victim.port}/steal").catch(()=>{});</script>ok`));
    useRule(async (u) => new URL(u).hostname === "127.0.0.1");
    const page = await render(`http://127.0.0.1:${target.port}/`);
    expect(page?.html).toContain("ok");
    expect(victim.hits).toHaveLength(0);
  }, 60_000);

  it("sends the customer's cookie to the scanned host but not to other hosts the page loads", async () => {
    const other = await serve("127.0.0.3", (_q, res) => res.writeHead(200, { "content-type": "image/gif" }).end("GIF89a"));
    const target = await serve("127.0.0.1", html(`<img src="http://127.0.0.3:${other.port}/pixel.gif"><p>dashboard</p>`));
    useRule(async () => true); // both hosts reachable: only the credential rule is under test
    await render(`http://127.0.0.1:${target.port}/`, { cookie: "sid=customer-session" });
    expect(target.hits[0]?.cookie).toBe("sid=customer-session");
    expect(other.hits.length).toBeGreaterThan(0);
    expect(other.hits.every((h) => h.cookie === undefined)).toBe(true);
  }, 60_000);
});

// Chromium's own local-network check refuses a page-to-loopback socket whatever this guard says, so a
// real browser cannot show an ALLOWED socket connecting here. Playwright's routeWebSocket contract was
// checked directly (no route: the socket reaches the server; close() in the handler: it does not); this
// tests the decision the guard makes inside that handler, with a positive control.
describe("browser request guard: WebSocket decision", () => {
  async function decide(allowed: boolean) {
    useRule(async () => allowed);
    let handler: ((ws: { url(): string; close(o?: unknown): Promise<void>; connectToServer(): unknown }) => Promise<void>) | undefined;
    await guardBrowser({
      route: async () => undefined,
      routeWebSocket: async (_p, h) => { handler = h as never; },
    });
    const calls = { closed: 0, connected: 0, blocked: [] as string[] };
    await handler!({ url: () => "ws://10.0.0.5/ws", close: async () => { calls.closed++; }, connectToServer: () => { calls.connected++; } });
    return calls;
  }

  it("control: connects a socket to an allowed host", async () => {
    expect(await decide(true)).toMatchObject({ connected: 1, closed: 0 });
  });

  it("closes a socket to a blocked host without connecting it", async () => {
    expect(await decide(false)).toMatchObject({ connected: 0, closed: 1 });
  });
});
