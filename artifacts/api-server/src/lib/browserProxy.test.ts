/**
 * The headless browser's name resolution goes through the vetted proxy, against a real Chromium.
 *
 * The address rule is replaced with "allow everything", standing in for a pre-check that a rebinding
 * name has already fooled; what is left to stop the fetch is the proxy's connect-time vetting. The rebinding name is
 * a real one: *.localtest.me is public DNS that answers 127.0.0.1, so the browser really resolves a name to loopback.
 * Skips when that name cannot be resolved (no network).
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import dns from "node:dns/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { initBrowser, closeBrowser, renderPage } from "./browser";
import { runWithScanHttp } from "./http";
import { __setBrowserUrlRule } from "./browserGuard";

let chromiumAvailable = false;
try {
  const { chromium } = await import("playwright");
  await (await chromium.launch({ headless: true, args: ["--no-sandbox"] })).close();
  chromiumAvailable = true;
} catch { /* no playwright, or no browser installed */ }
// A configured upstream proxy replaces the vetted one (see browserProxy.ts), so there is nothing to test.
let nameResolves = false;
try { nameResolves = (await dns.lookup("rebind.localtest.me", { all: true })).some((a) => a.address === "127.0.0.1"); } catch { /* offline */ }
const suite = chromiumAvailable && nameResolves && !process.env["HTTPS_PROXY"] && !process.env["HTTP_PROXY"] ? describe : describe.skip;

const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
let hits = 0;
let server: http.Server;
let port = 0;

suite("browser through the vetted proxy (real Chromium)", () => {
  beforeAll(async () => {
    server = http.createServer((_q, res) => { hits++; res.writeHead(200, { "content-type": "text/html" }).end("<h1>internal page</h1>"); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;
    delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    await initBrowser();
  }, 60_000);
  afterAll(async () => { await closeBrowser(); server.close(); });
  afterEach(() => {
    hits = 0;
    __setBrowserUrlRule(null);
    if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  });

  const render = (url: string) => runWithScanHttp({ targetUrl: url } as never, () => renderPage(url));

  it("does not fetch a name that resolves to loopback at connect time, even when the pre-check passed", async () => {
    __setBrowserUrlRule(async () => true);
    await render(`http://rebind.localtest.me:${port}/`);
    expect(hits).toBe(0);
  }, 60_000);

  it("does reach it through the proxy when the operator opts in (proving the traffic goes via the proxy)", async () => {
    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    __setBrowserUrlRule(async () => true);
    const page = await render(`http://optin.localtest.me:${port}/`);
    expect(hits).toBeGreaterThan(0);
    expect(JSON.stringify(page)).toContain("internal page");
  }, 60_000);
});
